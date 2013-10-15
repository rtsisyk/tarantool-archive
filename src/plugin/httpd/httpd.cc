
/*
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * <COPYRIGHT HOLDER> OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

extern "C" {
	#include "httpfast/httpfast.h"
}

#define PLUGIN_VERSION			1
#define PLUGIN_NAME			"httpd"

extern "C" {
	#include <lua.h>
	#include <lauxlib.h>
	#include <lualib.h>
}
#include <tarantool/plugin.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <coeio.h>
#include <say.h>
#include <tarantool_ev.h>


#include <lua/init.h>
#include <scoped_guard.h>
#include "tpleval.h"

static int
lbox_http_split_url(struct lua_State *L)
{
	if (lua_gettop(L) < 1)
		luaL_error(L, "box.http.split_url: wrong arguments");

	const char *p;
	const char *uri = lua_tostring(L, 1);
	int cnt = 0;

	/* scheme */
	for (p = uri; *p; p++) {
		if (*p == ':') {
			if (p[1] == '/' && p[2] == '/') {
				lua_pushlstring(L, uri, (int)(p - uri));
				uri = p + 3;
				cnt++;
			}
			goto DOMAIN;
		}
	}

	lua_pushstring(L, "http");
	cnt++;


	DOMAIN:
		for (p = uri; *p; p++) {
			if (*p == ':' || *p == '/' || *p == '?') {
				lua_pushlstring(L, uri, (int)(p - uri));
				uri = p;
				cnt++;

				if (*p == '/') {
					lua_pushnil(L);		/* port */
					cnt++;
					goto PATH;
				}

				uri++;
				if (*p == ':')
					goto PORT;

				lua_pushnil(L);
				lua_pushstring(L, "/");
				cnt += 2;
				goto QUERY;
			}
		}

		if (*uri) {
			lua_pushstring(L, uri);		/* host */
			cnt++;
		} else {
			lua_pushstring(L, "");
			cnt++;
		}
		lua_pushnil(L);			/* port */
		lua_pushstring(L, "/");		/* path */
		lua_pushstring(L, "");		/* query */
		cnt += 3;
		return cnt;


	PORT:
		/* extract port */
		for (p = uri; *p; p++) {
			if (*p == '/' || *p == '?') {
				lua_pushlstring(L, uri, (int)(p - uri));
				uri = p;
				cnt++;
				if (*p == '/')
					goto PATH;
				lua_pushstring(L, "/");
				cnt++;
				uri++;
				goto QUERY;
			}
		}
		if (*uri)
			lua_pushstring(L, uri);
		else
			lua_pushnil(L);
		lua_pushstring(L, "/");
		lua_pushstring(L, "");
		cnt += 3;
		return cnt;


	PATH:
		for (p = uri; *p; p++) {
			if (*p == '?') {
				lua_pushlstring(L, uri, (int)(p - uri));
				uri = p + 1;
				cnt++;
				goto QUERY;
			}
		}
		lua_pushstring(L, uri);
		lua_pushstring(L, "");
		cnt += 2;
		return cnt;

	QUERY:

		if (*uri)
			lua_pushstring(L, uri);
		else
			lua_pushstring(L, "");
		cnt++;


	return cnt;
}


static void
tpl_term(int type, const char *str, size_t len, void *data)
{
	luaL_Buffer *b = (typeof(b))data;
	size_t i;

	switch(type) {
		case TPE_TEXT:
			luaL_addstring(b, "_i(\"");
			for(i = 0; i < len; i++) {
				switch(str[i]) {
					case '\n':
						luaL_addstring(b,
							"\\n\" ..\n\"");
						break;
					case '\r':
						luaL_addstring(b,
							"\\r");
						break;
					case '"':
						luaL_addchar(b, '\\');
					default:
						luaL_addchar(b, str[i]);
						break;
				}
			}
			luaL_addstring(b, "\") ");
			break;
		case TPE_LINECODE:
		case TPE_MULTILINE_CODE:
			/* _i one line */
			if (len > 1 && str[0] == '=' && str[1] == '=') {
				luaL_addstring(b, "_i(");
				luaL_addlstring(b, str + 2, len - 2);
				luaL_addstring(b, ") ");
				break;
			}
			/* _q one line */
			if (len > 0 && str[0] == '=') {
				luaL_addstring(b, "_q(");
				luaL_addlstring(b, str + 1, len - 1);
				luaL_addstring(b, ") ");
				break;
			}
			luaL_addlstring(b, str, len);
			luaL_addchar(b, ' ');
			break;
		default:
			abort();
	}
}

static int
lbox_httpd_escape_html(struct lua_State *L)
{
	int idx  = lua_upvalueindex(1);

	luaL_Buffer b;
	luaL_buffinit(L, &b);

	lua_pushnumber(L, 1);
	lua_rawget(L, idx);
	if (lua_isnil(L, -1)) {
		luaL_addstring(&b, "");
		lua_pop(L, 1);
	} else {
		luaL_addvalue(&b);
	}


	int i, top = lua_gettop(L);
	for (i = 1; i <= top; i++) {
		if (lua_isnil(L, i)) {
			luaL_addstring(&b, "nil");
			continue;
		}
		const char *s = lua_tostring(L, i);
		for (; *s; s++) {
			switch(*s) {
				case '&':
					luaL_addstring(&b, "&amp;");
					break;
				case '<':
					luaL_addstring(&b, "&lt;");
					break;
				case '>':
					luaL_addstring(&b, "&gt;");
					break;
				case '"':
					luaL_addstring(&b, "&quot;");
					break;
				case '\'':
					luaL_addstring(&b, "&#39;");
					break;
				default:
					luaL_addchar(&b, *s);
					break;
			}
		}
	}

	lua_pushnumber(L, 1);
	luaL_pushresult(&b);
	lua_rawset(L, idx);
	return 0;
}

static int
lbox_httpd_immediate_html(struct lua_State *L)
{

	int idx  = lua_upvalueindex(1);

	luaL_Buffer b;
	luaL_buffinit(L, &b);

	lua_pushnumber(L, 1);
	lua_rawget(L, idx);
	if (lua_isnil(L, -1)) {
		luaL_addstring(&b, "");
		lua_pop(L, 1);
	} else {
		luaL_addvalue(&b);
	}


	int i, top = lua_gettop(L);
	for (i = 1; i <= top; i++) {
		if (lua_isnil(L, i)) {
			luaL_addstring(&b, "nil");
			continue;
		}
		lua_pushvalue(L, i);
		luaL_addvalue(&b);
	}

	lua_pushnumber(L, 1);
	luaL_pushresult(&b);
	lua_rawset(L, idx);
	return 0;
}

static int
lbox_httpd_template(struct lua_State *L)
{
	int top = lua_gettop(L);
	if (top == 1)
		lua_newtable(L);
	if (top != 2)
		luaL_error(L, "box.httpd.template: absent or spare argument");
	if (!lua_istable(L, 2))
		luaL_error(L, "usage: box.httpd.template(tpl, { var = val })");


	lua_newtable(L);	/* 3. results (closure table) */

	lua_pushnil(L);		/* 4. place for prepared html */

	lua_pushnil(L);		/* 5. place for process function */


	lua_pushvalue(L, 3);	/* _q */
	lua_pushcclosure(L, lbox_httpd_escape_html, 1);

	lua_pushvalue(L, 3);	/* _i */
	lua_pushcclosure(L, lbox_httpd_immediate_html, 1);

	size_t len;
	const char *str = lua_tolstring(L, 1, &len);

	luaL_Buffer b;
	luaL_buffinit(L, &b);

	luaL_addstring(&b, "return function(_q, _i");


	lua_pushnil(L);
	while(lua_next(L, 2) != 0) {
		size_t l;
		const char *s = lua_tolstring(L, -2, &l);

		/* TODO: check argument for lua syntax */

		luaL_addstring(&b, ", ");
		luaL_addlstring(&b, s, l);

		lua_pushvalue(L, -2);
		lua_remove(L, -3);
	}

	luaL_addstring(&b, ") ");

	tpe_parse(str, len, tpl_term, &b);

	luaL_addstring(&b, " end");

	luaL_pushresult(&b);

	lua_replace(L, 4);

	lua_pushvalue(L, 4);

	/* compile */
	if (luaL_dostring(L, lua_tostring(L, 4)) != 0)
		lua_error(L);


	lua_replace(L, 5);	/* process function */

	/* stack:
		1 - user's template,
		2 - user's arglist
		3 - closure table
		4 - prepared html
		5 - compiled function
		... function arguments
	*/

	if (lua_pcall(L, lua_gettop(L) - 5, 0, 0) != 0) {
		lua_getfield(L, -1, "match");

		lua_pushvalue(L, -2);
		lua_pushliteral(L, ":(%d+):(.*)");
		lua_call(L, 2, 2);


		lua_getfield(L, -1, "format");
		lua_pushliteral(L, "box.httpd.template: users template:%s: %s");
		lua_pushvalue(L, -4);
		lua_pushvalue(L, -4);
		lua_call(L, 3, 1);


		lua_error(L);
	}

	lua_pushnumber(L, 1);
	lua_rawget(L, 3);
	lua_replace(L, 3);

	return 2;
}

struct parse_object {
	parse_http_state state;
	header_t headers[0];
};

static int
lbox_http_parse_headers(struct lua_State *L)
{
	int top = lua_gettop(L);

	int max_headers;
	char *s;
	size_t len;

	switch(top) {
		case 1:
			max_headers = 128;
			break;
		case 2:
			max_headers = lua_tointeger(L, 2);
			if (max_headers < 32 || max_headers > 1024)
				luaL_error(L, "wrong value of max_headers: %d",
					max_headers);
			break;

		default:
			luaL_error(L, "bad arguments");
			break;
	}
	s = (char *)lua_tolstring(L, 1, &len);


	struct parse_object *po = (typeof(po))lua_newuserdata(L,
		 sizeof(struct parse_object) + sizeof(header_t) * max_headers);

	po->state.p = s;
	po->state.e = s + len;
	po->state.headers = po->headers;
	po->state.header_i = 0;
	po->state.header_max = max_headers;

	int res = parse_http_request(&po->state);

	if (res < 0) {
		lua_pushnil(L);
		lua_pushstring(L, "Parse header error");
		return 2;
	}

	luaL_error(L, "aaaaaaa %d", po->state.header_i);


	return 0;
}

static void
init(struct lua_State *L)
{
	extern char box_httpd_lua[];
	extern char box_http_lua[];
	static const char *lua_sources[] = {
		box_httpd_lua,
		box_http_lua,
		NULL
	};

	for (const char **s = lua_sources; *s; s++) {
		if (luaL_dostring(L, *s))
			panic("Error loading Lua source %.160s...: %s",
			      *s, lua_tostring(L, -1));
	}

	lua_getfield(L, LUA_GLOBALSINDEX, "box");
	lua_pushstring(L, "http");
	lua_rawget(L, -2);

	lua_pushstring(L, "split_url");
	lua_pushcfunction(L, lbox_http_split_url);
	lua_rawset(L, -3);

	lua_pushstring(L, "parse_headers");
	lua_pushcfunction(L, lbox_http_parse_headers);
	lua_rawset(L, -3);

	lua_pop(L, 2);





	lua_getfield(L, LUA_GLOBALSINDEX, "box");
	lua_pushstring(L, "httpd");
	lua_rawget(L, -2);

	lua_pushstring(L, "template");
	lua_pushcfunction(L, lbox_httpd_template);
	lua_rawset(L, -3);

	lua_pushstring(L, "parse_headers");
	lua_pushcfunction(L, lbox_http_parse_headers);
	lua_rawset(L, -3);

	lua_pop(L, 2);

}


DECLARE_PLUGIN(PLUGIN_NAME, PLUGIN_VERSION, init, NULL);
