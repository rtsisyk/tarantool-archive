-- box.httpd

(function(box, io, package, require)

local mime_table

print("Plugin box.httpd init...")

local function errorf(fmt, ...)
    error(string.format(fmt, ...))
end

local function printf(fmt, ...)
    print(string.format(fmt, ...))
end

local function sprintf(fmt, ...)
    return string.format(fmt, ...)
end

local function uri_escape(str)
    local res = string.gsub(str, '[^a-zA-Z0-9_]',
        function(c)
            return string.format('%%%02X', string.byte(c))
        end
    )
    return res
end

local function uri_unescape(str)
    local res = string.gsub(str, '%%([0-9a-fA-F][0-9a-fA-F])',
        function(c)
            return string.char(tonumber(c, 16))
        end
    )
    return res
end

local function extend(tbl, tblu, raise)
    local res = {}
    for k, v in pairs(tbl) do
        res[ k ] = v
    end
    for k, v in pairs(tblu) do
        if raise then
            if res[ k ] == nil then
                errorf("Unknown option '%s'", k)
            end
        end
        res[ k ] = v
    end
    return res
end

local function type_by_format(fmt)
    if fmt == nil then
        return 'application/octet-stream'
    end

    local t = mime_table[ fmt ]

    if t ~= nil then
        return t
    end

    return 'application/octet-stream'
end


local server_title =
    sprintf('Tarantool/%s box.httpd server', box.info.version)

local codes = {
    [200] = 'Ok',
    [201] = 'Created',
    [202] = 'Accepted',
    [203] = 'Non authoritative information',
    [204] = 'No content',
    [205] = 'Reset content',
    [206] = 'Partial content',
    [207] = 'Multi status',
    [208] = 'Already reported',
    [226] = 'IM used',
    [300] = 'Multiple choises',
    [301] = 'Moved permanently',
    [302] = 'Found',
    [303] = 'See other',
    [304] = 'Not modified',
    [305] = 'Use proxy',
    [307] = 'Temporary redirect',
    [400] = 'Bad request',
    [401] = 'Unauthorized',
    [402] = 'Payment required',
    [403] = 'Forbidden',
    [404] = 'Not found',
    [405] = 'Method not allowed',
    [406] = 'Not acceptable',
    [407] = 'Proxy authentification required',
    [408] = 'Request timeout',
    [409] = 'Conflict',
    [410] = 'Gone',
    [411] = 'Length required',
    [412] = 'Precondition failed',
    [413] = 'Request entity too large',
    [414] = 'Request uri too large',
    [415] = 'Unsupported media type',
    [416] = 'Request range not satisfiable',
    [417] = 'Expectation failed',
    [418] = 'I am a teapot',
    [422] = 'Unprocessable entity',
    [423] = 'Locked',
    [424] = 'Failed dependency',
    [425] = 'No code',
    [426] = 'Upgrade required',
    [428] = 'Precondition required',
    [429] = 'Too many requests',
    [431] = 'Request header fields too large',
    [449] = 'Retry with',
    [451] = 'Unavailable for legal reasons',
    [456] = 'Unrecoverable error',
    [500] = 'Internal server error',
    [501] = 'Not implemented',
    [502] = 'Bad gateway',
    [503] = 'Service unavailable',
    [504] = 'Gateway timeout',
    [505] = 'Http version not supported',
    [506] = 'Variant also negotiates',
    [507] = 'Insufficient storage',
    [509] = 'Bandwidth limit exceeded',
    [510] = 'Not extended',
    [511] = 'Network authentication required',
}

local function reason_by_code(code)
    code = tonumber(code)
    if codes[code] ~= nil then
        return codes[code]
    end
    return sprintf('Unknown code %d', code)
end

local function ucfirst(str)
    return str:gsub("^%l", string.upper, 1)
end

local function cached_query_param(self, name)
    if name == nil then
        return self.query_params
    end
    return self.query_params[ name ]
end

local function cached_post_param(self, name)
    if name == nil then
        return self.post_params
    end
    return self.post_params[ name ]
end

local request_methods = {
    to_string = function(self)
        local res = self:request_line() .. "\r\n"

        for hn, hv in pairs(self.headers) do
            res = sprintf("%s%s: %s\r\n", res, ucfirst(hn), hv)
        end

        return sprintf("%s\r\n%s", res, self.body)
    end,

    request_line = function(self)
        local rstr = self.path
        if string.len(self.query) then
            rstr = rstr .. '?' .. self.query
        end
        return sprintf("%s %s HTTP/%d.%d",
            self.method, rstr, self.proto[1], self.proto[2])
    end,

    query_param = function(self, name)
        if self.query == nil and string.len(self.query) == 0 then
            rawset(self, 'query_params', {})
        else
            local params = box.httpd.params(self.query)
            local pres = {}
            for k, v in pairs(params) do
                pres[ uri_unescape(k) ] = uri_unescape(v)
            end
            rawset(self, 'query_params', pres)
        end

        rawset(self, 'query_param', cached_query_param)
        return self:query_param(name)
    end,

    post_param = function(self, name)
        if self.headers[ 'content-type' ] == 'multipart/form-data' then
            -- TODO: do that!
            rawset(self, 'post_params', {})
        else
            local params = box.httpd.params(self.body)
            local pres = {}
            for k, v in pairs(params) do
                pres[ uri_unescape(k) ] = uri_unescape(v)
            end
            rawset(self, 'post_params', pres)
        end
        
        rawset(self, 'post_param', cached_post_param)
        return self:post_param(name)
    end,

    param = function(self, name)
        if name ~= nil then
            local v = self:post_param(name)
            if v ~= nil then
                return v
            end
            return self:query_param(name)
        end

        local post = self:post_param()
        local query = self:query_param()
        return extend(post, query, false)
    end
}

local mrequest = {
    __index = function(req, item)
        if item == 'body' then

            if req.s == nil then
                rawset(req, 's', nil)
                rawset(req, 'body', '')
                return ''
            end

            if req.headers['content-length'] == nil then
                rawset(req, 's', nil)
                rawset(req, 'body', '')
                return ''
            end

            local cl = tonumber(req.headers['content-length'])

            if cl == 0 then
                rawset(req, 's', nil)
                rawset(req, 'body', '')
                return ''
            end

            local body, status, eno, estr = req.s:recv(cl)

            if status ~= nil then
                printf("Can't read request body: %s %s", status, estr)
                rawset(req, 's', nil)
                rawset(req, 'body', '')
                rawset(req, 'broken', true)
                return ''
            end
            rawset(req, 's', nil)
            if body ~= nil then
                rawset(req, 'body', body)
                return body
            else
                rawset(req, 'body', '')
                return ''
            end
        end

        if item == 'json' then
            local s, json = pcall(box.cjson.decode, req.body)
            if s then
                rawset(req, 'json', json)
                return json
            else
                printf("Can't decode json in request '%s': %s",
                    req:request_line(), json)
                return nil
            end
        end
    end
}

local function catfile(...)
    local sp = { ... }

    local path

    if #sp == 0 then
        return
    end

    for i, pe in pairs(sp) do
        if path == nil then
            path = pe
        elseif string.match(path, '.$') ~= '/' then
            if string.match(pe, '^.') ~= '/' then
                path = path .. '/' .. pe
            else
                path = path .. pe
            end
        else
            if string.match(pe, '^.') == '/' then
                path = path .. string.gsub(pe, '^/', '', 1)
            else
                path = path .. pe
            end
        end
    end

    return path
end

local function log(peer, code, req, len)
    if req == nil then
        len = 0
        req = '-'
    else
        if len == nil then
            len = 0
        end
    end

    printf("%s - - \"%s\" %s %s\n", peer, req, code, len)
end

local function hlog(peer, code, hdr)
    if string.len(hdr) == 0 then
        return log(peer, code)
    end
    local rs = string.match(hdr, "^(.-)[\r\n]")
    if rs == nil then
        return log(peer, code, hdr)
    else
        return log(peer, code, rs)
    end
end

local function expires_str(str)

    local now = os.time()
    local gmtnow = now - os.difftime(now, os.time(os.date("!*t", now)))
    local fmt = '%a, %d-%b-%Y %H:%M:%S GMT'

    if str == 'now' or str == 0 or str == '0' then
        return os.date(fmt, gmtnow)
    end

    local diff, period = string.match(str, '^[+]?(%d+)([hdmy])$')
    if period == nil then
        return str
    end

    diff = tonumber(diff)
    if period == 'h' then
        diff = diff * 3600
    elseif period == 'd' then
        diff = diff * 86400
    elseif period == 'm' then
        diff = diff * 86400 * 30
    else
        diff = diff * 86400 * 365
    end

    return os.date(fmt, gmtnow + diff)
end

local function set_cookie(tx, cookie)
    local name = cookie.name
    local value = cookie.value

    if name == nil then
        error('cookie.name is undefined')
    end
    if value == nil then
        error('cookie.value is undefined')
    end

    local str = sprintf('%s=%s', name, uri_escape(value))
    if cookie.path ~= nil then
        str = sprintf('%s;path=%s', str, uri_escape(cookie.path))
    else
        str = sprintf('%s;path=%s', str, tx.req.path)
    end
    if cookie.domain ~= nil then
        str = sprintf('%s;domain=%s', str, domain)
    end

    if cookie.expires ~= nil then
        str = sprintf('%s;expires="%s"', str, expires_str(cookie.expires))
    end

    if tx.resp.headers['set-cookie'] == nil then
        tx.resp.headers['set-cookie'] = { str }
    elseif type(tx.resp.headers['set-cookie']) == 'string' then
        tx.resp.headers['set-cookie'] = {
            tx.resp.headers['set-cookie'],
            str
        }
    else
        table.insert(tx.resp.headers['set-cookie'], str)
    end
    return str
end

local function cookie(tx, cookie)
    if type(cookie) == 'table' then
        return set_cookie(tx, cookie)
    end
    
    if tx.req.headers.cookie == nil then
        return nil
    end
    for k, v in string.gmatch(
                tx.req.headers.cookie, "([^=,; \t]+)=([^,; \t]+)") do
        if k == cookie then
            return uri_unescape(v)
        end
    end
    return nil
end

local function url_for_helper(tx, name, args, query)
    return tx:url_for(name, args, query)
end

local function load_template(self, r, format)
    if r.template ~= nil then
        return
    end

    if format == nil then
        format = 'html'
    end

    local file
    if r.file ~= nil then
        file = r.file
    elseif r.controller ~= nil and r.action ~= nil then
        file = catfile(
            string.gsub(r.controller, '[.]', '/'),
            r.action .. '.' .. format .. '.el')
    else
        errorf("Can not find template for '%s'", r.path)
    end
    
    if self.options.cache_templates then
        if self.cache.tpl[ file ] ~= nil then
            return self.cache.tpl[ file ]
        end
    end


    local tpl = catfile(self.options.app_dir, 'templates', file)
    local fh = io.input(tpl)
    local template = fh:read('*a')
    fh:close()

    if self.options.cache_templates then
        self.cache.tpl[ file ] = template
    end
    return template
end


local function render(tx, opts)
    if tx == nil then
        error("Usage: self:render({ ... })")
    end

    local vars = {}
    if opts ~= nil then
        if opts.text ~= nil then
            if tx.httpd.options.charset ~= nil then
                tx.resp.headers['content-type'] =
                    sprintf("text/plain; charset=%s",
                        tx.httpd.options.charset
                    )
            else
                tx.resp.headers['content-type'] = 'text/plain'
            end
            tx.resp.body = tostring(opts.text)
            return
        end

        if opts.json ~= nil then
            if tx.httpd.options.charset ~= nil then
                tx.resp.headers['content-type'] =
                    sprintf('application/json; charset=%s',
                        tx.httpd.options.charset
                    )
            else
                tx.resp.headers['content-type'] = 'application/json'
            end
            tx.resp.body = box.json.encode(opts.json)
            return
        end

        if opts.data ~= nil then
            tx.resp.body = tostring(data)
            return
        end

        vars = extend(tx.tstash, opts, false)
    end
    
    local tpl

    local format = tx.tstash.format
    if format == nil then
        format = 'html'
    end
    
    if tx.endpoint.template ~= nil then
        tpl = tx.endpoint.template
    else
        tpl = load_template(tx.httpd, tx.endpoint, format)
        if tpl == nil then
            errorf('template is not defined for the route')
        end
    end

    if type(tpl) == 'function' then
        tpl = tpl()
    end

    for hname, sub in pairs(tx.httpd.helpers) do
        vars[hname] = function(...) return sub(tx, ...) end
    end
    vars.action = tx.endpoint.action
    vars.controller = tx.endpoint.controller
    vars.format = format

    tx.resp.body = box.httpd.template(tpl, vars)
    tx.resp.headers['content-type'] = type_by_format(format)

    if tx.httpd.options.charset ~= nil then
        if format == 'html' or format == 'js' or format == 'json' then
            tx.resp.headers['content-type'] = tx.resp.headers['content-type']
                .. '; charset=' .. tx.httpd.options.charset
        end
    end
end

local function redirect_to(tx, name, args, query)
    tx.resp.headers.location = tx:url_for(name, args, query)
    tx.resp.status = 302
end

local function access_stash(tx, name, ...)
    if type(tx) ~= 'table' then
        error("usage: ctx:stash('name'[, 'value'])")
    end
    if select('#', ...) > 0 then
        tx.tstash[ name ] = select(1, ...)
    end

    return tx.tstash[ name ]
end

local function url_for_tx(tx, name, args, query)
    if name == 'current' then
        return tx.endpoint:url_for(args, query)
    end
    return tx.httpd:url_for(name, args, query)
end

local function static_file(self, request, format)
        local file = catfile(self.options.app_dir, 'public', request.path)

        if self.options.cache_static and self.cache.static[ file ] ~= nil then
            return {
                200,
                {
                    [ 'content-type'] = type_by_format(format),
                },
                self.cache.static[ file ]
            }
        end

        local s, fh = pcall(io.input, file)

        if not s then
            return { 404 }
        end

        local body = fh:read('*a')
        io.close(fh)

        if self.options.cache_static then
            self.cache.static[ file ] = body
        end

        return {
            200,
            {
                [ 'content-type'] = type_by_format(format),
            },
            body
        }
end

local function handler(self, request)

    if self.hooks.before_routes ~= nil then
        self.hooks.before_dispatch(self, request)
    end

    local format = 'html'

    local pformat = string.match(request.path, '[.]([^.]+)$')
    if pformat ~= nil then
        format = pformat
    end


    local r = self:match(request.method, request.path)
    if r == nil then
        return static_file(self, request, format)
    end

    local stash = extend(r.stash, { format = format })


    local tx = {
        req         = request,
        resp        = { headers = {}, body = '', code = 200 },
        endpoint    = r.endpoint,
        tstash      = stash,
        render      = render,
        cookie      = cookie,
        redirect_to = redirect_to,
        httpd       = self,
        stash       = access_stash,
        url_for     = url_for_tx
    }

    r.endpoint.sub( tx )


    local res = { tx.resp.code, tx.resp.headers, tx.resp.body }

    if self.hooks.after_dispatch ~= nil then
        self.hooks.after_dispatch(tx, res)
    end

    return res
end

local function normalize_headers(hdrs)
    local res = {}
    for h, v in pairs(hdrs) do
        res[ string.lower(h) ] = v
    end
    return res
end

local function process_client(self, s, peer)

    while true do

        local hdrs = {
            s:readline(
                self.options.max_header_size,
                { "\n\n", "\r\n\r\n" },
                self.options.header_timeout
            )
        }

        if hdrs[2] == 'limit' then
            hlog(peer, 400, hdrs[1])
            break
        end
        if hdrs[2] ~= nil then
            printf("Error while reading headers: %s, %s (%s)",
                hdrs[4], hdrs[2], peer)
            break
        end

        local p = box.httpd.parse_request(hdrs[1])
        if rawget(p, 'error') ~= nil then
            if rawget(p, 'method') ~= nil then
                log(peer, 400, p:request_line())
            else
                hlog(peer, 400, hdrs[1])
            end
            s:send(sprintf("HTTP/1.0 400 Bad request\r\n\r\n%s", p.error))
            break
        end

        -- first access at body will load body
        if p.method ~= 'GET' then
            rawset(p, 'body', nil)
            rawset(p, 's', s)
        end

        local res = { pcall(self.options.handler, self, p) }
        local code, hdrs, body

        if res[1] == false then
            code = 500
            hdrs = {}
            body =
                  "Unhandled error:\n"
                .. debug.traceback(res[2]) .. "\n\n"

                .. "\n\nRequest:\n"
                .. p:to_string()

        else
            code = res[2][1]
            hdrs = res[2][2]
            body = res[2][3]

            if type(body) == 'table' then
                body = table.concat(body)
            else
                if body == nil then
                    body = ''
                end
            end

            if hdrs == nil then
                hdrs = {}
            elseif type(hdrs) ~= 'table' then
                code = 500
                hdrs = {}
                body = sprintf(
                    'Handler returned non-table headers: %s',
                    type(hdrs)
                )
            end
        end

        hdrs = normalize_headers(hdrs)

        if hdrs.server == nil then
            hdrs.server = server_title
        end

        if p.proto[1] ~= 1 then
            hdrs.connection = 'close'
        elseif p.broken then
            hdrs.connection = 'close'
        elseif rawget(p, 'body') == nil then
            hdrs.connection = 'close'
        elseif p.proto[2] == 1 then
            if p.headers.connection == nil then
                hdrs.connection = 'keep-alive'
            elseif string.lower(p.headers.connection) ~= 'keep-alive' then
                hdrs.connection = 'close'
            else
                hdrs.connection = 'keep-alive'
            end
        elseif p.proto[2] == 0 then
            if p.headers.connection == nil then
                hdrs.connection = 'close'
            elseif string.lower(p.headers.connection) == 'keep-alive' then
                hdrs.connection = 'keep-alive'
            else
                hdrs.connection = 'close'
            end
        end

        hdrs['content-length'] = string.len(body)

        local hdr = ''
        for k, v in pairs(hdrs) do
            if type(v) == 'table' then
                for i, sv in pairs(v) do
                    hdr = hdr .. sprintf("%s: %s\r\n", ucfirst(k), sv)
                end
            else
                hdr = hdr .. sprintf("%s: %s\r\n", ucfirst(k), v)
            end
        end


        s:send(sprintf(
            "HTTP/1.1 %s %s\r\n%s\r\n%s",
            code,
            reason_by_code(code),
            hdr,
            body
        ))

        if p.proto[1] ~= 1 then
            break
        end

        if hdrs.connection ~= 'keep-alive' then
            break
        end
    end
    s:close()
end

local function httpd_stop(self)
   if type(self) ~= 'table' then
       error("box.httpd: usage: httpd:stop()")
    end
    if self.is_run then
        self.is_run = false
    else
        error("server is already stopped")
    end
    return self
end

local function match_route(self, method, route)

    -- format
    route = string.gsub(route, '([^/])[.][^.]+$', '%1')
    
    -- route must have '/' at the begin and end
    if string.match(route, '.$') ~= '/' then
        route = route .. '/'
    end
    if string.match(route, '^.') ~= '/' then
        route = '/' .. route
    end

    method = string.upper(method)

    local fit
    local stash = {}

    for k, r in pairs(self.routes) do
        if r.method == method or r.method == 'ANY' then
            local m = { string.match(route, r.match)  }
            local nfit
            if #m > 0 then
                if #r.stash > 0 then
                    if #r.stash == #m then
                        nfit = r
                    end
                else
                    nfit = r
                end

                if nfit ~= nil then
                    if fit == nil then
                        fit = nfit
                        stash = m
                    else
                        if #fit.stash > #nfit.stash then
                            fit = nfit
                            stash = m
                        elseif r.method ~= fit.method then
                            if fit.method == 'ANY' then
                                fit = nfit
                                stash = m
                            end
                        end
                    end
                end
            end
        end
    end

    if fit == nil then
        return fit
    end
    local resstash = {}
    for i = 1, #fit.stash do
        resstash[ fit.stash[ i ] ] = stash[ i ]
    end
    return  { endpoint = fit, stash = resstash }
end

local function set_helper(self, name, sub)
    if sub == nil or type(sub) == 'function' then
        self.helpers[ name ] = sub
        return self
    end
    errorf("Wrong type for helper function: %s", type(sub))
end

local function set_hook(self, name, sub)
    if sub == nil or type(sub) == 'function' then
        self.hooks[ name ] = sub
    end
    errorf("Wrong type for hook function: %s", type(sub))
end

local function url_for_route(r, args, query)
    if args == nil then
        args = {}
    end
    name = r.path
    for i, sn in pairs(r.stash) do
        local sv = args[sn]
        if sv == nil then
            sv = ''
        end
        name = string.gsub(name, '[*:]' .. sn, sv, 1)
    end

    if query ~= nil then
        if type(query) == 'table' then
            local sep = '?'
            for k, v in pairs(query) do
                name = name .. sep .. uri_escape(k) .. '=' .. uri_escape(v)
                sep = '&'
            end
        else
            name = name .. '?' .. query
        end
    end

    if string.match(name, '^/') == nil then
        return '/' .. name
    else
        return name
    end
end

local function ctx_action(tx)
    local ctx = tx.endpoint.controller
    local action = tx.endpoint.action
    if tx.httpd.options.cache_controllers then
        if tx.httpd.cache[ ctx ] ~= nil then
            if type(tx.httpd.cache[ ctx ][ action ]) ~= 'function' then
                errorf("Controller '%s' doesn't contain function '%s'",
                    ctx, action)
            end
            tx.httpd.cache[ ctx ][ action ](tx)
            return
        end
    end

    local ppath = package.path
    package.path = catfile(tx.httpd.options.app_dir, 'controllers', '?.lua')
                .. ';'
                .. catfile(tx.httpd.options.app_dir,
                    'controllers', '?/init.lua')
    if ppath ~= nil then
        package.path = package.path .. ';' .. ppath
    end

    local st, mod = pcall(require, ctx)
    package.path = ppath
    package.loaded[ ctx ] = nil

    if not st then
        errorf("Can't load module '%s': %s'", ctx, mod)
    end

    if type(mod) ~= 'table' then
        errorf("require '%s' didn't return table", ctx)
    end

    if type(mod[ action ]) ~= 'function' then
        errorf("Controller '%s' doesn't contain function '%s'", ctx, action)
    end

    if tx.httpd.options.cache_controllers then
        tx.httpd.cache[ ctx ] = mod
    end

    mod[action](tx)
end

local function add_route(self, opts, sub)
    if type(opts) ~= 'table' or type(self) ~= 'table' then
        error("Usage: httpd:route({ ... }, function(cx) ... end)")
    end

    opts = extend({method = 'ANY'}, opts, false)
    
    local ctx
    local action

    if sub == nil then
        sub = function(cx) cx:render() end
    elseif type(sub) == 'string' then

        ctx, action = string.match(sub, '(.+)#(.*)')

        if ctx == nil or action == nil then
            errorf("Wrong controller format '%s', must be 'module#action'", sub)
        end

        sub = ctx_action
        
    elseif type(sub) ~= 'function' then
        errorf("wrong argument: expected function, but received %s",
            type(sub))
    end


    opts.method = string.upper(opts.method)

    if opts.method ~= 'GET' and opts.method ~= 'POST' then
        opts.method = 'ANY'
    end

    if opts.path == nil then
        error("path is not defined")
    end

    opts.controller = ctx
    opts.action = action
    opts.match = opts.path
    opts.match = string.gsub(opts.match, '[-]', "[-]")

    local estash = {  }
    local stash = {  }
    while true do
        local name = string.match(opts.match, ':([%a_][%w_]*)')
        if name == nil then
            break
        end
        if estash[name] then
            errorf("duplicate stash: %s", name)
        end
        estash[name] = true
        opts.match = string.gsub(opts.match, ':[%a_][%w_]*', '([^/]-)', 1)

        table.insert(stash, name)
    end
    while true do
        local name = string.match(opts.match, '[*]([%a_][%w_]*)')
        if name == nil then
            break
        end
        if estash[name] then
            errorf("duplicate stash: %s", name)
        end
        estash[name] = true
        opts.match = string.gsub(opts.match, '[*][%a_][%w_]*', '(.-)', 1)

        table.insert(stash, name)
    end

    if string.match(opts.match, '.$') ~= '/' then
        opts.match = opts.match .. '/'
    end
    if string.match(opts.match, '^.') ~= '/' then
        opts.match = '/' .. opts.match
    end

    opts.match = '^' .. opts.match .. '$'

    estash = nil

    opts.stash = stash
    opts.sub = sub
    opts.url_for = url_for_route

    if opts.name ~= nil then
        if opts.name == 'current' then
            error("Route can not have name 'current'")
        end
        if self.iroutes[ opts.name ] ~= nil then
            errorf("Route with name '%s' is already exists", opts.name)
        end
        table.insert(self.routes, opts)
        self.iroutes[ opts.name ] = #self.routes
    else
        table.insert(self.routes, opts)
    end
    return self
end

local function url_for_httpd(httpd, name, args, query)
    
    local idx = httpd.iroutes[ name ]
    if idx ~= nil then
        return httpd.routes[ idx ]:url_for(args, query)
    end

    if string.match(name, '^/') == nil then
        if string.match(name, '^https?://') ~= nil then
            return name
        else
            return '/' .. name
        end
    else
        return name
    end
end

local function httpd_start(self)
    if type(self) ~= 'table' then
        error("box.httpd: usage: httpd:start()")
    end
    local s = box.socket.tcp()
    if s == nil then
        error("Can't create new tcp socket")
    end

    local res = { s:bind(self.host, self.port) }
    if res[1] == 'error' then
        errorf("Can't bind socket: %s", res[3])
    end

    res = { s:listen() }
    if res[1] == 'error' then
        errorf("Can't listen socket: %s", res[3])
    end

    rawset(self, 'is_run', true)
    rawset(self, 's', s)
    rawset(self, 'stop', httpd_stop)

    box.fiber.wrap(function()
        printf('box.httpd: started at host=%s, port=%s',
            self.host, self.port)
        while self.is_run do
            local cs, status, es, eport = s:accept(.1)
            if cs == 'error' then
                printf("Can't accept socket: %s", es)
                break
            elseif cs ~= 'timeout' then
                es = sprintf('%s:%s', es, eport)
                box.fiber.wrap(function() process_client(self, cs, es) end)
                cs = nil
            end
        end
        self.s:close()
        rawset(self, 's', nil)
        rawset(self, 'is_run', false)
    end)

    return self
end

box.httpd = {
    new = function(host, port, options)
        if options == nil then
            options = {}
        end
        if type(options) ~= 'table' then
            errorf("options must be table not '%s'", type(options))
        end
        local default = {
            max_header_size     = 4096,
            header_timeout      = 100,
            handler             = handler,
            app_dir             = '.',
            charset             = 'utf-8',
            cache_templates     = true,
            cache_controllers   = true,
            cache_static        = true,
        }

        local self = {
            host    = host,
            port    = port,
            is_run  = false,
            stop    = httpd_stop,
            start   = httpd_start,
            options = extend(default, options, true),

            routes  = {  },
            iroutes = {  },
            helpers = {
                url_for = url_for_helper,
            },
            hooks   = {  },

            -- methods
            route   = add_route,
            match   = match_route,
            helper  = set_helper,
            hook    = set_hook,
            url_for = url_for_httpd,

            -- caches
            cache   = {
                tpl         = {},
                ctx         = {},
                static      = {},
            },
        }

        return self
    end,

    parse_request = function(str)
        local req = box.httpd._parse_request(str)
        if req.error ~= nil then
            return req
        end

        rawset(req, 'broken', false)

        for m, f in pairs(request_methods) do
            req[ m ] = f
        end

        setmetatable(req, mrequest)

        return req
    end,
}

-- the table can be created by command (in Vim):
-- :r !grep '^[a-z]' /etc/mime.types|grep '[[:space:]][^[:space:]]'|awk '{ for (i = 2; i <= NF; i++) print "['"'"'" $i "'"'"'] = '"'"'" $1  "'"'"'," }'

mime_table = {

    ['ez']          = 'application/andrew-inset',
    ['anx']         = 'application/annodex',
    ['atom']        = 'application/atom+xml',
    ['atomcat']     = 'application/atomcat+xml',
    ['atomsrv']     = 'application/atomserv+xml',
    ['lin']         = 'application/bbolin',
    ['cu']          = 'application/cu-seeme',
    ['davmount']    = 'application/davmount+xml',
    ['dcm']         = 'application/dicom',
    ['tsp']         = 'application/dsptype',
    ['es']          = 'application/ecmascript',
    ['spl']         = 'application/futuresplash',
    ['hta']         = 'application/hta',
    ['jar']         = 'application/java-archive',
    ['ser']         = 'application/java-serialized-object',
    ['class']       = 'application/java-vm',
    ['js']          = 'application/javascript',
    ['json']        = 'application/json',
    ['m3g']         = 'application/m3g',
    ['hqx']         = 'application/mac-binhex40',
    ['cpt']         = 'application/mac-compactpro',
    ['nb']          = 'application/mathematica',
    ['nbp']         = 'application/mathematica',
    ['mbox']        = 'application/mbox',
    ['mdb']         = 'application/msaccess',
    ['doc']         = 'application/msword',
    ['dot']         = 'application/msword',
    ['mxf']         = 'application/mxf',
    ['bin']         = 'application/octet-stream',
    ['oda']         = 'application/oda',
    ['ogx']         = 'application/ogg',
    ['one']         = 'application/onenote',
    ['onetoc2']     = 'application/onenote',
    ['onetmp']      = 'application/onenote',
    ['onepkg']      = 'application/onenote',
    ['pdf']         = 'application/pdf',
    ['pgp']         = 'application/pgp-encrypted',
    ['key']         = 'application/pgp-keys',
    ['sig']         = 'application/pgp-signature',
    ['prf']         = 'application/pics-rules',
    ['ps']          = 'application/postscript',
    ['ai']          = 'application/postscript',
    ['eps']         = 'application/postscript',
    ['epsi']        = 'application/postscript',
    ['epsf']        = 'application/postscript',
    ['eps2']        = 'application/postscript',
    ['eps3']        = 'application/postscript',
    ['rar']         = 'application/rar',
    ['rdf']         = 'application/rdf+xml',
    ['rtf']         = 'application/rtf',
    ['stl']         = 'application/sla',
    ['smi']         = 'application/smil+xml',
    ['smil']        = 'application/smil+xml',
    ['xhtml']       = 'application/xhtml+xml',
    ['xht']         = 'application/xhtml+xml',
    ['xml']         = 'application/xml',
    ['xsd']         = 'application/xml',
    ['xsl']         = 'application/xslt+xml',
    ['xslt']        = 'application/xslt+xml',
    ['xspf']        = 'application/xspf+xml',
    ['zip']         = 'application/zip',
    ['apk']         = 'application/vnd.android.package-archive',
    ['cdy']         = 'application/vnd.cinderella',
    ['kml']         = 'application/vnd.google-earth.kml+xml',
    ['kmz']         = 'application/vnd.google-earth.kmz',
    ['xul']         = 'application/vnd.mozilla.xul+xml',
    ['xls']         = 'application/vnd.ms-excel',
    ['xlb']         = 'application/vnd.ms-excel',
    ['xlt']         = 'application/vnd.ms-excel',
    ['xlam']        = 'application/vnd.ms-excel.addin.macroEnabled.12',
    ['xlsb']        = 'application/vnd.ms-excel.sheet.binary.macroEnabled.12',
    ['xlsm']        = 'application/vnd.ms-excel.sheet.macroEnabled.12',
    ['xltm']        = 'application/vnd.ms-excel.template.macroEnabled.12',
    ['eot']         = 'application/vnd.ms-fontobject',
    ['thmx']        = 'application/vnd.ms-officetheme',
    ['cat']         = 'application/vnd.ms-pki.seccat',
    ['ppt']         = 'application/vnd.ms-powerpoint',
    ['pps']         = 'application/vnd.ms-powerpoint',
    ['ppam']        = 'application/vnd.ms-powerpoint.addin.macroEnabled.12',
    ['pptm']        = 'application/vnd.ms-powerpoint.presentation.macroEnabled.12',
    ['sldm']        = 'application/vnd.ms-powerpoint.slide.macroEnabled.12',
    ['ppsm']        = 'application/vnd.ms-powerpoint.slideshow.macroEnabled.12',
    ['potm']        = 'application/vnd.ms-powerpoint.template.macroEnabled.12',
    ['docm']        = 'application/vnd.ms-word.document.macroEnabled.12',
    ['dotm']        = 'application/vnd.ms-word.template.macroEnabled.12',
    ['odc']         = 'application/vnd.oasis.opendocument.chart',
    ['odb']         = 'application/vnd.oasis.opendocument.database',
    ['odf']         = 'application/vnd.oasis.opendocument.formula',
    ['odg']         = 'application/vnd.oasis.opendocument.graphics',
    ['otg']         = 'application/vnd.oasis.opendocument.graphics-template',
    ['odi']         = 'application/vnd.oasis.opendocument.image',
    ['odp']         = 'application/vnd.oasis.opendocument.presentation',
    ['otp']         = 'application/vnd.oasis.opendocument.presentation-template',
    ['ods']         = 'application/vnd.oasis.opendocument.spreadsheet',
    ['ots']         = 'application/vnd.oasis.opendocument.spreadsheet-template',
    ['odt']         = 'application/vnd.oasis.opendocument.text',
    ['odm']         = 'application/vnd.oasis.opendocument.text-master',
    ['ott']         = 'application/vnd.oasis.opendocument.text-template',
    ['oth']         = 'application/vnd.oasis.opendocument.text-web',
    ['pptx']        = 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    ['sldx']        = 'application/vnd.openxmlformats-officedocument.presentationml.slide',
    ['ppsx']        = 'application/vnd.openxmlformats-officedocument.presentationml.slideshow',
    ['potx']        = 'application/vnd.openxmlformats-officedocument.presentationml.template',
    ['xlsx']        = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    ['xltx']        = 'application/vnd.openxmlformats-officedocument.spreadsheetml.template',
    ['docx']        = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    ['dotx']        = 'application/vnd.openxmlformats-officedocument.wordprocessingml.template',
    ['cod']         = 'application/vnd.rim.cod',
    ['mmf']         = 'application/vnd.smaf',
    ['sdc']         = 'application/vnd.stardivision.calc',
    ['sds']         = 'application/vnd.stardivision.chart',
    ['sda']         = 'application/vnd.stardivision.draw',
    ['sdd']         = 'application/vnd.stardivision.impress',
    ['sdf']         = 'application/vnd.stardivision.math',
    ['sdw']         = 'application/vnd.stardivision.writer',
    ['sgl']         = 'application/vnd.stardivision.writer-global',
    ['sxc']         = 'application/vnd.sun.xml.calc',
    ['stc']         = 'application/vnd.sun.xml.calc.template',
    ['sxd']         = 'application/vnd.sun.xml.draw',
    ['std']         = 'application/vnd.sun.xml.draw.template',
    ['sxi']         = 'application/vnd.sun.xml.impress',
    ['sti']         = 'application/vnd.sun.xml.impress.template',
    ['sxm']         = 'application/vnd.sun.xml.math',
    ['sxw']         = 'application/vnd.sun.xml.writer',
    ['sxg']         = 'application/vnd.sun.xml.writer.global',
    ['stw']         = 'application/vnd.sun.xml.writer.template',
    ['sis']         = 'application/vnd.symbian.install',
    ['cap']         = 'application/vnd.tcpdump.pcap',
    ['pcap']        = 'application/vnd.tcpdump.pcap',
    ['vsd']         = 'application/vnd.visio',
    ['wbxml']       = 'application/vnd.wap.wbxml',
    ['wmlc']        = 'application/vnd.wap.wmlc',
    ['wmlsc']       = 'application/vnd.wap.wmlscriptc',
    ['wpd']         = 'application/vnd.wordperfect',
    ['wp5']         = 'application/vnd.wordperfect5.1',
    ['wk']          = 'application/x-123',
    ['7z']          = 'application/x-7z-compressed',
    ['abw']         = 'application/x-abiword',
    ['dmg']         = 'application/x-apple-diskimage',
    ['bcpio']       = 'application/x-bcpio',
    ['torrent']     = 'application/x-bittorrent',
    ['cab']         = 'application/x-cab',
    ['cbr']         = 'application/x-cbr',
    ['cbz']         = 'application/x-cbz',
    ['cdf']         = 'application/x-cdf',
    ['cda']         = 'application/x-cdf',
    ['vcd']         = 'application/x-cdlink',
    ['pgn']         = 'application/x-chess-pgn',
    ['mph']         = 'application/x-comsol',
    ['cpio']        = 'application/x-cpio',
    ['csh']         = 'application/x-csh',
    ['deb']         = 'application/x-debian-package',
    ['udeb']        = 'application/x-debian-package',
    ['dcr']         = 'application/x-director',
    ['dir']         = 'application/x-director',
    ['dxr']         = 'application/x-director',
    ['dms']         = 'application/x-dms',
    ['wad']         = 'application/x-doom',
    ['dvi']         = 'application/x-dvi',
    ['pfa']         = 'application/x-font',
    ['pfb']         = 'application/x-font',
    ['gsf']         = 'application/x-font',
    ['pcf']         = 'application/x-font',
    ['pcf.Z']       = 'application/x-font',
    ['woff']        = 'application/x-font-woff',
    ['mm']          = 'application/x-freemind',
    ['spl']         = 'application/x-futuresplash',
    ['gan']         = 'application/x-ganttproject',
    ['gnumeric']    = 'application/x-gnumeric',
    ['sgf']         = 'application/x-go-sgf',
    ['gcf']         = 'application/x-graphing-calculator',
    ['gtar']        = 'application/x-gtar',
    ['tgz']         = 'application/x-gtar-compressed',
    ['taz']         = 'application/x-gtar-compressed',
    ['hdf']         = 'application/x-hdf',
    ['hwp']         = 'application/x-hwp',
    ['ica']         = 'application/x-ica',
    ['info']        = 'application/x-info',
    ['ins']         = 'application/x-internet-signup',
    ['isp']         = 'application/x-internet-signup',
    ['iii']         = 'application/x-iphone',
    ['iso']         = 'application/x-iso9660-image',
    ['jam']         = 'application/x-jam',
    ['jnlp']        = 'application/x-java-jnlp-file',
    ['jmz']         = 'application/x-jmol',
    ['chrt']        = 'application/x-kchart',
    ['kil']         = 'application/x-killustrator',
    ['skp']         = 'application/x-koan',
    ['skd']         = 'application/x-koan',
    ['skt']         = 'application/x-koan',
    ['skm']         = 'application/x-koan',
    ['kpr']         = 'application/x-kpresenter',
    ['kpt']         = 'application/x-kpresenter',
    ['ksp']         = 'application/x-kspread',
    ['kwd']         = 'application/x-kword',
    ['kwt']         = 'application/x-kword',
    ['latex']       = 'application/x-latex',
    ['lha']         = 'application/x-lha',
    ['lyx']         = 'application/x-lyx',
    ['lzh']         = 'application/x-lzh',
    ['lzx']         = 'application/x-lzx',
    ['frm']         = 'application/x-maker',
    ['maker']       = 'application/x-maker',
    ['frame']       = 'application/x-maker',
    ['fm']          = 'application/x-maker',
    ['fb']          = 'application/x-maker',
    ['book']        = 'application/x-maker',
    ['fbdoc']       = 'application/x-maker',
    ['md5']         = 'application/x-md5',
    ['mif']         = 'application/x-mif',
    ['m3u8']        = 'application/x-mpegURL',
    ['wmd']         = 'application/x-ms-wmd',
    ['wmz']         = 'application/x-ms-wmz',
    ['com']         = 'application/x-msdos-program',
    ['exe']         = 'application/x-msdos-program',
    ['bat']         = 'application/x-msdos-program',
    ['dll']         = 'application/x-msdos-program',
    ['msi']         = 'application/x-msi',
    ['nc']          = 'application/x-netcdf',
    ['pac']         = 'application/x-ns-proxy-autoconfig',
    ['dat']         = 'application/x-ns-proxy-autoconfig',
    ['nwc']         = 'application/x-nwc',
    ['o']           = 'application/x-object',
    ['oza']         = 'application/x-oz-application',
    ['p7r']         = 'application/x-pkcs7-certreqresp',
    ['crl']         = 'application/x-pkcs7-crl',
    ['pyc']         = 'application/x-python-code',
    ['pyo']         = 'application/x-python-code',
    ['qgs']         = 'application/x-qgis',
    ['shp']         = 'application/x-qgis',
    ['shx']         = 'application/x-qgis',
    ['qtl']         = 'application/x-quicktimeplayer',
    ['rdp']         = 'application/x-rdp',
    ['rpm']         = 'application/x-redhat-package-manager',
    ['rss']         = 'application/x-rss+xml',
    ['rb']          = 'application/x-ruby',
    ['sci']         = 'application/x-scilab',
    ['sce']         = 'application/x-scilab',
    ['xcos']        = 'application/x-scilab-xcos',
    ['sh']          = 'application/x-sh',
    ['sha1']        = 'application/x-sha1',
    ['shar']        = 'application/x-shar',
    ['swf']         = 'application/x-shockwave-flash',
    ['swfl']        = 'application/x-shockwave-flash',
    ['scr']         = 'application/x-silverlight',
    ['sql']         = 'application/x-sql',
    ['sit']         = 'application/x-stuffit',
    ['sitx']        = 'application/x-stuffit',
    ['sv4cpio']     = 'application/x-sv4cpio',
    ['sv4crc']      = 'application/x-sv4crc',
    ['tar']         = 'application/x-tar',
    ['tcl']         = 'application/x-tcl',
    ['gf']          = 'application/x-tex-gf',
    ['pk']          = 'application/x-tex-pk',
    ['texinfo']     = 'application/x-texinfo',
    ['texi']        = 'application/x-texinfo',
    ['~']           = 'application/x-trash',
    ['%']           = 'application/x-trash',
    ['bak']         = 'application/x-trash',
    ['old']         = 'application/x-trash',
    ['sik']         = 'application/x-trash',
    ['t']           = 'application/x-troff',
    ['tr']          = 'application/x-troff',
    ['roff']        = 'application/x-troff',
    ['man']         = 'application/x-troff-man',
    ['me']          = 'application/x-troff-me',
    ['ms']          = 'application/x-troff-ms',
    ['ustar']       = 'application/x-ustar',
    ['src']         = 'application/x-wais-source',
    ['wz']          = 'application/x-wingz',
    ['crt']         = 'application/x-x509-ca-cert',
    ['xcf']         = 'application/x-xcf',
    ['fig']         = 'application/x-xfig',
    ['xpi']         = 'application/x-xpinstall',
    ['amr']         = 'audio/amr',
    ['awb']         = 'audio/amr-wb',
    ['axa']         = 'audio/annodex',
    ['au']          = 'audio/basic',
    ['snd']         = 'audio/basic',
    ['csd']         = 'audio/csound',
    ['orc']         = 'audio/csound',
    ['sco']         = 'audio/csound',
    ['flac']        = 'audio/flac',
    ['mid']         = 'audio/midi',
    ['midi']        = 'audio/midi',
    ['kar']         = 'audio/midi',
    ['mpga']        = 'audio/mpeg',
    ['mpega']       = 'audio/mpeg',
    ['mp2']         = 'audio/mpeg',
    ['mp3']         = 'audio/mpeg',
    ['m4a']         = 'audio/mpeg',
    ['m3u']         = 'audio/mpegurl',
    ['oga']         = 'audio/ogg',
    ['ogg']         = 'audio/ogg',
    ['opus']        = 'audio/ogg',
    ['spx']         = 'audio/ogg',
    ['sid']         = 'audio/prs.sid',
    ['aif']         = 'audio/x-aiff',
    ['aiff']        = 'audio/x-aiff',
    ['aifc']        = 'audio/x-aiff',
    ['gsm']         = 'audio/x-gsm',
    ['m3u']         = 'audio/x-mpegurl',
    ['wma']         = 'audio/x-ms-wma',
    ['wax']         = 'audio/x-ms-wax',
    ['ra']          = 'audio/x-pn-realaudio',
    ['rm']          = 'audio/x-pn-realaudio',
    ['ram']         = 'audio/x-pn-realaudio',
    ['ra']          = 'audio/x-realaudio',
    ['pls']         = 'audio/x-scpls',
    ['sd2']         = 'audio/x-sd2',
    ['wav']         = 'audio/x-wav',
    ['alc']         = 'chemical/x-alchemy',
    ['cac']         = 'chemical/x-cache',
    ['cache']       = 'chemical/x-cache',
    ['csf']         = 'chemical/x-cache-csf',
    ['cbin']        = 'chemical/x-cactvs-binary',
    ['cascii']      = 'chemical/x-cactvs-binary',
    ['ctab']        = 'chemical/x-cactvs-binary',
    ['cdx']         = 'chemical/x-cdx',
    ['cer']         = 'chemical/x-cerius',
    ['c3d']         = 'chemical/x-chem3d',
    ['chm']         = 'chemical/x-chemdraw',
    ['cif']         = 'chemical/x-cif',
    ['cmdf']        = 'chemical/x-cmdf',
    ['cml']         = 'chemical/x-cml',
    ['cpa']         = 'chemical/x-compass',
    ['bsd']         = 'chemical/x-crossfire',
    ['csml']        = 'chemical/x-csml',
    ['csm']         = 'chemical/x-csml',
    ['ctx']         = 'chemical/x-ctx',
    ['cxf']         = 'chemical/x-cxf',
    ['cef']         = 'chemical/x-cxf',
    ['emb']         = 'chemical/x-embl-dl-nucleotide',
    ['embl']        = 'chemical/x-embl-dl-nucleotide',
    ['spc']         = 'chemical/x-galactic-spc',
    ['inp']         = 'chemical/x-gamess-input',
    ['gam']         = 'chemical/x-gamess-input',
    ['gamin']       = 'chemical/x-gamess-input',
    ['fch']         = 'chemical/x-gaussian-checkpoint',
    ['fchk']        = 'chemical/x-gaussian-checkpoint',
    ['cub']         = 'chemical/x-gaussian-cube',
    ['gau']         = 'chemical/x-gaussian-input',
    ['gjc']         = 'chemical/x-gaussian-input',
    ['gjf']         = 'chemical/x-gaussian-input',
    ['gal']         = 'chemical/x-gaussian-log',
    ['gcg']         = 'chemical/x-gcg8-sequence',
    ['gen']         = 'chemical/x-genbank',
    ['hin']         = 'chemical/x-hin',
    ['istr']        = 'chemical/x-isostar',
    ['ist']         = 'chemical/x-isostar',
    ['jdx']         = 'chemical/x-jcamp-dx',
    ['dx']          = 'chemical/x-jcamp-dx',
    ['kin']         = 'chemical/x-kinemage',
    ['mcm']         = 'chemical/x-macmolecule',
    ['mmd']         = 'chemical/x-macromodel-input',
    ['mmod']        = 'chemical/x-macromodel-input',
    ['mol']         = 'chemical/x-mdl-molfile',
    ['rd']          = 'chemical/x-mdl-rdfile',
    ['rxn']         = 'chemical/x-mdl-rxnfile',
    ['sd']          = 'chemical/x-mdl-sdfile',
    ['sdf']         = 'chemical/x-mdl-sdfile',
    ['tgf']         = 'chemical/x-mdl-tgf',
    ['mcif']        = 'chemical/x-mmcif',
    ['mol2']        = 'chemical/x-mol2',
    ['b']           = 'chemical/x-molconn-Z',
    ['gpt']         = 'chemical/x-mopac-graph',
    ['mop']         = 'chemical/x-mopac-input',
    ['mopcrt']      = 'chemical/x-mopac-input',
    ['mpc']         = 'chemical/x-mopac-input',
    ['zmt']         = 'chemical/x-mopac-input',
    ['moo']         = 'chemical/x-mopac-out',
    ['mvb']         = 'chemical/x-mopac-vib',
    ['asn']         = 'chemical/x-ncbi-asn1',
    ['prt']         = 'chemical/x-ncbi-asn1-ascii',
    ['ent']         = 'chemical/x-ncbi-asn1-ascii',
    ['val']         = 'chemical/x-ncbi-asn1-binary',
    ['aso']         = 'chemical/x-ncbi-asn1-binary',
    ['asn']         = 'chemical/x-ncbi-asn1-spec',
    ['pdb']         = 'chemical/x-pdb',
    ['ent']         = 'chemical/x-pdb',
    ['ros']         = 'chemical/x-rosdal',
    ['sw']          = 'chemical/x-swissprot',
    ['vms']         = 'chemical/x-vamas-iso14976',
    ['vmd']         = 'chemical/x-vmd',
    ['xtel']        = 'chemical/x-xtel',
    ['xyz']         = 'chemical/x-xyz',
    ['gif']         = 'image/gif',
    ['ief']         = 'image/ief',
    ['jp2']         = 'image/jp2',
    ['jpg2']        = 'image/jp2',
    ['jpeg']        = 'image/jpeg',
    ['jpg']         = 'image/jpeg',
    ['jpe']         = 'image/jpeg',
    ['jpm']         = 'image/jpm',
    ['jpx']         = 'image/jpx',
    ['jpf']         = 'image/jpx',
    ['pcx']         = 'image/pcx',
    ['png']         = 'image/png',
    ['svg']         = 'image/svg+xml',
    ['svgz']        = 'image/svg+xml',
    ['tiff']        = 'image/tiff',
    ['tif']         = 'image/tiff',
    ['djvu']        = 'image/vnd.djvu',
    ['djv']         = 'image/vnd.djvu',
    ['ico']         = 'image/vnd.microsoft.icon',
    ['wbmp']        = 'image/vnd.wap.wbmp',
    ['cr2']         = 'image/x-canon-cr2',
    ['crw']         = 'image/x-canon-crw',
    ['ras']         = 'image/x-cmu-raster',
    ['cdr']         = 'image/x-coreldraw',
    ['pat']         = 'image/x-coreldrawpattern',
    ['cdt']         = 'image/x-coreldrawtemplate',
    ['cpt']         = 'image/x-corelphotopaint',
    ['erf']         = 'image/x-epson-erf',
    ['art']         = 'image/x-jg',
    ['jng']         = 'image/x-jng',
    ['bmp']         = 'image/x-ms-bmp',
    ['nef']         = 'image/x-nikon-nef',
    ['orf']         = 'image/x-olympus-orf',
    ['psd']         = 'image/x-photoshop',
    ['pnm']         = 'image/x-portable-anymap',
    ['pbm']         = 'image/x-portable-bitmap',
    ['pgm']         = 'image/x-portable-graymap',
    ['ppm']         = 'image/x-portable-pixmap',
    ['rgb']         = 'image/x-rgb',
    ['xbm']         = 'image/x-xbitmap',
    ['xpm']         = 'image/x-xpixmap',
    ['xwd']         = 'image/x-xwindowdump',
    ['eml']         = 'message/rfc822',
    ['igs']         = 'model/iges',
    ['iges']        = 'model/iges',
    ['msh']         = 'model/mesh',
    ['mesh']        = 'model/mesh',
    ['silo']        = 'model/mesh',
    ['wrl']         = 'model/vrml',
    ['vrml']        = 'model/vrml',
    ['x3dv']        = 'model/x3d+vrml',
    ['x3d']         = 'model/x3d+xml',
    ['x3db']        = 'model/x3d+binary',
    ['appcache']    = 'text/cache-manifest',
    ['ics']         = 'text/calendar',
    ['icz']         = 'text/calendar',
    ['css']         = 'text/css',
    ['csv']         = 'text/csv',
    ['323']         = 'text/h323',
    ['html']        = 'text/html',
    ['htm']         = 'text/html',
    ['shtml']       = 'text/html',
    ['uls']         = 'text/iuls',
    ['mml']         = 'text/mathml',
    ['asc']         = 'text/plain',
    ['txt']         = 'text/plain',
    ['text']        = 'text/plain',
    ['pot']         = 'text/plain',
    ['brf']         = 'text/plain',
    ['srt']         = 'text/plain',
    ['rtx']         = 'text/richtext',
    ['sct']         = 'text/scriptlet',
    ['wsc']         = 'text/scriptlet',
    ['tm']          = 'text/texmacs',
    ['tsv']         = 'text/tab-separated-values',
    ['ttl']         = 'text/turtle',
    ['jad']         = 'text/vnd.sun.j2me.app-descriptor',
    ['wml']         = 'text/vnd.wap.wml',
    ['wmls']        = 'text/vnd.wap.wmlscript',
    ['bib']         = 'text/x-bibtex',
    ['boo']         = 'text/x-boo',
    ['h++']         = 'text/x-c++hdr',
    ['hpp']         = 'text/x-c++hdr',
    ['hxx']         = 'text/x-c++hdr',
    ['hh']          = 'text/x-c++hdr',
    ['c++']         = 'text/x-c++src',
    ['cpp']         = 'text/x-c++src',
    ['cxx']         = 'text/x-c++src',
    ['cc']          = 'text/x-c++src',
    ['h']           = 'text/x-chdr',
    ['htc']         = 'text/x-component',
    ['csh']         = 'text/x-csh',
    ['c']           = 'text/x-csrc',
    ['d']           = 'text/x-dsrc',
    ['diff']        = 'text/x-diff',
    ['patch']       = 'text/x-diff',
    ['hs']          = 'text/x-haskell',
    ['java']        = 'text/x-java',
    ['ly']          = 'text/x-lilypond',
    ['lhs']         = 'text/x-literate-haskell',
    ['moc']         = 'text/x-moc',
    ['p']           = 'text/x-pascal',
    ['pas']         = 'text/x-pascal',
    ['gcd']         = 'text/x-pcs-gcd',
    ['pl']          = 'text/x-perl',
    ['pm']          = 'text/x-perl',
    ['py']          = 'text/x-python',
    ['scala']       = 'text/x-scala',
    ['etx']         = 'text/x-setext',
    ['sfv']         = 'text/x-sfv',
    ['sh']          = 'text/x-sh',
    ['tcl']         = 'text/x-tcl',
    ['tk']          = 'text/x-tcl',
    ['tex']         = 'text/x-tex',
    ['ltx']         = 'text/x-tex',
    ['sty']         = 'text/x-tex',
    ['cls']         = 'text/x-tex',
    ['vcs']         = 'text/x-vcalendar',
    ['vcf']         = 'text/x-vcard',
    ['3gp']         = 'video/3gpp',
    ['axv']         = 'video/annodex',
    ['dl']          = 'video/dl',
    ['dif']         = 'video/dv',
    ['dv']          = 'video/dv',
    ['fli']         = 'video/fli',
    ['gl']          = 'video/gl',
    ['mpeg']        = 'video/mpeg',
    ['mpg']         = 'video/mpeg',
    ['mpe']         = 'video/mpeg',
    ['ts']          = 'video/MP2T',
    ['mp4']         = 'video/mp4',
    ['qt']          = 'video/quicktime',
    ['mov']         = 'video/quicktime',
    ['ogv']         = 'video/ogg',
    ['webm']        = 'video/webm',
    ['mxu']         = 'video/vnd.mpegurl',
    ['flv']         = 'video/x-flv',
    ['lsf']         = 'video/x-la-asf',
    ['lsx']         = 'video/x-la-asf',
    ['mng']         = 'video/x-mng',
    ['asf']         = 'video/x-ms-asf',
    ['asx']         = 'video/x-ms-asf',
    ['wm']          = 'video/x-ms-wm',
    ['wmv']         = 'video/x-ms-wmv',
    ['wmx']         = 'video/x-ms-wmx',
    ['wvx']         = 'video/x-ms-wvx',
    ['avi']         = 'video/x-msvideo',
    ['movie']       = 'video/x-sgi-movie',
    ['mpv']         = 'video/x-matroska',
    ['mkv']         = 'video/x-matroska',
    ['ice']         = 'x-conference/x-cooltalk',
    ['sisx']        = 'x-epoc/x-sisx-app',
    ['vrm']         = 'x-world/x-vrml',
    ['vrml']        = 'x-world/x-vrml',
    ['wrl']         = 'x-world/x-vrml',
}

end)(box, io, package, require)

