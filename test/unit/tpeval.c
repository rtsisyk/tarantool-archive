#include <stdio.h>
#include <stdarg.h>
#include <rlist.h>
#include <stdlib.h>
#include <string.h>
#include "test.h"
#include "../../src/plugin/httpd/tpleval.h"

#define PLAN		110


struct token {
	struct rlist list;
	const char *s;
	size_t len;
	int type;
};

RLIST_HEAD(list);

static void
cb(int type, const char *s, size_t len, void *data)
{
/*         printf("* token: '%.*s'\n", (int)len, s); */
	struct token *token = malloc(sizeof(*token));
	token->s = s;
	token->len = len;
	token->type = type;
	rlist_add_tail_entry(&list, token, list);

	(void)data;
}

static size_t
list_size(void)
{
	size_t cnt = 0;
	struct token *token;
	rlist_foreach_entry(token, &list, list) {
		cnt++;
	}
	return cnt;
}






int
main(void)
{
	struct token *token;
	plan(PLAN);

	{
		rlist_create(&list);
		const char *tpl = "";
		tpe_parse(tpl, strlen(tpl), cb, NULL);
		ok(rlist_empty(&list), "Parser didn't return results");
	}

	{
		rlist_create(&list);
		const char *tpl = "\n";
		tpe_parse(tpl, strlen(tpl), cb, NULL);
		ok(!rlist_empty(&list), "Parser returned results");
		token = rlist_first_entry(&list, struct token, list);
		is(strncmp(token->s, "\n", token->len), 0, "first token");
		is(token->type, TPE_TEXT, "token.type");
		is(token->len, 1, "token->len");
	}

	{
		rlist_create(&list);
		const char *tpl = "test\n";
		tpe_parse(tpl, strlen(tpl), cb, NULL);
		ok(!rlist_empty(&list), "Parser returned results");
		token = rlist_first_entry(&list, struct token, list);
		is(token->len, strlen("test\n"), "token length");
		is(strncmp(token->s, "test\n", token->len), 0, "first token");
		is(token->type, TPE_TEXT, "token.type");
		is(token->len, 5, "token->len");
	}

	{
		rlist_create(&list);
		const char *tpl = "test1\ntest2";
		tpe_parse(tpl, strlen(tpl), cb, NULL);
		is(list_size(), 2, "2 tokens found");
		ok(!rlist_empty(&list), "Parser returned results");
		token = rlist_first_entry(&list, struct token, list);
		is(strncmp(token->s, "test1\n", token->len), 0, "first token");
		is(token->type, TPE_TEXT, "token.type");
		is(token->len, 6, "token->len");

		token = rlist_last_entry(&list, struct token, list);
		is(strncmp(token->s, "test2", token->len), 0, "last token");
		is(token->type, TPE_TEXT, "token.type");
		is(token->len, 5, "token->len");
	}

	{
		rlist_create(&list);
		const char *tpl = "%";
		tpe_parse(tpl, strlen(tpl), cb, NULL);
		is(list_size(), 0, "0 token found");
	}
	{
		rlist_create(&list);
		const char *tpl = "% ";
		tpe_parse(tpl, strlen(tpl), cb, NULL);
		is(list_size(), 1, "1 token found");
		token = rlist_first_entry(&list, struct token, list);
		is(strncmp(token->s, " ", token->len), 0, "token.str");
		is(token->type, TPE_LINECODE, "token.type");
		is(token->len, 1, "token->len");
	}
	{

		rlist_create(&list);
		const char *tpl = "abccd %";
		tpe_parse(tpl, strlen(tpl), cb, NULL);
		is(list_size(), 1, "1 token found");
		token = rlist_first_entry(&list, struct token, list);
		is(strncmp(token->s, "abccd %", token->len), 0, "token.str");
		is(token->type, TPE_TEXT, "token.type");
		is(token->len, 7, "token->len");
	}
	{

		rlist_create(&list);
		const char *tpl = "abccd\n%";
		tpe_parse(tpl, strlen(tpl), cb, NULL);
		is(list_size(), 1, "1 token found");
		token = rlist_first_entry(&list, struct token, list);
		is(strncmp(token->s, "abccd\n", token->len), 0, "token.str");
		is(token->type, TPE_TEXT, "token.type");
		is(token->len, 6, "token->len");
	}
	{

		rlist_create(&list);
		const char *tpl = "abccd\n%123";
		tpe_parse(tpl, strlen(tpl), cb, NULL);
		is(list_size(), 2, "1 token found");
		token = rlist_first_entry(&list, struct token, list);
		is(strncmp(token->s, "abccd\n", token->len), 0, "token.str");
		is(token->type, TPE_TEXT, "token.type");
		is(token->len, 6, "token->len");
		token = rlist_last_entry(&list, struct token, list);
		is(strncmp(token->s, "123", token->len), 0, "token.str");
		is(token->type, TPE_LINECODE, "token.type");
		is(token->len, 3, "token->len");
	}
	{
		rlist_create(&list);
		const char *tpl = "abccd\n%123\n";
		tpe_parse(tpl, strlen(tpl), cb, NULL);
		is(list_size(), 3, "1 token found");
		token = rlist_first_entry(&list, struct token, list);
		is(strncmp(token->s, "abccd\n", token->len), 0, "token.str");
		is(token->type, TPE_TEXT, "token.type");
		is(token->len, 6, "token->len");

		token = rlist_first_entry(list.next, struct token, list);
		is(strncmp(token->s, "123", token->len), 0, "token.str");
		is(token->type, TPE_LINECODE, "token.type");
		is(token->len, 3, "token->len");

		token = rlist_last_entry(&list, struct token, list);
		is(strncmp(token->s, "\n", token->len), 0, "token.str");
		is(token->type, TPE_TEXT, "token.type");
		is(token->len, 1, "token->len");
	}
	{
		rlist_create(&list);
		const char *tpl = "abccd\n%123\ncde";
		tpe_parse(tpl, strlen(tpl), cb, NULL);
		is(list_size(), 3, "1 token found");
		token = rlist_first_entry(&list, struct token, list);
		is(strncmp(token->s, "abccd\n", token->len), 0, "token.str");
		is(token->type, TPE_TEXT, "token.type");
		is(token->len, 6, "token->len");

		token = rlist_first_entry(list.next, struct token, list);
		is(strncmp(token->s, "123", token->len), 0, "token.str");
		is(token->type, TPE_LINECODE, "token.type");
		is(token->len, 3, "token->len");

		token = rlist_last_entry(&list, struct token, list);
		is(strncmp(token->s, "\ncde", token->len), 0, "token.str");
		is(token->type, TPE_TEXT, "token.type");
		is(token->len, 4, "token->len");
	}
	{
		rlist_create(&list);
		const char *tpl = "abccd\n%123\n\t  %343\n";
		tpe_parse(tpl, strlen(tpl), cb, NULL);
		is(list_size(), 5, "1 token found");
		token = rlist_first_entry(&list, struct token, list);
		is(strncmp(token->s, "abccd\n", token->len), 0, "token.str");
		is(token->type, TPE_TEXT, "token.type");
		is(token->len, 6, "token->len");

		token = rlist_first_entry(list.next, struct token, list);
		is(strncmp(token->s, "123", token->len), 0, "token.str");
		is(token->type, TPE_LINECODE, "token.type");
		is(token->len, 3, "token->len");

		token = rlist_last_entry(&list, struct token, list);
		is(strncmp(token->s, "\n", token->len), 0, "token.str");
		is(token->type, TPE_TEXT, "token.type");
		is(token->len, 1, "token->len");

		token = rlist_first_entry(list.next->next, struct token, list);
		is(strncmp(token->s, "\n\t  ", token->len), 0, "token.str");
		is(token->type, TPE_TEXT, "token.type");
		is(token->len, 4, "token->len");
	}
	{

		rlist_create(&list);
		const char *tpl = "<%%>";
		tpe_parse(tpl, strlen(tpl), cb, NULL);
		is(list_size(), 0, "0 tokens found");
	}
	{
		rlist_create(&list);
		const char *tpl = "<%= 123 %>";
		tpe_parse(tpl, strlen(tpl), cb, NULL);
		is(list_size(), 1, "1 token found");
		token = rlist_first_entry(&list, struct token, list);
		is(strncmp(token->s, "= 123 ", token->len), 0, "token.str");
		is(token->type, TPE_MULTILINE_CODE, "token.type");
		is(token->len, 6, "token->len");
	}
	{
		rlist_create(&list);
		const char *tpl = "abc%<%= 123 %>%cde";
		tpe_parse(tpl, strlen(tpl), cb, NULL);
		is(list_size(), 3, "3 tokens found");
		token = rlist_first_entry(&list, struct token, list);
		is(strncmp(token->s, "abc%", token->len), 0, "token.str");
		is(token->type, TPE_TEXT, "token.type");
		is(token->len, 4, "token->len");

		token = rlist_first_entry(list.next, struct token, list);
		is(strncmp(token->s, "= 123 ", token->len), 0, "token.str");
		is(token->type, TPE_MULTILINE_CODE, "token.type");
		is(token->len, 6, "token->len");

		token = rlist_first_entry(list.next->next, struct token, list);
		is(strncmp(token->s, "%cde", token->len), 0, "token.str");
		is(token->type, TPE_TEXT, "token.type");
		is(token->len, 4, "token->len");
	}
	{
		rlist_create(&list);
		const char *tpl = "abc%<%= 123 % 12 \n\n%>%cde";
		tpe_parse(tpl, strlen(tpl), cb, NULL);
		is(list_size(), 3, "3 tokens found");
		token = rlist_first_entry(&list, struct token, list);
		is(strncmp(token->s, "abc%", token->len), 0, "token.str");
		is(token->type, TPE_TEXT, "token.type");
		is(token->len, 4, "token->len");

		token = rlist_first_entry(list.next, struct token, list);
		is(strncmp(token->s, "= 123 % 12 \n\n", token->len), 0,
			"token.str");
		is(token->type, TPE_MULTILINE_CODE, "token.type");
		is(token->len, 13, "token->len");

		token = rlist_first_entry(list.next->next, struct token, list);
		is(strncmp(token->s, "%cde", token->len), 0, "token.str");
		is(token->type, TPE_TEXT, "token.type");
		is(token->len, 4, "token->len");
	}
	{
		rlist_create(&list);
		const char *tpl = "abc%<%= 123 % 12\n";
		tpe_parse(tpl, strlen(tpl), cb, NULL);
		is(list_size(), 2, "2 tokens found");
		token = rlist_first_entry(&list, struct token, list);
		is(strncmp(token->s, "abc%", token->len), 0, "token.str");
		is(token->type, TPE_TEXT, "token.type");
		is(token->len, 4, "token->len");

		token = rlist_first_entry(list.next, struct token, list);
		is(strncmp(token->s, "<%= 123 % 12\n", token->len), 0,
			"token.str");
		is(token->type, TPE_TEXT, "token.type");
		is(token->len, 13, "token->len");
	}
	{
		rlist_create(&list);
		const char *tpl = "abc%<%= 123 % 12 %";
		tpe_parse(tpl, strlen(tpl), cb, NULL);
		is(list_size(), 2, "2 tokens found");
		token = rlist_first_entry(&list, struct token, list);
		is(strncmp(token->s, "abc%", token->len), 0, "token.str");
		is(token->type, TPE_TEXT, "token.type");
		is(token->len, 4, "token->len");

		token = rlist_first_entry(list.next, struct token, list);
		is(strncmp(token->s, "<%= 123 % 12 %", token->len), 0,
			"token.str");
		is(token->type, TPE_TEXT, "token.type");
		is(token->len, 14, "token->len");
	}

	return check_plan();
}

