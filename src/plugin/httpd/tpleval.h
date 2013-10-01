#ifndef TPL_EVAL_H_INCLUDED
#define TPL_EVAL_H_INCLUDED

#include <stdlib.h>
#include <stdio.h>

enum {
    TPE_TEXT,
    TPE_LINECODE,
    TPE_MULTILINE_CODE
};

static inline void
tpe_parse(const char *p, size_t len,
    void(*term)(int type, const char *str, size_t len, void *data),
    void *data)
{
    int bl = 1;
    size_t i, be;
    int type = TPE_TEXT;

    for (be = i = 0; i < len; i++) {
        if (type == TPE_TEXT) {
            switch(p[i]) {
                case ' ':
                case '\t':
                    break;
                case '%':
                    if (bl) {
                        if (be < i)
                            term(type, p + be, i - be, data);

                        be = i + 1;
                        bl = 0;

                        type = TPE_LINECODE;
                        break;
                    }

                    if (i == 0 || p[i - 1] != '<')
                        break;

                    if (be < i - 1)
                        term(type, p + be, i - be - 1, data);
                    be = i + 1;
                    bl = 0;

                    type = TPE_MULTILINE_CODE;
                    break;

                case '\n':
                    if (be <= i)
                        term(type, p + be, i - be + 1, data);
                    be = i + 1;
                    bl = 1;
                    break;
                default:
                    bl = 0;
                    break;
            }
            continue;
        }

        if (type == TPE_LINECODE) {
            switch(p[i]) {
                case '\n':
                    if (be < i)
                        term(type, p + be, i - be, data);
                    be = i;
                    type = TPE_TEXT;
                    bl = 1;
                    break;
                default:
                    break;
            }
            continue;
        }

        if (type == TPE_MULTILINE_CODE) {
            switch(p[i]) {
                case '%':
                    if (i == len - 1 || p[i + 1] != '>')
                        continue;
                    if (be < i)
                        term(type, p + be, i - be, data);
                    be = i + 2;
                    i++;
                    bl = 0;
                    type = TPE_TEXT;
                    break;
                default:
                    break;
            }
            continue;
        }

        abort();
    }

    if (len == 0 || be >= len)
        return;

    switch(type) {
        /* unclosed multiline tag as text */
        case TPE_MULTILINE_CODE:
            if (be >= 2)
                be -= 2;
            type = TPE_TEXT;

        case TPE_LINECODE:
        case TPE_TEXT:
            term(type, p + be, len - be, data);
            break;
        default:
            break;
    }
}


#endif /* TPL_EVAL_H_INCLUDED */
