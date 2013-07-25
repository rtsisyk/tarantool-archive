-- box_request.lua (internal file)

(function(box)
    local ffi = require('ffi')
    ffi.cdef([[
    /* from request.h */
    struct request
    {
        uint32_t type;
        uint32_t flags;
        union {
            struct {
                uint32_t space_no;
                uint32_t index_no;
                uint32_t offset;
                uint32_t limit;
                uint32_t key_count;
                const char *keys;
                const char *keys_end;
            } s; /* select */

            struct {
                uint32_t space_no;
                const char *tuple;
                const char *tuple_end;
            } r; /* replace */

            struct {
                uint32_t space_no;
                uint32_t key_part_count;
                const char *key;
                const char *key_end;
                const char *expr;
                const char *expr_end;
            } u; /* update */

            struct {
                uint32_t space_no;
                uint32_t key_part_count;
                const char *key;
                const char *key_end;
            } d; /* delete */

            struct {
                const char *procname;
                uint32_t procname_len;
                uint32_t arg_count;
                const char *args;
                const char *args_end;
            } c; /* call */
        };

        const char *data;
        uint32_t len;

        void (*execute)(const struct request *, struct txn *, struct port *);
    };
    ]])
end)(box);

-- vim: set et ts=4 sts
