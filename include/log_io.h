#ifndef TARANTOOL_LOG_IO_H_INCLUDED
#define TARANTOOL_LOG_IO_H_INCLUDED
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
#include <stdio.h>
#include <limits.h>
#include <stdbool.h>
#include "tarantool/util.h"
#include "tarantool_ev.h"
#include "recovery.h" /* struct lsn, mh_uuidnode_t */

extern const uint32_t xlog_format;

enum log_mode {
	LOG_READ,
	LOG_WRITE
};

struct log_dir {
	bool panic_if_error;
	/**
	 * true if the file can by fsync()ed at close
	 * in a separate thread.
	 */
	bool sync_is_async;

	/* Additional flags to apply at open(2) to write. */
	int  open_wflags;
	const char *filetype;
	const char *filename_ext;
	char *dirname;
	/** File create mode in this directory. */
	mode_t mode;
};

extern struct log_dir snap_dir;
extern struct log_dir wal_dir;

struct log_io *
log_dir_find_xlog(struct log_dir *dir, struct mh_uuidnode_t *nodes,
		  int64_t prev_sum);

struct log_io *
log_dir_find_snap(struct log_dir *dir);

struct log_io {
	struct log_dir *dir;
	FILE *f;

	enum log_mode mode;
	size_t rows;
	int retry;
	char filename[PATH_MAX + 1];

	/* header/footer has been written (just for debugging) */
	bool header;
	bool footer;

	/* used by log_io_scan */
	struct log_io *file;
	int64_t lsns_sum;
	uint32_t lsns_count;
	const struct lsn *lsns;
};

struct log_io *
log_io_open_for_read(struct log_dir *dir, const char *filename);

struct log_io *
log_io_open_for_write(struct log_dir *dir, mh_uuidnode_t *nodes);

int
log_io_sync(struct log_io *l);

const struct lsn *
log_io_read_header(struct log_io *l, uint32_t *p_count);

const struct lsn *
log_io_read_footer(struct log_io *l, uint32_t *p_count);

int
log_io_write_header(struct log_io *l, mh_uuidnode_t *nodes,
		    const struct node *local_node, bool write_current);

int
log_io_write_footer(struct log_io *l, mh_uuidnode_t *lsns,
		    const struct node *local_node, bool write_current);

int
inprogress_log_rename(struct log_io *l);

int
log_io_close(struct log_io **lptr);
void
log_io_atfork(struct log_io **lptr);

struct log_io_cursor
{
	struct log_io *log;
	int row_count;
	off_t good_offset;
	bool eof_read;
};

void
log_io_cursor_open(struct log_io_cursor *i, struct log_io *l);
void
log_io_cursor_close(struct log_io_cursor *i);

const struct log_row *
log_io_cursor_next(struct log_io_cursor *i);

typedef uint32_t log_magic_t;

struct log_row {
	log_magic_t marker;
	uint32_t header_crc32c; /* calculated for the header block */
	/* {{{ header block */
	char header[0]; /* start of the header */
	struct lsn lsn;
	double tm;
	uint32_t len;
	uint16_t tag;
	uint64_t cookie;
	uint32_t data_crc32c; /* calculated for data */
	/* }}} */
	char data[0];   /* start of the data */
} __attribute__((packed));

void
log_row_sign(struct log_row *row);

void
log_row_fill(struct log_row *row, const struct lsn *lsn, uint64_t cookie,
	     const char *metadata, size_t metadata_len,
	     const char *data, size_t data_len);

static inline size_t
log_row_size(const struct log_row *row)
{
	return sizeof(struct log_row) + row->len;
}

/** @todo remove path_join */
const char *
path_join(const char *dir, const char *name);

#endif /* TARANTOOL_LOG_IO_H_INCLUDED */
