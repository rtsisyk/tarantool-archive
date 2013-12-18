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
#include "log_io.h"
#include "recovery.h"
#include <dirent.h>
#include <fcntl.h>
#include <tbuf.h>

#include "fiber.h"
#include "crc32.h"
#include "fio.h"
#include "tarantool_eio.h"

const uint32_t xlog_format = 12;
const log_magic_t row_marker = 0xba0babed;
const log_magic_t header_marker = 0xabcddddd;
const log_magic_t footer_marker = 0x10adab1e;
const log_magic_t eof_marker = 0xabcdefdd;

const char inprogress_suffix[] = ".inprogress";
const char v12[] = "0.12\n";

void
log_row_sign(struct log_row *header)
{
	header->data_crc32c = crc32_calc(0, header->data, header->len);
	header->header_crc32c = crc32_calc(0, header->header, sizeof(*header) -
					   offsetof(struct log_row, header));
}

void
log_row_fill(struct log_row *row, const struct lsn *lsn, uint64_t cookie,
		const char *metadata, size_t metadata_len,
		const char *data, size_t data_len)
{
	row->marker = row_marker;
	row->cookie = cookie;
	row->lsn = *lsn;

	memcpy(row->data, metadata, metadata_len);
	memcpy(row->data + metadata_len, data, data_len);

	row->tm = ev_now();
	row->len = metadata_len + data_len;
}

struct log_dir snap_dir = {
	/* .panic_if_error = */ false,
	/* .sync_is_async = */ false,
	/* .open_wflags = */ 0,
	/* .filetype = */ "SNAP\n",
	/* .filename_ext = */ ".snap",
	/* .dirname = */ NULL,
	/* .mode = */ 0660
};

struct log_dir wal_dir = {
	/* .panic_if_error = */ false,
	/* .sync_is_async = */ true,
	/* .open_wflags = */ 0,
	/* .filetype = */ "XLOG\n",
	/* .filename_ext = */ ".xlog",
	/* .dirname = */ NULL,
	/* .mode = */ 0660
};

const char *
path_join(const char *dir, const char *name)
{
	static __thread char filename[PATH_MAX + 1];
	snprintf(filename, PATH_MAX, "%s/%s", dir, name);
	return filename;
}

static int
log_io_lsns_sum_cmp(const void *_a, const void *_b)
{
	const struct log_io *a = *(const struct log_io **) _a;
	const struct log_io *b = *(const struct log_io **) _b;

	if (a->lsns_sum == b->lsns_sum)
		return 0;
	return (a->lsns_sum > b->lsns_sum) ? 1 : -1;
}

static struct log_io **
log_dir_scan(struct log_dir *dir, uint32_t *p_files_count)
{
	DIR *dh = opendir(dir->dirname);
	if (dh == NULL) {
		say_syserror("cannot open directory %s", dir->dirname);
		return NULL;
	}

	struct tbuf *files = tbuf_new(&fiber->gc);
	uint32_t files_count = 0;

	errno = 0;
	struct dirent *dent;
	while ((dent = readdir(dh)) != NULL) {
		char *ext = strchr(dent->d_name, '.');
		if (ext == NULL || strcmp(ext, dir->filename_ext) != 0)
			continue;

		log_io *wal = log_io_open_for_read(dir, dent->d_name);
		if (wal == NULL) {
			say_warn("%s/%s: ignoring invalid file",
				 dir->dirname, dent->d_name);
			continue;
		}

		wal->lsns = log_io_read_header(wal, &wal->lsns_count);
		if (wal->lsns == NULL) {
			say_warn("%s/%s: ignoring invalid file",
				dir->dirname, dent->d_name);
			log_io_close(&wal);
			continue;
		}

		wal->lsns_sum = 0;
		for (uint32_t i = 0; i < wal->lsns_count; i++) {
			wal->lsns_sum += wal->lsns[i].seq;
		}

		tbuf_append(files, &wal, sizeof(wal));
		++files_count;
	}

	closedir(dh);


	qsort(files->data, files_count, sizeof(log_io *), log_io_lsns_sum_cmp);

	/** @todo: check lsn ordering here */
	say_debug("found %u %s file(s)", files_count, dir->filename_ext);

	*p_files_count = files_count;
	return (struct log_io **) files->data;
}

static inline struct log_io *
log_dir_find_first_xlog(struct log_io **files, uint32_t files_count,
			struct mh_uuidnode_t *nodes)
{
	assert(files_count >= 1);
	uint32_t i = 0;
	for (i = 1; i < files_count; i++) {
		for (uint32_t l = 0; l < files[i]->lsns_count; l++) {
			uint32_t a = mh_uuidnode_find(nodes,
				files[i]->lsns[l].uuid, NULL);
			int64_t seq_a = (a != mh_end(nodes))
				?  mh_uuidnode(nodes, a)->confirmed_lsn : 0;

			if (seq_a < files[i]->lsns[l].seq)
				goto out;
		}
	}

out:
	for (uint32_t j = 0; j < files_count; j++) {
		if (files[j] != files[i - 1])
			log_io_close(&files[j]);
	}
	return files[i - 1];
}

static inline struct log_io *
log_dir_find_next_xlog(struct log_io **files, uint32_t files_count,
		       int64_t prev_sum)
{
	assert(files_count >= 1);
	struct log_io *ret = NULL;
	for (uint32_t i = 0; i < files_count; i++) {
		if (files[i]->lsns_sum >= prev_sum) {
			ret = files[i];
			break;
		}
	}

	for (uint32_t i = 0; i < files_count; i++) {
		if (files[i] != ret)
			log_io_close(&files[i]);
	}

	return ret;
}

struct log_io *
log_dir_find_xlog(struct log_dir *dir, struct mh_uuidnode_t *nodes,
		  int64_t prev_sum)
{
	uint32_t files_count;
	struct log_io **files = log_dir_scan(dir, &files_count);
	if (files == NULL || files_count == 0)
		return NULL;

	if (prev_sum <= 0)
		return log_dir_find_first_xlog(files, files_count, nodes);

	return log_dir_find_next_xlog(files, files_count, prev_sum);
}

struct log_io *
log_dir_find_snap(struct log_dir *dir)
{

	uint32_t files_count;
	struct log_io **files = log_dir_scan(dir, &files_count);
	if (files == NULL || files_count == 0)
		return NULL;

	for (uint32_t i = 0; i < files_count - 1; i++)
		log_io_close(&files[i]);

	return files[files_count - 1];
}

/* }}} */

/* {{{ struct log_io_cursor */

static struct log_row ROW_EOF;

static const struct log_row *
row_reader(FILE *f)
{
	struct log_row m;

	uint32_t header_crc, data_crc;

	if (fread(&m.header_crc32c, sizeof(m) - sizeof(log_magic_t), 1, f) != 1)
		return &ROW_EOF;

	header_crc = crc32_calc(0, m.header, sizeof(struct log_row) -
				offsetof(struct log_row, header));

	if (m.header_crc32c != header_crc) {
		say_error("header crc32c mismatch");
		return NULL;
	}
	char *row = (char *) region_alloc(&fiber->gc, sizeof(m) + m.len);
	memcpy(row, &m, sizeof(m));

	if (fread(row + sizeof(m), m.len, 1, f) != 1)
		return &ROW_EOF;

	data_crc = crc32_calc(0, row + sizeof(m), m.len);
	if (m.data_crc32c != data_crc) {
		say_error("data crc32c mismatch");
		return NULL;
	}

	say_debug("read row v11 success lsn:%lld", (long long) m.lsn.seq);
	return (const struct log_row *) row;
}

void
log_io_cursor_open(struct log_io_cursor *i, struct log_io *l)
{
	i->log = l;
	i->row_count = 0;
	i->good_offset = ftello(l->f);
	i->eof_read  = false;
}

void
log_io_cursor_close(struct log_io_cursor *i)
{
	struct log_io *l = i->log;
	l->rows += i->row_count;
	/*
	 * Since we don't close log_io
	 * we must rewind log_io to last known
	 * good position if there was an error.
	 * Seek back to last known good offset.
	 */
	fseeko(l->f, i->good_offset, SEEK_SET);
	region_free(&fiber->gc);
}

/**
 * Read logfile contents using designated format, panic if
 * the log is corrupted/unreadable.
 *
 * @param i	iterator object, encapsulating log specifics.
 *
 */
const struct log_row *
log_io_cursor_next(struct log_io_cursor *i)
{
	struct log_io *l = i->log;
	const struct log_row *row;
	log_magic_t magic;
	off_t marker_offset = 0;

	assert(i->eof_read == false);

	say_debug("log_io_cursor_next: marker:0x%016X/%zu",
		  row_marker, sizeof(row_marker));

	/*
	 * Don't let gc pool grow too much. Yet to
	 * it before reading the next row, to make
	 * sure it's not freed along here.
	 */
	region_free_after(&fiber->gc, 128 * 1024);

restart:
	if (marker_offset > 0)
		fseeko(l->f, marker_offset + 1, SEEK_SET);

	if (fread(&magic, sizeof(magic), 1, l->f) != 1 || magic == footer_marker)
		goto eof;

	while (magic != row_marker) {
		int c = fgetc(l->f);
		if (c == EOF) {
			say_debug("eof while looking for magic");
			goto eof;
		}
		magic = magic >> 8 |
			((log_magic_t) c & 0xff) << (sizeof(magic)*8 - 8);
	}
	marker_offset = ftello(l->f) - sizeof(row_marker);
	if (i->good_offset != marker_offset)
		say_warn("skipped %jd bytes after 0x%08jx offset",
			(intmax_t)(marker_offset - i->good_offset),
			(uintmax_t)i->good_offset);
	say_debug("magic found at 0x%08jx", (uintmax_t)marker_offset);

	row = row_reader(l->f);
	if (row == &ROW_EOF)
		goto eof;

	if (row == NULL) {
		if (l->dir->panic_if_error)
			panic("failed to read row");
		say_warn("failed to read row");
		goto restart;
	}

	i->good_offset = ftello(l->f);
	i->row_count++;

	if (i->row_count % 100000 == 0)
		say_info("%.1fM rows processed", i->row_count / 1000000.);

	return row;
eof:
	/*
	 * The only two cases of fully read file:
	 * 1. sizeof(eof_marker) > 0 and it is the last record in file
	 * 2. sizeof(eof_marker) == 0 and there is no unread data in file
	 */
	if (ftello(l->f) == i->good_offset + sizeof(footer_marker)) {
		fseeko(l->f, i->good_offset, SEEK_SET);
		if (fread(&magic, sizeof(magic), 1, l->f) != 1) {
			say_error("can't read eof marker");
		} else if (magic == footer_marker || magic == eof_marker) {
			i->good_offset = ftello(l->f);
			i->eof_read = true;
		} else if (magic != row_marker) {
			say_error("eof marker is corrupt: %lu",
				  (unsigned long) magic);
		} else {
			/*
			 * Row marker at the end of a file: a sign
			 * of a corrupt log file in case of
			 * recovery, but OK in case we're in local
			 * hot standby or replication relay mode
			 * (i.e. data is being written to the
			 * file. Don't pollute the log, the
			 * condition is taken care of up the
			 * stack.
			 */
		}
	}
	/* No more rows. */
	return NULL;
}

/* }}} */

int
inprogress_log_rename(struct log_io *l)
{
	char *filename = l->filename;
	char new_filename[PATH_MAX];
	char *suffix = strrchr(filename, '.');

	assert(l->mode == LOG_WRITE);
	assert(suffix);
	assert(strcmp(suffix, inprogress_suffix) == 0);

	/* Create a new filename without '.inprogress' suffix. */
	memcpy(new_filename, filename, suffix - filename);
	new_filename[suffix - filename] = '\0';

	if (rename(filename, new_filename) != 0) {
		say_syserror("can't rename %s to %s", filename, new_filename);
		return -1;
	}

	*suffix = 0;

	return 0;
}

/* {{{ struct log_io */

int
log_io_close(struct log_io **lptr)
{
	struct log_io *l = *lptr;
	int r;

	if (l->mode == LOG_WRITE) {
		if (l->rows == 0) {
			/* remove empty file */
			say_info("%s: remove empty file", l->filename);
			if (unlink(l->filename) != 0)
				say_syserror("%s: unlink", l->filename);
			goto out;
		}
		fio_write(fileno(l->f), &eof_marker, sizeof(log_magic_t));
		assert(l->header && l->footer);
		/*
		 * Sync the file before closing, since
		 * otherwise we can end up with a partially
		 * written file in case of a crash.
		 * Do not sync if the file is opened with O_SYNC.
		 */
		if (! (l->dir->open_wflags & WAL_SYNC_FLAG))
			log_io_sync(l);
	}

out:
	r = fclose(l->f);
	if (r < 0)
		say_syserror("can't close");
	free(l);
	*lptr = NULL;
	return r;
}

/** Free log_io memory and destroy it cleanly, without side
 * effects (for use in the atfork handler).
 */
void
log_io_atfork(struct log_io **lptr)
{
	struct log_io *l = *lptr;
	if (l) {
		/*
		 * Close the file descriptor STDIO buffer does not
		 * make its way into the respective file in
		 * fclose().
		 */
		close(fileno(l->f));
		fclose(l->f);
		free(l);
		*lptr = NULL;
	}
}

static int
sync_cb(eio_req *req)
{
	if (req->result)
		say_error("%s: fsync failed, errno: %d",
			  __func__, (int) req->result);

	int fd = (intptr_t) req->data;
	close(fd);
	return 0;
}

int
log_io_sync(struct log_io *l)
{
	if (l->dir->sync_is_async) {
		int fd = dup(fileno(l->f));
		if (fd == -1) {
			say_syserror("%s: dup() failed", __func__);
			return -1;
		}
		eio_fsync(fd, 0, sync_cb, (void *) (intptr_t) fd);
	} else if (fsync(fileno(l->f)) < 0) {
		say_syserror("%s: fsync failed", l->filename);
		return -1;
	}
	return 0;
}

static int
log_io_write_meta(struct log_io *l)
{
	int ret = fprintf(l->f, "%s%s\n", l->dir->filetype, v12);

	return ret < 0 ? -1 : 0;
}

/**
 * Verify that file is of the given format.
 *
 * @param l		log_io object, denoting the file to check.
 * @param[out] errmsg   set if error
 *
 * @return 0 if success, -1 on error.
 */
static int
log_io_verify_meta(struct log_io *l, const char **errmsg)
{
	char filetype[32], version[32], buf[256];
	struct log_dir *dir = l->dir;
	FILE *stream = l->f;

	if (fgets(filetype, sizeof(filetype), stream) == NULL ||
	    fgets(version, sizeof(version), stream) == NULL) {
		*errmsg = "failed to read log file header";
		goto error;
	}
	if (strcmp(dir->filetype, filetype) != 0) {
		*errmsg = "unknown filetype";
		goto error;
	}

	if (strcmp(v12, version) != 0) {
		*errmsg = "unsupported file format version";
		goto error;
	}
	for (;;) {
		if (fgets(buf, sizeof(buf), stream) == NULL) {
			*errmsg = "failed to read log file header";
			goto error;
		}
		if (strcmp(buf, "\n") == 0 || strcmp(buf, "\r\n") == 0)
			break;
	}
	return 0;
error:
	return -1;
}

static const struct lsn *
log_io_read_lsn_table(struct log_io *l, uint32_t *p_count)
{
	const struct log_row *row = row_reader(l->f);
	assert(row != &ROW_EOF);
	if (row == NULL || row->len < sizeof(uint32_t)) {
		say_error("%s: cannot read LSN table", l->filename);
		return NULL;
	}

	assert(p_count != NULL);
	*p_count = *(uint32_t *) row->data;

	if ((sizeof(uint32_t) + *p_count * sizeof(struct lsn)) != row->len) {
		say_error("%s: broken LSN table", l->filename);
		return NULL;
	}

	say_debug("%s/%s: successfully read LSN table",
		  l->dir->dirname, l->filename);

	return (const struct lsn *) (row->data + sizeof(*p_count));
}

const struct lsn *
log_io_read_header(struct log_io *l, uint32_t *p_count)
{
	assert(l->mode == LOG_READ);

	off_t cur_pos = ftello(l->f);
	log_magic_t marker;
	const struct lsn *ret;

	/* Read header */
	if (fread(&marker, sizeof(marker), 1, l->f) != 1 ||
	    marker != header_marker) {
		say_error("%s: cannot find header", l->filename);
		goto error;
	}

	ret = log_io_read_lsn_table(l, p_count);
	if (ret != NULL)
		return ret;

error:
	fseeko(l->f, cur_pos, SEEK_SET);
	return NULL;
}

const struct lsn *
log_io_read_footer(struct log_io *l, uint32_t *p_count)
{
	assert(l->mode == LOG_READ);

	struct {
		uint32_t size;
		log_magic_t marker;
	} __attribute__((packed)) footer;

	off_t cur_pos = ftello(l->f);
	off_t row_pos;
	log_magic_t marker;
	const struct lsn *ret;

	if (fseeko(l->f, -sizeof(footer), SEEK_END) == -1 ||
	    fread(&footer, sizeof(footer), 1, l->f) != 1 ||
	    footer.marker != eof_marker ||
	    (row_pos = ftell(l->f) - sizeof(footer) - footer.size) < 0 ||
	    fseeko(l->f, row_pos, SEEK_SET) == -1 ||
	    fread(&marker, sizeof(marker), 1, l->f) != 1 ||
	    marker != footer_marker) {
		say_error("%s: cannot find footer", l->filename);
		goto error;
	}

	ret = log_io_read_lsn_table(l, p_count);
	if (ret != NULL)
		return ret;
error:
	fseeko(l->f, cur_pos, SEEK_SET);
	return NULL;
}

static uint32_t
log_io_write_lsn_table(struct log_io *l, struct mh_uuidnode_t *nodes,
		       const struct node *local_node, bool write_current,
		       log_magic_t marker)
{
	uint32_t cnt = mh_size(nodes);
	uint32_t row_len = sizeof(uint32_t) + cnt * sizeof(struct lsn);
	struct log_row *row = (struct log_row *)
		region_alloc_nothrow(&fiber->gc, sizeof(*row) + row_len);
	if (row == NULL)
		return 0;

	row->marker = marker;
	memcpy(row->lsn.uuid, local_node->uuid, sizeof(uuid_t));
	row->lsn.seq = write_current ? local_node->current_lsn
				     : local_node->confirmed_lsn;
	row->cookie = 0;
	row->len = row_len;
	row->tag  = 0; /* unused. */
	row->tm = ev_now();

	*(uint32_t *) row->data = cnt;
	uint32_t k = 0;
	struct lsn *curlsn = (struct lsn *) (row->data + sizeof(uint32_t));
	struct lsn *endlsn = curlsn + cnt;
	mh_foreach(nodes, k) {
		struct node *node = mh_uuidnode(nodes, k);
		memcpy(curlsn->uuid, node->uuid, sizeof(uuid_t));
		curlsn->seq = write_current ? node->current_lsn
					    : node->confirmed_lsn;
		curlsn++;
	}
	assert(curlsn == endlsn);

	log_row_sign(row);

	uint32_t total_len = log_row_size(row);
	if (fio_write(fileno(l->f), row, total_len) == -1) {
		say_syserror("%s: cannot write LSN table", l->filename);
		return 0;
	}

	return total_len;
}

int
log_io_write_header(struct log_io *l, mh_uuidnode_t *nodes,
		    const struct node *local_node, bool write_current)
{
	assert(l->mode == LOG_WRITE && !l->header && !l->footer);

	uint32_t sz = log_io_write_lsn_table(l, nodes, local_node,
					     write_current, header_marker);
	if (sz == 0)
		return -1;

	l->header = true;
	return 0;
}

int
log_io_write_footer(struct log_io *l, mh_uuidnode_t *nodes,
		    const struct node *local_node, bool write_current)
{
	assert(l->mode == LOG_WRITE && l->header && !l->footer);

	uint32_t sz = log_io_write_lsn_table(l, nodes, local_node,
					     write_current, footer_marker);
	if (sz == 0)
		return -1;

	if (fio_write(fileno(l->f), &sz, sizeof(sz)) == -1) {
		say_syserror("%s: cannot write LSN footer", l->filename);
		return -2;
	}

	l->footer = true;
	return 0;
}

struct log_io *
log_io_open_for_read(struct log_dir *dir, const char *filename)
{
	char fullpath[PATH_MAX];
	FILE *f = NULL;
	const char *errmsg;
	struct log_io *l;

	snprintf(fullpath, PATH_MAX, "%s/%s", dir->dirname, filename);
	f = fopen(fullpath, "r");

	if (f == NULL) {
		say_syserror("%s: cannot open", fullpath);
		goto error_1;
	}

	l = (struct log_io *) calloc(1, sizeof(*l));
	if (l == NULL) {
		say_syserror("%s: memory error", fullpath);
		goto error_2;
	}

	l->f = f;
	strncpy(l->filename, fullpath, PATH_MAX);
	l->mode = LOG_READ;
	l->dir = dir;

	/* Read meta */
	if (log_io_verify_meta(l, &errmsg) != 0) {
		say_error("%s: %s", errmsg, fullpath);
		goto error_3;
	}

	return l;
error_3:
	free(l);
error_2:
	fclose(f);
error_1:
	return NULL;
}

/**
 * In case of error, writes a message to the server log
 * and sets errno.
 */
struct log_io *
log_io_open_for_write(struct log_dir *dir, mh_uuidnode_t *nodes)
{
	/* Generate name */
	uint32_t k = 0;
	int64_t sum = 0;
	mh_foreach(nodes, k) {
		sum += mh_uuidnode(nodes, k)->confirmed_lsn;
	}
	char filename[PATH_MAX];
	snprintf(filename, PATH_MAX, "%s/%020jd%s%s", dir->dirname,
		 (intmax_t) sum, dir->filename_ext, inprogress_suffix);

	FILE *f;
	int fd;
	struct log_io *l;

	char filename2[PATH_MAX + 1];
	snprintf(filename2, PATH_MAX, "%s/%020jd%s", dir->dirname,
		 (intmax_t) sum, dir->filename_ext);

	/*
	 * Check whether a file with this name already exists.
	 * We don't overwrite existing files.
	 */
	if (access(filename2, F_OK) == 0) {
		errno = EEXIST;
		say_syserror("%s", filename2);
		goto error_1;
	}

	/*
	 * Open the <lsn>.<suffix>.inprogress file. If it exists,
	 * open will fail.
	 */
	fd = open(filename, O_WRONLY | O_CREAT | O_EXCL | dir->open_wflags,
		  dir->mode);
	if (fd < 0 || (f = fdopen(fd, "w")) == NULL) {
		say_syserror("%s: cannot open for write", filename);
		goto error_1;
	}
	setvbuf(f, NULL, _IONBF, 0);

	l = (struct log_io *) calloc(1, sizeof(*l));
	if (l == NULL) {
		say_syserror("%s: memory error", filename);
		goto error_2;
	}

	l->f = f;
	strncpy(l->filename, filename, PATH_MAX);
	l->mode = LOG_WRITE;
	l->dir = dir;

	if (log_io_write_meta(l) != 0) {
		say_syserror("%s: cannot write meta", filename);
		goto error_3;
	}

	return l;
error_3:
	free(l);
error_2:
	fclose(f);
error_1:
	return NULL;
}

/* }}} */
