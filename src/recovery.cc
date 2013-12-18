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
#define MH_SOURCE 1
#include "recovery.h"

#include <fcntl.h>

#include "log_io.h"
#include "fiber.h"
#include "tt_pthread.h"
#include "fio.h"
#include "sio.h"
#include "errinj.h"
#include "bootstrap.h"

#include "replication.h"

/*
 * Recovery subsystem
 * ------------------
 *
 * A facade of the recovery subsystem is struct recovery_state,
 * which is a singleton.
 *
 * Depending on the configuration, start-up parameters, the
 * actual task being performed, the recovery can be
 * in a different state.
 *
 * The main factors influencing recovery state are:
 * - temporal: whether or not the instance is just booting
 *   from a snapshot, is in 'local hot standby mode', or
 *   is already accepting requests
 * - topological: whether or not it is a master instance
 *   or a replica
 * - task based: whether it's a master process,
 *   snapshot saving process or a replication relay.
 *
 * Depending on the above factors, recovery can be in two main
 * operation modes: "read mode", recovering in-memory state
 * from existing data, and "write mode", i.e. recording on
 * disk changes of the in-memory state.
 *
 * Let's enumerate all possible distinct states of recovery:
 *
 * Read mode
 * ---------
 * IR - initial recovery, initiated right after server start:
 * reading data from the snapshot and existing WALs
 * and restoring the in-memory state
 * IRR - initial replication relay mode, reading data from
 * existing WALs (xlogs) and sending it to the client.
 *
 * HS - standby mode, entered once all existing WALs are read:
 * following the WAL directory for all changes done by the master
 * and updating the in-memory state
 * RR - replication relay, following the WAL directory for all
 * changes done by the master and sending them to the
 * replica
 *
 * Write mode
 * ----------
 * M - master mode, recording in-memory state changes in the WAL
 * R - replica mode, receiving changes from the master and
 * recording them in the WAL
 * S - snapshot mode, writing entire in-memory state to a compact
 * snapshot file.
 *
 * The following state transitions are possible/supported:
 *
 * recovery_init() -> IR | IRR # recover()
 * IR -> HS         # recovery_follow_local()
 * IRR -> RR        # recovery_follow_local()
 * HS -> M          # recovery_finalize()
 * M -> R           # recovery_follow_remote()
 * R -> M           # recovery_stop_remote()
 * M -> S           # snapshot()
 * R -> S           # snapshot()
 */

struct recovery_state *recovery_state;

static const uuid_t nil_uuid = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static const uint64_t snapshot_cookie = 0;

const char *wal_mode_STRS[] = { "none", "write", "fsync", "fsync_delay", NULL };

/* {{{ LSN API */

static void
confirm_lsn(struct recovery_state *r, struct node *node, int64_t seq,
	    bool is_commit)
{
	(void) r;
	say_debug("confirm_lsn %s, %ld", uuid_hex(node->uuid), seq);

	if (node->confirmed_lsn < seq) {
		if (is_commit) {
			if (node->confirmed_lsn + 1 != seq)
				say_warn("non consecutive LSN for %s "
					 "confirmed: %lld, new: %lld, diff: %lld",
					 uuid_hex(node->uuid),
					 (long long) node->confirmed_lsn,
					 (long long) seq,
					 (long long) (seq - node->confirmed_lsn));
			node->confirmed_lsn = seq;
		}
	} else {
		/*
		* There can be holes in
		* confirmed_lsn, in case of disk write failure, but
		* wal_writer never confirms LSNs out order.
		*/
		panic("LSN for %s is used twice or COMMIT order is broken: "
		      "confirmed: %lld, new: %lld", uuid_hex(node->uuid),
		      (long long) node->confirmed_lsn, (long long) seq);
	}
}

int
recovery_set_lsns(struct recovery_state *r, const struct lsn *lsn,
		  uint32_t count)
{
	const struct lsn *end = lsn + count;
	for (; lsn < end; ++lsn) {
		struct node *node = cluster_node(r, lsn->uuid);
		if (node == NULL)
			return -1;
		if (lsn->seq < node->confirmed_lsn) {
			say_debug("skipping too young LSN table record");
			continue;
		}

		node->current_lsn = node->confirmed_lsn = lsn->seq;
		say_debug("set_lsn(%s, %lld)", uuid_hex(lsn->uuid),
			  (long long) node->confirmed_lsn);
	}

	return 0;
}

/* }}} */

/* {{{ Cluster */

static int
cluster_init(struct recovery_state *r)
{
	/* A file to store server UUID (in text form) */
	const char *filename = path_join(r->snap_dir->dirname, "server_uuid");

	FILE *f;
	int i;
	uuid_t local_uuid;

	/* Try to read UUID from server_uuid file */
	if ((f = fopen(filename, "r")) != NULL) {
		unsigned c;
		for (i = 0; i < sizeof(uuid_t) &&
			fscanf(f, "%02x", &c) == 1; local_uuid[i++] = c);
		fclose(f);

		/* UUID is valid */
		if (i == sizeof(uuid_t))
			goto exit;
	}

	/* Generate a new UUID and save it to server_uuid file */
	if ((f = fopen(filename, "w")) == NULL) {
		say_syserror("fopen('%s', 'w')", filename);
		return false;
	}

	uuid_generate(local_uuid);

	for (i = 0; i < sizeof(uuid_t) &&
	     fprintf(f, "%02x", local_uuid[i]) == 2; i++);
	if (i != sizeof(uuid_t)) {
		say_error("fprintf");
		fclose(f);
		unlink(filename);
		return -1;
	}

	if (fclose(f) != 0) {
		say_syserror("fclose");
		return -2;
	}

exit:
	r->local_node = cluster_node(r, local_uuid);
	if (r->local_node == NULL)
		return -3;

	say_crit("server UUID is %s", uuid_hex(local_uuid));

	return 0;
}

void
cluster_dump(struct recovery_state *r)
{
	say_info("cluster state:");
	uint32_t k;
	mh_foreach(r->cluster, k) {
		struct node *node = mh_uuidnode(r->cluster, k);
		say_info("\t{uuid = %s, current = %lld, confirmed = %lld}%s",
			 uuid_hex(node->uuid),
			 (long long) node->current_lsn,
			 (long long) node->confirmed_lsn,
			 (node == r->local_node) ? " -- this server" : "");
	}
}

struct node *
cluster_node(struct recovery_state *r, const uuid_t uuid)
{
	uint32_t k = mh_uuidnode_find(r->cluster, uuid, NULL);
	if (k == mh_end(r->cluster)) {
		struct node *node = (struct node *) calloc(1, sizeof(*node));
		if (node == NULL) {
			say_syserror("cannot allocate struct node");
			return NULL;
		}
		memcpy(node->uuid, uuid, sizeof(uuid_t));
		k = mh_uuidnode_put(r->cluster, (const struct node **) &node,
				    NULL, NULL);
		if (k == mh_end(r->cluster)) {
			say_syserror("cannot reallocate r->cluster");
			free(node);
			return NULL;
		}

		return node;
	} else {
		return mh_uuidnode(r->cluster, k);
	}
}

/* }}} */

/* {{{ Initial recovery */

static int
wal_writer_start(struct recovery_state *state);
void
wal_writer_stop(struct recovery_state *r);
static void
recovery_stop_local(struct recovery_state *r);

int
recovery_init(const char *snap_dirname, const char *wal_dirname,
	      row_handler row_handler, void *row_handler_param,
	      int rows_per_wal)
{
	int rc = 0;
	assert(recovery_state == NULL);
	recovery_state = (struct recovery_state *) calloc(1, sizeof(struct recovery_state));
	struct recovery_state *r = recovery_state;
	recovery_update_mode(r, "none", 0);

	--rc;
	r->cluster = mh_uuidnode_new();
	if (r->cluster == NULL) {
		say_syserror("cannot allocate recovery_state->cluster");
		goto error_1;
	}
	assert(rows_per_wal > 1);

	r->row_handler = row_handler;
	r->row_handler_param = row_handler_param;

	r->snap_dir = &snap_dir;
	r->snap_dir->dirname = strdup(snap_dirname);
	r->wal_dir = &wal_dir;
	r->wal_dir->dirname = strdup(wal_dirname);
	r->wal_dir->open_wflags = r->wal_mode == WAL_FSYNC ? WAL_SYNC_FLAG : 0;
	r->rows_per_wal = rows_per_wal;

	--rc;
	if (cluster_init(r) != 0)
		goto error_2;

	return 0;

error_2:
	free(r->local_node);
error_1:
	return rc;
}

void
recovery_update_mode(struct recovery_state *r,
		     const char *mode, double fsync_delay)
{
	r->wal_mode = (enum wal_mode) strindex(wal_mode_STRS, mode, WAL_MODE_MAX);
	assert(r->wal_mode != WAL_MODE_MAX);
	/* No mutex lock: let's not bother with whether
	 * or not a WAL writer thread is present, and
	 * if it's present, the delay will be propagated
	 * to it whenever there is a next lock/unlock of
	 * wal_writer->mutex.
	 */
	r->wal_fsync_delay = fsync_delay;
}

void
recovery_update_io_rate_limit(struct recovery_state *r, double new_limit)
{
	r->snap_io_rate_limit = new_limit * 1024 * 1024;
	if (r->snap_io_rate_limit == 0)
		r->snap_io_rate_limit = UINT64_MAX;
}

void
recovery_free()
{
	struct recovery_state *r = recovery_state;
	if (r == NULL)
		return;

	if (r->watcher)
		recovery_stop_local(r);

	if (r->writer)
		wal_writer_stop(r);

	free(r->snap_dir->dirname);
	free(r->wal_dir->dirname);
	if (r->current_wal) {
		/*
		 * Possible if shutting down a replication
		 * relay or if error during startup.
		 */
		log_io_close(&r->current_wal);
	}

	while (mh_size(r->cluster) > 0) {
		mh_int_t k = mh_first(r->cluster);

		struct node *node = mh_uuidnode(r->cluster, k);
		mh_uuidnode_del(r->cluster, k, NULL);
		free(node);
	}

	recovery_state = NULL;
}

void
recovery_setup_panic(struct recovery_state *r, bool on_snap_error, bool on_wal_error)
{
	r->wal_dir->panic_if_error = on_wal_error;
	r->snap_dir->panic_if_error = on_snap_error;
}

/** Write the bootstrap snapshot.
 *
 *  @return panics on error
 *  Errors are logged to the log file.
 */
static void
init_storage_on_master(const char *snap_dir)
{
	const char *filename = path_join(snap_dir, "bootstrap.snap");
	int fd = open(filename, O_EXCL|O_CREAT|O_WRONLY, 0660);
	say_info("saving snapshot `%s'", filename);
	if (fd == -1) {
		panic_syserror("failed to open snapshot file `%s' for "
			       "writing", filename);
	}
	if (write(fd, bootstrap_bin, sizeof(bootstrap_bin)) !=
						sizeof(bootstrap_bin)) {
		panic_syserror("failed to write to snapshot file `%s'",
			       filename);
	}
	close(fd);
}

/** Download the latest snapshot from master. */
static void
init_storage_on_replica(const char *snap_dirname, const char *replication_source)
{
	say_info("downloading snapshot from master %s...",
		 replication_source);

	int master = replica_connect(replication_source);
	FDGuard guard_master(master);

	uint32_t request = RPL_GET_SNAPSHOT;
	sio_writen(master, &request, sizeof(request));

	uint64_t file_size;
	sio_readn(master, &file_size, sizeof(file_size));

	const char *filename = path_join(snap_dirname, "master.snap");
	say_info("saving snapshot `%s'", filename);
	int fd = open(filename, O_WRONLY|O_CREAT|O_EXCL, 0660);
	if (fd == -1) {
		panic_syserror("failed to open snapshot file `%s' for "
			       "writing", filename);
	}
	FDGuard guard_fd(fd);

	sio_recvfile(master, fd, NULL, file_size);
}

/** Create the initial snapshot file in the snap directory. */
void
init_storage(const char *snap_dirname, const char *replication_source)
{
	if (replication_source)
		init_storage_on_replica(snap_dirname, replication_source);
	else
		init_storage_on_master(snap_dirname);
	say_info("done");
}


static int
recover_rows(struct recovery_state *r, struct log_io *l, bool skip);

/**
 * Read a snapshot and call row_handler for every snapshot row.
 * Panic in case of error.
 */
int
recover_snap(struct recovery_state *r, const char *replication_source)
{
	const struct lsn *lsns;
	uint32_t lsns_count;
	int64_t start_seq = 0;
	uint32_t k;
	struct node *nil_node;

	/*  current_wal isn't open during initial recover. */
	assert(r->current_wal == NULL);
	say_info("recovery start");

	int rc = -1;
	struct log_io *l = log_dir_find_snap(r->snap_dir);
	if (l == NULL) {
		say_info("found an empty data directory, initializing...");
		init_storage(r->snap_dir->dirname, replication_source);
		l = log_dir_find_snap(r->snap_dir);
	}
	if (l == NULL) {
		say_error("didn't you forget to initialize storage with "
		          "--init-storage switch?");
		return rc;
	}
	say_info("found snapshot %s", l->filename);

	--rc;
	if (recovery_set_lsns(r, l->lsns, l->lsns_count) != 0)
		goto error;

	nil_node = cluster_node(r, nil_uuid);
	if (nil_node == NULL)
		goto error;
	nil_node->confirmed_lsn = nil_node->current_lsn = 0;

	--rc;
	say_info("recover from `%s'", l->filename);
	if (recover_rows(r, l, false) != 0) {
		say_error("can't recover wal");
		goto error;
	}

	--rc;
	lsns = log_io_read_footer(l, &lsns_count);
	if (lsns == NULL || recovery_set_lsns(r, lsns, lsns_count) != 0)
		goto error;

	/* Clear LSN for nil uuid */
	k = mh_uuidnode_find(r->cluster, nil_uuid, NULL);
	if (k != mh_end(r->cluster)) {
		if (mh_size(r->cluster) == 1) {
			/* bootstrap.snap detected */
			start_seq = mh_uuidnode(r->cluster, k)->confirmed_lsn;
		}
		mh_uuidnode_del(r->cluster, k, NULL);
	}

	/*
	 * Set LSN for local uuid
	 */
	if (r->local_node->confirmed_lsn == 0) {
		r->local_node->current_lsn = r->local_node->confirmed_lsn = start_seq;
	}

	say_info("snapshot recovered");
	cluster_dump(r);
	return 0;

error:
	log_io_close(&l);
	return rc;

}

/**
 * @retval -1 error
 * @retval 0 EOF
 * @retval 1 ok, maybe read something
 */
static int
recover_rows(struct recovery_state *r, struct log_io *l, bool skip)
{
	int res = -1;
	struct log_io_cursor i;

	log_io_cursor_open(&i, l);

	const struct log_row *row;
	while ((row = log_io_cursor_next(&i))) {
		++l->rows;
		struct node *node = cluster_node(r, row->lsn.uuid);
		if (node == NULL)
			goto end;
		if (skip) {
			if (row->lsn.seq <= node->confirmed_lsn) {
				say_debug("skipping too young row");
				continue;
			}
		}

		if (r->row_handler(r->row_handler_param, row) < 0) {
			say_error("can't apply row");
			if (l->dir->panic_if_error)
				goto end;
		}
	}
	res = i.eof_read ? 0 : 1;
end:
	log_io_cursor_close(&i);
	/* Sic: we don't close the log here. */
	return res;
}

/** Find out if there are new .xlog files since the current
 * LSN, and read them all up.
 *
 * This function will not close r->current_wal if
 * recovery was successful.
 */
int
recover_wals(struct recovery_state *r)
{
	const struct lsn *lsns;
	uint32_t lsns_count;

	if (r->current_wal != NULL)
		goto recover_current_wal;

find_next_wal:
	r->current_wal = log_dir_find_xlog(r->wal_dir, r->cluster, r->prev_sum);
	if (r->current_wal == NULL)
		return 0; /* no more files */

	say_info("recover from %s", r->current_wal->filename);

	if (recovery_set_lsns(r, r->current_wal->lsns,
			      r->current_wal->lsns_count) != 0)
		return -1; /* error */

	r->prev_sum = 1;
	for (uint32_t i = 0; i < r->current_wal->lsns_count; i++) {
		r->prev_sum += r->current_wal->lsns[i].seq;
	}

recover_current_wal:
	int rc = recover_rows(r, r->current_wal, true);
	if (rc < 0) {
		say_error("%s: cannot recover wal", r->current_wal->filename);
		return -1;
	} else if (rc > 0) {
		return 1; /* not ready */
	}

	lsns = log_io_read_footer(r->current_wal, &lsns_count);
	if (lsns == NULL)
		return 1; /* not ready */

	if (recovery_set_lsns(r, lsns, lsns_count) != 0)
		 return -1; /* error */

	say_debug("%s: recovered %zu rows", r->current_wal->filename,
		  r->current_wal->rows);
	if (r->current_wal->rows == 0) {
		say_warn("%s: removing empty file", r->current_wal->filename);
		if (unlink(r->current_wal->filename) != 0) {
			/* Don't panic if there is no such file. */
			say_syserror("%s: unlink", r->current_wal->filename);
		}
	}

	/* finish with the xlog */
	log_io_close(&r->current_wal);

	region_free(&fiber->gc);
	goto find_next_wal;
}

int
recovery_finalize(struct recovery_state *r)
{
	int result;

	if (r->watcher)
		recovery_stop_local(r);

	r->finalize = true;
	while ((result = recover_wals(r)) != 0) {
		if (r->current_wal != NULL) {
			say_error("%s: cannot fully recover file!",
				  r->current_wal->filename);
			log_io_close(&r->current_wal);
		}

		if (result < 0)
			return -1;
	}

	if (wal_writer_start(r) != 0) {
		say_error("cannot start wal writer");
		return -2;
	}

	/* set current lsn to confirmed lsn after recovery */
	uint32_t k = 0;
	mh_foreach(r->cluster, k) {
		struct node *node = mh_uuidnode(r->cluster, k);
		node->current_lsn = node->confirmed_lsn;
	}

	say_info("recovered");
	cluster_dump(r);

	return 0;
}

/* }}} */

/* {{{ Local recovery: support of hot standby and replication relay */

/**
 * This is used in local hot standby or replication
 * relay mode: look for changes in the wal_dir and apply them
 * locally or send to the replica.
 */
struct wal_watcher {
	/**
	 * Rescan the WAL directory in search for new WAL files
	 * every wal_dir_rescan_delay seconds.
	 */
	ev_timer dir_timer;
	/**
	 * When the latest WAL does not contain a EOF marker,
	 * re-read its tail on every change in file metadata.
	 */
	ev_stat stat;
	/** Path to the file being watched with 'stat'. */
	char filename[PATH_MAX+1];
};

static struct wal_watcher wal_watcher;

static int
recovery_rescan(struct recovery_state *r);

static void
recovery_rescan_dir(ev_timer *w, int revents)
{
	(void) revents;
	struct recovery_state *r = (struct recovery_state *) w->data;
	if (recovery_rescan(r) < 0)
		panic("recovery failed");
}


static void
recovery_rescan_file(ev_stat *w, int revents)
{
	(void) revents;
	struct recovery_state *r = (struct recovery_state *) w->data;
	if (recovery_rescan(r) < 0)
		panic("recovery failed");
}

static void
recovery_watch_file(struct wal_watcher *watcher, struct log_io *wal)
{
	strncpy(watcher->filename, wal->filename, PATH_MAX);
	ev_stat_init(&watcher->stat, recovery_rescan_file, watcher->filename, 0.);
	ev_stat_start(&watcher->stat);
}

static void
recovery_stop_file(struct wal_watcher *watcher)
{
	ev_stat_stop(&watcher->stat);
}

static int
recovery_rescan(struct recovery_state *r)
{
	struct log_io *save_current_wal = r->current_wal;
	int result = recover_wals(r);
	if (result != 0)
		return result;
	if (save_current_wal != r->current_wal) {
		if (save_current_wal != NULL)
			recovery_stop_file(r->watcher);
		if (r->current_wal != NULL)
			recovery_watch_file(r->watcher, r->current_wal);
	}

	return 0;
}

void
recovery_follow_local(struct recovery_state *r, ev_tstamp wal_dir_rescan_delay)
{
	assert(r->watcher == NULL);
	assert(r->writer == NULL);

	struct wal_watcher  *watcher = r->watcher= &wal_watcher;

	ev_timer_init(&watcher->dir_timer, recovery_rescan_dir,
		      wal_dir_rescan_delay, wal_dir_rescan_delay);
	watcher->dir_timer.data = watcher->stat.data = r;
	ev_timer_start(&watcher->dir_timer);
	/*
	 * recover_wals() leaves the current wal open if it has no
	 * EOF marker.
	 */
	if (r->current_wal != NULL)
		recovery_watch_file(watcher, r->current_wal);
}

static void
recovery_stop_local(struct recovery_state *r)
{
	struct wal_watcher *watcher = r->watcher;
	assert(ev_is_active(&watcher->dir_timer));
	ev_timer_stop(&watcher->dir_timer);
	if (ev_is_active(&watcher->stat))
		ev_stat_stop(&watcher->stat);

	r->watcher = NULL;
}

/* }}} */

/* {{{ WAL writer - maintain a Write Ahead Log for every change
 * in the data state.
 */

struct wal_write_request {
	STAILQ_ENTRY(wal_write_request) wal_fifo_entry;
	/* Auxiliary. */
	int res;
	struct fiber *fiber;
	struct log_row row;
};

/* Context of the WAL writer thread. */
STAILQ_HEAD(wal_fifo, wal_write_request);

struct wal_writer
{
	struct wal_fifo input;
	struct wal_fifo commit;
	pthread_t thread;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	ev_async write_event;
	struct fio_batch *batch;
	bool is_shutdown;
	bool is_rollback;
};

static pthread_once_t wal_writer_once = PTHREAD_ONCE_INIT;

static struct wal_writer wal_writer;

/**
 * A pthread_atfork() callback for a child process. Today we only
 * fork the master process to save a snapshot, and in the child
 * the WAL writer thread is not necessary and not present.
 */
static void
wal_writer_child()
{
	log_io_atfork(&recovery_state->current_wal);
	if (wal_writer.batch) {
		free(wal_writer.batch);
		wal_writer.batch = NULL;
	}
	/*
	 * Make sure that atexit() handlers in the child do
	 * not try to stop the non-existent thread.
	 * The writer is not used in the child.
	 */
	recovery_state->writer = NULL;
}

/**
 * Today a WAL writer is started once at start of the
 * server.  Nevertheless, use pthread_once() to make
 * sure we can start/stop the writer many times.
 */
static void
wal_writer_init_once()
{
	(void) tt_pthread_atfork(NULL, NULL, wal_writer_child);
}

/**
 * A commit watcher callback is invoked whenever there
 * are requests in wal_writer->commit. This callback is
 * associated with an internal WAL writer watcher and is
 * invoked in the front-end main event loop.
 *
 * A rollback watcher callback is invoked only when there is
 * a rollback request and commit is empty.
 * We roll back the entire input queue.
 *
 * ev_async, under the hood, is a simple pipe. The WAL
 * writer thread writes to that pipe whenever it's done
 * handling a pack of requests (look for ev_async_send()
 * call in the writer thread loop).
 */
static void
wal_schedule_queue(struct wal_fifo *queue)
{
	/*
	 * Can't use STAILQ_FOREACH since fiber_call()
	 * destroys the list entry.
	 */
	struct wal_write_request *req, *tmp;
	STAILQ_FOREACH_SAFE(req, queue, wal_fifo_entry, tmp)
		fiber_call(req->fiber);
}

static void
wal_schedule(ev_async *watcher, int event __attribute__((unused)))
{
	struct wal_writer *writer = (struct wal_writer *) watcher->data;
	struct wal_fifo commit = STAILQ_HEAD_INITIALIZER(commit);
	struct wal_fifo rollback = STAILQ_HEAD_INITIALIZER(rollback);

	(void) tt_pthread_mutex_lock(&writer->mutex);
	STAILQ_CONCAT(&commit, &writer->commit);
	if (writer->is_rollback) {
		STAILQ_CONCAT(&rollback, &writer->input);
		writer->is_rollback = false;
	}
	(void) tt_pthread_mutex_unlock(&writer->mutex);

	wal_schedule_queue(&commit);
	/*
	 * Perform a cascading abort of all transactions which
	 * depend on the transaction which failed to get written
	 * to the write ahead log. Abort transactions
	 * in reverse order, performing a playback of the
	 * in-memory database state.
	 */
	STAILQ_REVERSE(&rollback, wal_write_request, wal_fifo_entry);
	wal_schedule_queue(&rollback);
}

/**
 * Initialize WAL writer context. Even though it's a singleton,
 * encapsulate the details just in case we may use
 * more writers in the future.
 */
static void
wal_writer_init(struct wal_writer *writer)
{
	/* I. Initialize the state. */
	pthread_mutexattr_t errorcheck;

	(void) tt_pthread_mutexattr_init(&errorcheck);

#ifndef NDEBUG
	(void) tt_pthread_mutexattr_settype(&errorcheck, PTHREAD_MUTEX_ERRORCHECK);
#endif
	/* Initialize queue lock mutex. */
	(void) tt_pthread_mutex_init(&writer->mutex, &errorcheck);
	(void) tt_pthread_mutexattr_destroy(&errorcheck);

	(void) tt_pthread_cond_init(&writer->cond, NULL);

	STAILQ_INIT(&writer->input);
	STAILQ_INIT(&writer->commit);

	ev_async_init(&writer->write_event, wal_schedule);
	writer->write_event.data = writer;

	(void) tt_pthread_once(&wal_writer_once, wal_writer_init_once);

	writer->batch = fio_batch_alloc(sysconf(_SC_IOV_MAX));

	if (writer->batch == NULL)
		panic_syserror("fio_batch_alloc");
}

/** Destroy a WAL writer structure. */
static void
wal_writer_destroy(struct wal_writer *writer)
{
	(void) tt_pthread_mutex_destroy(&writer->mutex);
	(void) tt_pthread_cond_destroy(&writer->cond);
	free(writer->batch);
}

/** WAL writer thread routine. */
static void *wal_writer_thread(void *worker_args);

/**
 * Initialize WAL writer, start the thread.
 *
 * @pre   The server has completed recovery from a snapshot
 *        and/or existing WALs. All WALs opened in read-only
 *        mode are closed.
 *
 * @param state			WAL writer meta-data.
 *
 * @return 0 success, -1 on error. On success, recovery->writer
 *         points to a newly created WAL writer.
 */
static int
wal_writer_start(struct recovery_state *r)
{
	assert(r->writer == NULL);
	assert(r->watcher == NULL);
	assert(r->current_wal == NULL);
	assert(! wal_writer.is_shutdown);
	assert(STAILQ_EMPTY(&wal_writer.input));
	assert(STAILQ_EMPTY(&wal_writer.commit));

	/* I. Initialize the state. */
	wal_writer_init(&wal_writer);
	r->writer = &wal_writer;

	ev_async_start(&wal_writer.write_event);

	/* II. Start the thread. */

	if (tt_pthread_create(&wal_writer.thread, NULL, wal_writer_thread, r)) {
		wal_writer_destroy(&wal_writer);
		r->writer = NULL;
		return -1;
	}
	return 0;
}

/** Stop and destroy the writer thread (at shutdown). */
void
wal_writer_stop(struct recovery_state *r)
{
	struct wal_writer *writer = r->writer;

	/* Stop the worker thread. */

	(void) tt_pthread_mutex_lock(&writer->mutex);
	writer->is_shutdown= true;
	(void) tt_pthread_cond_signal(&writer->cond);
	(void) tt_pthread_mutex_unlock(&writer->mutex);

	if (tt_pthread_join(writer->thread, NULL) != 0) {
		/* We can't recover from this in any reasonable way. */
		panic_syserror("WAL writer: thread join failed");
	}

	ev_async_stop(&writer->write_event);
	wal_writer_destroy(writer);

	r->writer = NULL;
}

/**
 * If there is no current WAL, try to open it, and close the
 * previous WAL. We close the previous WAL only after opening
 * a new one to smoothly move local hot standby and replication
 * over to the next WAL.
 * If the current WAL has only 1 record, it means we need to
 * rename it from '.inprogress' to '.xlog'. We maintain
 * '.inprogress' WALs to ensure that, at any point in time,
 * an .xlog file contains at least 1 valid record.
 * In case of error, we try to close any open WALs.
 *
 * @post r->current_wal is in a good shape for writes or is NULL.
 * @return 0 in case of success, -1 on error.
 */
static int
wal_opt_rotate(struct recovery_state *r, struct log_io **wal, int rows_per_wal,
	       struct log_dir *dir)
{
	struct log_io *l = *wal, *wal_to_close = NULL;

	ERROR_INJECT_RETURN(ERRINJ_WAL_ROTATE);

	if (l != NULL && (l->rows >= rows_per_wal)) {
		/*
		 * if l->rows == 1, log_io_close() does
		 * inprogress_log_rename() for us.
		 */
		wal_to_close = l;
		l = NULL;
	}
	if (l == NULL) {
		/* Open WAL with '.inprogress' suffix. */
		l = log_io_open_for_write(dir, r->cluster);
		if (l ==  NULL)
			return -1;

		if (log_io_write_header(l, r->cluster, r->local_node, false) != 0) {
			log_io_close(&l);
			return -2;
		}

		if (inprogress_log_rename(l) != 0) {
			log_io_close(&l);
			return -3;
		}

		/*
		 * Close the file *after* we create the new WAL, since
		 * this is when replication relays get an inotify alarm
		 * (when we close the file), and try to reopen the next
		 * WAL. In other words, make sure that replication relays
		 * try to open the next WAL only when it exists.
		 */
		if (wal_to_close) {
			/*
			 * We can not handle log_io_close()
			 * failure in any reasonable way.
			 * A warning is written to the server
			 * log file.
			 */
			log_io_write_footer(wal_to_close, r->cluster,
					    r->local_node, false);
			log_io_close(&wal_to_close);
		}
	}
	assert(wal_to_close == NULL);
	*wal = l;
	return l ? 0 : -1;
}

static void
wal_opt_sync(struct log_io *wal, double sync_delay)
{
	static ev_tstamp last_sync = 0;

	if (sync_delay > 0 && ev_now() - last_sync >= sync_delay) {
		/*
		 * XXX: in case of error, we don't really know how
		 * many records were not written to disk: probably
		 * way more than the last one.
		 */
		(void) log_io_sync(wal);
		last_sync = ev_now();
	}
}

static struct wal_write_request *
wal_fill_batch(struct log_io *wal, struct fio_batch *batch, int rows_per_wal,
	       struct wal_write_request *req)
{
	int max_rows = rows_per_wal - wal->rows;
	/* Post-condition of successful wal_opt_rotate(). */
	assert(max_rows > 0);
	fio_batch_start(batch, max_rows);
	while (req != NULL && ! fio_batch_is_full(batch)) {
		struct log_row *row = &req->row;
		log_row_sign(row);
		fio_batch_add(batch, row, log_row_size(row));
		req = STAILQ_NEXT(req, wal_fifo_entry);
	}
	return req;
}

static struct wal_write_request *
wal_write_batch(struct log_io *wal, struct fio_batch *batch,
		struct wal_write_request *req, struct wal_write_request *end)
{
	int rows_written = fio_batch_write(batch, fileno(wal->f));
	wal->rows += rows_written;
	while (req != end && rows_written-- != 0)  {
		req->res = 0;
		req = STAILQ_NEXT(req, wal_fifo_entry);
	}
	return req;
}

static void
wal_write_to_disk(struct recovery_state *r, struct wal_writer *writer,
		  struct wal_fifo *input, struct wal_fifo *commit,
		  struct wal_fifo *rollback)
{
	struct log_io **wal = &r->current_wal;
	struct fio_batch *batch = writer->batch;

	struct wal_write_request *req = STAILQ_FIRST(input);
	struct wal_write_request *write_end = req;

	while (req) {
		if (wal_opt_rotate(r, wal, r->rows_per_wal, r->wal_dir) != 0)
			break;
		struct wal_write_request *batch_end;
		batch_end = wal_fill_batch(*wal, batch, r->rows_per_wal, req);
		write_end = wal_write_batch(*wal, batch, req, batch_end);
		if (batch_end != write_end)
			break;
		wal_opt_sync(*wal, r->wal_fsync_delay);
		req = write_end;
	}
	STAILQ_SPLICE(input, write_end, wal_fifo_entry, rollback);
	STAILQ_CONCAT(commit, input);
}

/** WAL writer thread main loop.  */
static void *
wal_writer_thread(void *worker_args)
{
	struct recovery_state *r = (struct recovery_state *) worker_args;
	struct wal_writer *writer = r->writer;
	struct wal_fifo input = STAILQ_HEAD_INITIALIZER(input);
	struct wal_fifo commit = STAILQ_HEAD_INITIALIZER(commit);
	struct wal_fifo rollback = STAILQ_HEAD_INITIALIZER(rollback);

	(void) tt_pthread_mutex_lock(&writer->mutex);
	while (! writer->is_shutdown) {
		/**
		 * Pop a bulk of requests to write to disk to process.
		 * Block on the condition only if we have no other work to
		 * do. Loop in case of a spurious wakeup.
		 */
		if (writer->is_rollback || STAILQ_EMPTY(&writer->input)) {
			(void) tt_pthread_cond_wait(&writer->cond, &writer->mutex);
			continue;
		}

		STAILQ_CONCAT(&input, &writer->input);
		(void) tt_pthread_mutex_unlock(&writer->mutex);

		wal_write_to_disk(r, writer, &input, &commit, &rollback);

		(void) tt_pthread_mutex_lock(&writer->mutex);
		STAILQ_CONCAT(&writer->commit, &commit);
		if (! STAILQ_EMPTY(&rollback)) {
			/*
			 * Begin rollback: create a rollback queue
			 * from all requests which were not
			 * written to disk and all requests in the
			 * input queue.
			 */
			writer->is_rollback = true;
			STAILQ_CONCAT(&rollback, &writer->input);
			STAILQ_CONCAT(&writer->input, &rollback);
		}
		ev_async_send(&writer->write_event);
	}
	(void) tt_pthread_mutex_unlock(&writer->mutex);
	if (r->current_wal != NULL) {
		log_io_write_footer(r->current_wal, r->cluster,
				    r->local_node, false);
		log_io_close(&r->current_wal);
	}
	return NULL;
}

/**
 * WAL writer main entry point: queue a single request
 * to be written to disk and wait until this task is completed.
 */
int
wal_write(struct recovery_state *r, const struct lsn *lsn, uint64_t cookie,
	  uint16_t op, const char *row, uint32_t row_len)
{
	struct node *node = r->local_node;
	/** @todo: remove temporary curlsn */
	struct lsn curlsn;
	if (lsn == NULL) {
		node = r->local_node;
		memcpy(curlsn.uuid, r->local_node->uuid, sizeof(uuid_t));
		curlsn.seq = ++node->current_lsn;
		lsn = &curlsn;
	} else {
		node = cluster_node(r, lsn->uuid);
		if (node == NULL) {
			say_syserror("cannot allocate struct node");
			return -1;
		}

		node->current_lsn = lsn->seq;
	}

	ERROR_INJECT_RETURN(ERRINJ_WAL_IO);

	if (r->wal_mode == WAL_NONE) {
		confirm_lsn(r, node, lsn->seq, true);
		return 0;
	}

	struct wal_writer *writer = r->writer;

	struct wal_write_request *req = (struct wal_write_request *)
		region_alloc(&fiber->gc, sizeof(struct wal_write_request) +
			     sizeof(op) + row_len);

	req->fiber = fiber;
	req->res = -1;
	log_row_fill(&req->row, lsn, cookie, (const char *) &op, sizeof(op),
			row, row_len);

	(void) tt_pthread_mutex_lock(&writer->mutex);

	bool input_was_empty = STAILQ_EMPTY(&writer->input);
	STAILQ_INSERT_TAIL(&writer->input, req, wal_fifo_entry);

	if (input_was_empty)
		(void) tt_pthread_cond_signal(&writer->cond);

	(void) tt_pthread_mutex_unlock(&writer->mutex);

	fiber_yield(); /* Request was inserted. */

	confirm_lsn(r, node, lsn->seq, req->res == 0);
	return req->res;
}

/* }}} */

/* {{{ SAVE SNAPSHOT and tarantool_box --cat */

static void
snap_write_batch(struct fio_batch *batch, int fd)
{
	int rows_written = fio_batch_write(batch, fd);
	if (rows_written != batch->rows) {
		say_error("partial write: %d out of %d rows",
			  rows_written, batch->rows);
		panic_syserror("fio_batch_write");
	}
}

void
snapshot_write_row(struct log_io *l, struct fio_batch *batch,
		   const char *metadata, size_t metadata_len,
		   const char *data, size_t data_len)
{
	static uint64_t bytes;
	ev_tstamp elapsed;
	static ev_tstamp last = 0;

	struct log_row *row = (struct log_row *) region_alloc(&fiber->gc,
		sizeof(*row) + data_len + metadata_len);

	struct lsn lsn;
	memset(lsn.uuid, 0, sizeof(lsn.uuid)); /* use UUID 0x0 for snapshot */
	lsn.seq = ++l->rows;
	log_row_fill(row,  &lsn, snapshot_cookie, metadata, metadata_len,
			data, data_len);
	log_row_sign(row);

	fio_batch_add(batch, row, log_row_size(row));
	bytes += log_row_size(row);

	if (l->rows % 100000 == 0)
		say_crit("%.1fM rows written", l->rows / 1000000.);

	if (fio_batch_is_full(batch) ||
	    bytes > recovery_state->snap_io_rate_limit) {

		snap_write_batch(batch, fileno(l->f));
		fio_batch_start(batch, INT_MAX);
		region_free_after(&fiber->gc, 128 * 1024);
		if (recovery_state->snap_io_rate_limit != UINT64_MAX) {
			if (last == 0) {
				/*
				 * Remember the time of first
				 * write to disk.
				 */
				ev_now_update();
				last = ev_now();
			}
			/**
			 * If io rate limit is set, flush the
			 * filesystem cache, otherwise the limit is
			 * not really enforced.
			 */
			fdatasync(fileno(l->f));
		}
		while (bytes >= recovery_state->snap_io_rate_limit) {
			ev_now_update();
			/*
			 * How much time have passed since
			 * last write?
			 */
			elapsed = ev_now() - last;
			/*
			 * If last write was in less than
			 * a second, sleep until the
			 * second is reached.
			 */
			if (elapsed < 1)
				usleep(((1 - elapsed) * 1000000));

			ev_now_update();
			last = ev_now();
			bytes -= recovery_state->snap_io_rate_limit;
		}
	}
}

int
snapshot_save(struct recovery_state *r,
	      void (*f) (struct log_io *, struct fio_batch *))
{
	struct fio_batch *batch;
	struct log_io *snap = log_io_open_for_write(r->snap_dir, r->cluster);
	if (snap == NULL)
		goto error_1;

	if (log_io_write_header(snap, r->cluster, r->local_node, true) != 0)
		goto error_2;

	batch = fio_batch_alloc(sysconf(_SC_IOV_MAX));
	if (batch == NULL) {
		say_syserror("memory error");
		goto error_3;
	}

	fio_batch_start(batch, INT_MAX);
	/*
	 * While saving a snapshot, snapshot name is set to
	 * <lsn>.snap.inprogress. When done, the snapshot is
	 * renamed to <lsn>.snap.
	 */
	say_info("saving snapshot `%s'", snap->filename);
	f(snap, batch);

	if (batch->rows)
		snap_write_batch(batch, fileno(snap->f));

	free(batch);

	if (log_io_write_footer(snap, r->cluster, r->local_node, true) != 0)
		goto error_3;

	if (inprogress_log_rename(snap) != 0)
		goto error_3;

	if (log_io_close(&snap) != 0)
		goto error_3;

	return 0;

error_3:
	/** @todo: unlink broken file */
error_2:
	say_error("error");
	log_io_close(&snap);
error_1:
	return -1;
}

/* }}} */

const char *
uuid_hex(const uuid_t uuid)
{
	static char uuid_hex[2 * sizeof(uuid_t) + 1];
	for (int i = 0; i < sizeof(uuid_t); i++)
		snprintf(uuid_hex + i * 2, 3, "%02x", (unsigned) uuid[i]);

	return uuid_hex;
}

