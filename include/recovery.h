#ifndef TARANTOOL_RECOVERY_H_INCLUDED
#define TARANTOOL_RECOVERY_H_INCLUDED
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
#include <stdbool.h>
#include <uuid.h> /* uuid_t */
#include <netinet/in.h>

#include "tarantool/util.h"
#include "tarantool_ev.h"

#if defined(__cplusplus)
extern "C" {
#endif /* defined(__cplusplus) */

struct fiber;
struct tbuf;

typedef int (row_handler)(void *, const struct log_row *);

/*
 * Global Log Sequence Number
 */
struct lsn {
	uuid_t uuid;
	int64_t seq;
};

/*
 * Cluster Node
 */
struct node {
	uuid_t uuid;
	int64_t current_lsn;
	int64_t confirmed_lsn;
};

struct wal_writer;
struct wal_watcher;

/** Master connection */
struct remote {
	struct sockaddr_in addr;
	struct fiber *reader;
	uint64_t cookie;
	ev_tstamp recovery_lag, recovery_last_update_tstamp;
};

enum wal_mode { WAL_NONE = 0, WAL_WRITE, WAL_FSYNC, WAL_FSYNC_DELAY, WAL_MODE_MAX };

/** String constants for the supported modes. */
extern const char *wal_mode_STRS[];

struct mh_uuidnode_t;

struct recovery_state {
	struct mh_uuidnode_t *cluster;
	struct node *local_node;
	int64_t prev_sum; /* a hint for log_dir_find_xlog */
	/* The WAL we're currently reading/writing from/to. */
	struct log_io *current_wal;
	struct log_dir *snap_dir;
	struct log_dir *wal_dir;
	struct wal_writer *writer;
	struct wal_watcher *watcher;
	struct remote *remote;
	/**
	 * row_handler is a module callback invoked during initial
	 * recovery and when reading rows from the master.  It is
	 * presented with the most recent format of data.
	 * row_reader is responsible for converting data from old
	 * formats.
	 */
	row_handler *row_handler;
	void *row_handler_param;
	uint64_t snap_io_rate_limit;
	int rows_per_wal;
	double wal_fsync_delay;
	enum wal_mode wal_mode;

	bool finalize;
};

extern struct recovery_state *recovery_state;

int
recovery_init(const char *snap_dirname, const char *xlog_dirname,
	      row_handler row_handler, void *row_handler_param,
	      int rows_per_wal);
void recovery_update_mode(struct recovery_state *r,
			  const char *wal_mode, double fsync_delay);
void recovery_update_io_rate_limit(struct recovery_state *r,
				   double new_limit);
void recovery_free();
int recover_snap(struct recovery_state *r, const char *replication_source);
int recover_wals(struct recovery_state *r);
void recovery_follow_local(struct recovery_state *r, ev_tstamp wal_dir_rescan_delay);
int recovery_finalize(struct recovery_state *r);
int wal_write(struct recovery_state *r, const struct lsn *lsn, uint64_t cookie,
	      uint16_t op, const char *row, uint32_t row_len);
void recovery_setup_panic(struct recovery_state *r, bool on_snap_error, bool on_wal_error);

void
cluster_dump(struct recovery_state *r);

struct node *
cluster_node(struct recovery_state *r, const uuid_t uuid);

int
recovery_set_lsns(struct recovery_state *r, const struct lsn *lsn,
		  uint32_t count);

void recovery_follow_remote(struct recovery_state *r, const char *addr);
void recovery_stop_remote(struct recovery_state *r);

void recovery_follow_remote_1_5(struct recovery_state *r, const char *addr);
void recovery_stop_remote_1_5(struct recovery_state *r);

/**
 * The replication protocol is request/response. The
 * replica saends a request, and the master responds with
 * appropriate data.
 */
enum rpl_request_type {
	RPL_GET_WAL = 0,
	RPL_GET_SNAPSHOT
};

struct fio_batch;

void snapshot_write_row(struct log_io *i, struct fio_batch *batch,
			const char *metadata, size_t metadata_size,
			const char *data, size_t data_size);
int
snapshot_save(struct recovery_state *r,
	      void (*loop) (struct log_io *, struct fio_batch *));

void
init_storage(const char *snap_dirname, const char *replication_source);

const char *
uuid_hex(const uuid_t uuid);


/*
 * Map: (uuid) => (struct node)
 */

#include "third_party/PMurHash.h"

static inline bool
mh_uuidnode_eq_key(const uuid_t key, const struct node *node, void *arg)
{
	(void) arg;
	return memcmp(key, node->uuid, sizeof(uuid_t)) == 0;
}

static inline bool
mh_uuidnode_eq(const struct node *node_a, const struct node *node_b, void *arg)
{
	(void) arg;
	return memcmp(node_a->uuid, node_b->uuid, sizeof(uuid_t)) == 0;
}

static inline uint32_t
mh_uuidnode_hash_key(const uuid_t key, void *arg)
{
	(void) arg;
	return *(uint32_t *) key;
}

static inline uint32_t
mh_uuidnode_hash(const struct node *node, void *arg)
{
	(void) arg;
	return *(uint32_t *) node->uuid;
}

#define mh_name _uuidnode
#define mh_key_t const uuid_t
#define mh_node_t struct node *
#define mh_arg_t void *
#define mh_hash(a, arg) mh_uuidnode_hash(*a, arg)
#define mh_hash_key(a, arg) mh_uuidnode_hash_key(a, arg)
#define mh_eq(a, b, arg) mh_uuidnode_eq(*a, *b, arg)
#define mh_eq_key(key, node, arg) mh_uuidnode_eq_key(key, *node, arg)
#include <mhash.h>

#define mh_uuidnode(hash, k) (*mh_uuidnode_node(hash, k))

#if defined(__cplusplus)
} /* extern "C" */
#endif /* defined(__cplusplus) */

#endif /* TARANTOOL_RECOVERY_H_INCLUDED */
