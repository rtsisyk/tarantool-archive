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
#include "fiber.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <say.h>
#include <tbuf.h>
#include <palloc.h>
#include <stat.h>
#include <assoc.h>
#include <rlist.h>
#include "third_party/queue.h"

const ev_tstamp FIBER_TIMEOUT_INFINITY = 365*86400*100.0;

@implementation FiberCancelException
@end

static struct fiber sched;
__thread struct fiber *fiber = &sched;
static __thread uint32_t last_used_fid;
static __thread struct mh_i32ptr_t *fiber_registry;
static __thread struct rlist fibers, zombie_fibers, ready_fibers;
static __thread ev_async ready_async;

static void
update_last_stack_frame(struct fiber *fiber)
{
#ifdef ENABLE_BACKTRACE
	fiber->last_stack_frame = __builtin_frame_address(0);
#else
	(void)fiber;
#endif /* ENABLE_BACKTRACE */
}

static void
fiber_zombificate(struct fiber *f);

static void
fiber_wakeup_next(struct fiber *f);

extern inline struct fiber *
fiber_self(void);

extern inline uint32_t
fiber_id(const struct fiber *f);

extern const char *
fiber_name(const struct fiber *f);

extern inline uint32_t
fiber_sid(const struct fiber *f);

extern inline void
fiber_set_sid(struct fiber *f, uint32_t sid);

extern inline enum fiber_state
fiber_state(const struct fiber *f);

extern inline bool
fiber_flag(const struct fiber *f, enum fiber_flags flag);

extern inline bool
fiber_set_flag(struct fiber *f, enum fiber_flags flag);

extern inline bool
fiber_clear_flag(struct fiber *f, enum fiber_flags flag);

extern inline const void *
fiber_args_format(void);

extern inline bool
fiber_has_args(void);

extern inline void
fiber_args_start(va_list ap);

extern inline void
fiber_args_end(va_list ap);

void
fiber_change_state(enum fiber_state state)
{
#if defined(DEBUG) || defined(FIBER_TRACE_STATE)
	switch(state) {
	case FIBER_STARTED:
		say_debug("start");
		assert(fiber->state == FIBER_CREATED);
		break;
	case FIBER_RESUMED:
		say_debug("resume");
		assert(fiber->state == FIBER_PAUSED ||
		       fiber->state == FIBER_STARTED);
		break;
	case FIBER_PAUSED:
		say_debug("pause");
		assert(fiber->state == FIBER_RESUMED);
		break;
	case FIBER_STOPPED:
		say_debug("stop");
		assert(fiber->state == FIBER_PAUSED);
		break;
	case FIBER_CREATED:
	case FIBER_DESTROYED:
		break;
	}
#endif /* defined(DEBUG) || defined(FIBER_TRACE_STATE) */
	fiber->state = state;

	if (state < FIBER_STARTED || state > FIBER_DESTROYED)
		return;

	size_t hook = state - FIBER_CREATED - 1;
	for (size_t i = 0; i < fiber->hook_sizes[hook]; i++) {
		fiber->hooks[hook][i]();
	}
}

void
fiber_transfer(struct fiber *callee)
{
	struct fiber *caller = fiber;
	update_last_stack_frame(caller);

	fiber = callee;
	coro_transfer(&caller->coro.ctx, &fiber->coro.ctx);
	assert(fiber->fid == caller->fid);
}

void
fiber_vresume(struct fiber *callee, const void *args_format, va_list ap)
{
	struct fiber *caller = fiber;
	assert(fiber_state(callee) < FIBER_STOPPED);
	assert(callee != &sched);

	bool call_from_sched = (caller == &sched);

	if (caller == callee) {
		say_warn("An attempt to resume yourself has been detected. "
			 "Please use 'wakeup' instead. ");
		fiber_cancel(fiber);
		return;
	}

	if (callee->caller != &sched && callee->caller != caller) {
		say_warn("An attempt to resume an attached fiber "
			 "from a different fiber has been detected: "
			 "callee %u (%s), origin caller %u (%s), new caller %u (%s). "
			 "Please detach %u (%s) first and/or use 'wakeup'.",
			 callee->fid, callee->name,
			 callee->caller->fid, callee->caller->name,
			 fiber->fid, fiber->name,
			 callee->fid, callee->name);
		fiber_cancel(fiber);
		return;
	}

	fiber_change_state(FIBER_PAUSED);

	callee->caller = caller;
	callee->args_format = args_format;
	va_copy(callee->args, ap);

	if (!call_from_sched) {
		/* Transfer to sched */
		fiber_wakeup_next(callee);
		fiber_transfer(&sched);
	} else {
		/* Transfer directly to callee */
		fiber_transfer(callee);
	}
	va_end(callee->args);

	fiber_change_state(FIBER_RESUMED);

	if (!call_from_sched) {
		fiber_testcancel();
	}
}

void
fiber_resume(struct fiber *callee, const void *args_format, ...)
{
	va_list ap;
	va_start(ap, args_format);
	fiber_vresume(callee, args_format, ap);
	va_end(ap);
}

void
fiber_vyield(const void *args_format, va_list ap)
{
	struct fiber *caller = fiber;
	assert(caller != &sched);
	(void) caller;
	struct fiber *callee = fiber->caller;
	assert(callee != NULL);

	fiber_change_state(FIBER_PAUSED);

	callee->args_format = args_format;

	if (callee != &sched) {
		fiber_wakeup_next(callee);
	}

	/* Transfer to sched */
	va_copy(callee->args, ap);
	fiber_transfer(&sched);
	va_end(callee->args);

	fiber_change_state(FIBER_RESUMED);
}

void
fiber_yield(const void *args_format, ...)
{
	va_list ap;
	va_start(ap, args_format);
	fiber_vyield(args_format, ap);
	va_end(ap);
}

void
fiber_detach(void)
{
	if (fiber->caller == &sched)
		return;

	fiber_wakeup(fiber->caller);
	fiber->caller = &sched;
	fiber->sid = 0;
	// fiber_sleep(FIBER_TIMEOUT_INFINITY);
}

/** Interrupt a synchronous wait of a fiber inside the event loop.
 * We do so by keeping an "async" event in every fiber, solely
 * for this purpose, and raising this event here.
 */

void fiber_wakeup2(struct fiber *f, bool head)
{
	assert(fiber_state(f) < FIBER_STOPPED);
	if (f->flags & FIBER_CANCEL) {
		panic("Attempt to wakeup cancelled fiber: %u (%s)",
			 f->fid, f->name);
		return;
	}

	if (f == &sched)
		return;

	/* Do not change the position in the ready_fibers list if f
	 * is already there */
	if (!rlist_empty(&f->ready_link))
		return;

	if (rlist_empty(&ready_fibers))
		ev_async_send(&ready_async);

	if (head) {
		rlist_move_entry(&ready_fibers, f, ready_link);
	} else {
		rlist_move_tail_entry(&ready_fibers, f, ready_link);
	}
}

void
fiber_wakeup_next(struct fiber *f)
{
	fiber_wakeup2(f, true);
}

void
fiber_wakeup(struct fiber *f)
{
	fiber_wakeup2(f, false);
}

void
fiber_cancel(struct fiber *f)
{
	assert(fiber_state(f) != FIBER_DESTROYED);
	assert(!(f->flags & FIBER_CANCEL));

	f->flags |= FIBER_CANCEL;

	if (f == fiber) {
		fiber_testcancel();
		return;
	}

	if (fiber_state(f) == FIBER_CREATED) {
		assert(f->caller == &sched);
		if (f->refs == 0) {
			fiber_zombificate(f);
		}
		return;
	}

	/*
	* The subject fiber is passing through a wait
	* point and can be kicked out of it right away.
	*/

	struct fiber *caller = f->caller;
	f->caller = fiber;

	if (f->flags & FIBER_CANCELLABLE) {
		fiber_change_state(FIBER_PAUSED);
		fiber_transfer(f);
		fiber_change_state(FIBER_RESUMED);
	} else {
		rlist_del(&fiber->ready_link);
		fiber_sleep(FIBER_TIMEOUT_INFINITY);
	}

	if (caller != &sched) {
		fiber_wakeup(caller);
	}

	fiber_testcancel(); /* Check if we're ourselves cancelled. */
}

void
fiber_testcancel(void)
{
	if (fiber_flag(fiber, FIBER_CANCEL))
		tnt_raise(FiberCancelException);
}

static void
fiber_schedule_timeout(EV_A_ ev_watcher *watcher)
{
	assert(fiber == &sched);
	struct { struct fiber *f; bool timed_out; } *state = watcher->data;
	state->timed_out = true;

	fiber_change_state(FIBER_PAUSED);
	fiber_transfer(state->f);
	fiber_change_state(FIBER_RESUMED);

	fiber_testcancel();
}

/**
 * @brief yield & check timeout
 * @return true if timeout exceeded
 */
bool
fiber_sleep(ev_tstamp delay)
{
	assert(fiber != &sched);

	fiber_ref(fiber, 1);
	struct ev_timer timer;
	ev_timer_init(&timer, (void *)fiber_schedule_timeout, delay, 0);
	struct { struct fiber *f; bool timed_out; } state = { fiber, false };
	timer.data = &state;
	ev_timer_start(&timer);

	fiber_change_state(FIBER_PAUSED);
	fiber_transfer(&sched);
	fiber_change_state(FIBER_RESUMED);

	ev_timer_stop(&timer);
	fiber_ref(fiber, -1);

	fiber_testcancel();
	return state.timed_out;
}

/** Wait for a forked child to complete.
 * @note: this is a cancellation point (@sa fiber_testcancel()).
 * @return process return status
*/
int
fiber_wait_for_child(pid_t pid)
{
	fiber_ref(fiber, 1);
	ev_child cw;
	ev_init(&cw, (void *)fiber_schedule);
	ev_child_set(&cw, pid, 0);
	cw.data = fiber;
	ev_child_start(&cw);
	rlist_del_entry(fiber, ready_link);
	fiber_sleep(FIBER_TIMEOUT_INFINITY);
	ev_child_stop(&cw);
	int status = cw.rstatus;
	fiber_ref(fiber, -1);
	assert(fiber->state < FIBER_STOPPED);
	fiber_testcancel();
	return status;
}

void
fiber_schedule(ev_watcher *watcher, int event __attribute__((unused)))
{
	assert(fiber == &sched);
	struct fiber *callee = watcher->data;

	fiber_change_state(FIBER_PAUSED);
	fiber_transfer(callee);
	fiber_testcancel();
	fiber_change_state(FIBER_RESUMED);
}

static void
fiber_ready_async(void)
{
#if defined(DEBUG)
	say_debug("fiber_ready_async:");
	struct fiber *f;
	rlist_foreach_entry(f, &ready_fibers, ready_link) {
		say_debug("  %u %s", f->fid, f->name);
	}
#endif /* defined(DEBUG) */

	while(!rlist_empty(&ready_fibers)) {
		struct fiber *f =
			rlist_first_entry(&ready_fibers, struct fiber, ready_link);
		rlist_del_entry(f, ready_link);

		fiber_change_state(FIBER_PAUSED);
		fiber_transfer(f);
		fiber_change_state(FIBER_RESUMED);
	}
}

struct fiber *
fiber_find(uint32_t fid)
{
	struct mh_i32ptr_node_t node = { .key = fid };
	mh_int_t k = mh_i32ptr_get(fiber_registry, &node, NULL, NULL);

	if (k == mh_end(fiber_registry))
		return NULL;
	return mh_i32ptr_node(fiber_registry, k)->val;
}

static void
register_fid(struct fiber *fiber)
{
	int ret;
	struct mh_i32ptr_node_t node = { .key = fiber -> fid, .val = fiber };
	mh_i32ptr_put(fiber_registry, &node, NULL, NULL, &ret);
}

static void
unregister_fid(struct fiber *fiber)
{
	struct mh_i32ptr_node_t node = { .key = fiber->fid };
	mh_i32ptr_remove(fiber_registry, &node, NULL, NULL);
}

void
fiber_gc(void)
{
	if (palloc_allocated(fiber->gc_pool) < 128 * 1024) {
		palloc_reset(fiber->gc_pool);
		return;
	}

	prelease(fiber->gc_pool);
}


/** Destroy the currently active fiber and prepare it for reuse.
 */

static void
fiber_zombificate(struct fiber *f)
{
	assert(f->refs == 0);
	rlist_del(&f->ready_link);
	f->caller = NULL;
	fiber_set_name(f, "zombie");
	f->body = NULL;
	f->args_format = NULL;
	memset(&f->args, 0, sizeof(f->args));
	unregister_fid(f);
	f->fid = 0;
	f->sid = 0;
	f->state = FIBER_DESTROYED;
	f->flags = 0;
	f->refs = 0;
	prelease(f->gc_pool);
	rlist_move_entry(&zombie_fibers, f, link);
}

static void
fiber_loop(void *data __attribute__((unused)))
{
	for (;;) {
		assert(fiber != NULL && fiber->body != NULL && fiber->fid != 0);

		fiber_ref(fiber, 1);

		@try {
			fiber_change_state(FIBER_STARTED);
			fiber_change_state(FIBER_RESUMED);
			fiber->body();
		} @catch (FiberCancelException *e) {
			say_info("fiber `%s' has been cancelled", fiber->name);
			say_info("fiber `%s': exiting", fiber->name);
		} @catch (tnt_Exception *e) {
			[e log];
		} @catch (id e) {
			say_error("fiber `%s': exception `%s'",
				fiber->name, object_getClassName(e));
			panic("fiber `%s': exiting", fiber->name);
		}

		bool in_cancel = (fiber->flags & FIBER_CANCEL);
		struct fiber *caller = fiber->caller;
		assert(caller != NULL);

		@try {
			fiber_change_state(FIBER_PAUSED);
			fiber_change_state(FIBER_STOPPED);
		} @catch(id) {
			/* Ignore exceptions from hooks when a fiber
			 * is stopping */
		}

		fiber_ref(fiber, -1);

		/* A special case for synchronous fiber_cancel */
		if (in_cancel) {
			fiber_transfer(caller);
			continue;
		}

		if (caller != &sched) {
			fiber_wakeup(caller);
		}

		fiber_transfer(&sched); /* give control back to scheduler */
	}
}

/** Set fiber name.
 *
 * @param[in] name the new name of the fiber. Truncated to
 * FIBER_NAME_MAXLEN.
*/

void
fiber_set_name(struct fiber *fiber, const char *name)
{
	assert(name != NULL);
	snprintf(fiber->name, sizeof(fiber->name), "%s", name);
	palloc_set_name(fiber->gc_pool, fiber->name);
}

struct fiber *
fiber_new(const char *name, void (*body) (void))
{
	struct fiber *fiber = NULL;

	if (!rlist_empty(&zombie_fibers)) {
		fiber = rlist_first_entry(&zombie_fibers, struct fiber, link);
		rlist_move_entry(&fibers, fiber, link);
	} else {
		fiber = palloc(eter_pool, sizeof(*fiber));

		memset(fiber, 0, sizeof(*fiber));
		tarantool_coro_init(&fiber->coro, fiber_loop, NULL);

		fiber->gc_pool = palloc_create_pool("");

		rlist_add_entry(&fibers, fiber, link);
		rlist_init(&fiber->ready_link);
	}


	fiber->refs = 0;
	fiber->body = body;

	/* fids from 0 to 100 are reserved */
	if (++last_used_fid < 100)
		last_used_fid = 100;
	fiber->fid = last_used_fid;
	fiber->sid = 0;
	fiber->state = FIBER_CREATED;
	fiber->flags = 0;
	fiber->caller = &sched;
	fiber->refs = 0;
	memset(fiber->hook_sizes, 0, sizeof(fiber->hook_sizes));
	memset(fiber->hooks, 0, sizeof(fiber->hooks));
	fiber_set_name(fiber, name);
	register_fid(fiber);

	return fiber;
}

void
fiber_ref(struct fiber *fiber, int count)
{
#if 0
	say_debug("ref (%u %s) %d => %d", fiber->fid, fiber->name,
		  count, fiber->refs + count);
#endif
	assert(fiber->refs + count >= 0);
	fiber->refs += count;

	if (fiber->refs == 0)
		fiber_zombificate(fiber);
}

/**
 * Free as much memory as possible taken by the fiber.
 *
 * @note we can't release memory allocated via palloc(eter_pool, ...)
 * so, struct fiber and some of its members are leaked forever.
 */
void
fiber_destroy(struct fiber *f)
{
	if (f == fiber) /* do not destroy running fiber */
		return;
	if (strcmp(f->name, "sched") == 0)
		return;

	rlist_del(&f->ready_link);
	palloc_destroy_pool(f->gc_pool);
	tarantool_coro_destroy(&f->coro);
}

void
fiber_destroy_all()
{
	struct fiber *f;
	rlist_foreach_entry(f, &fibers, link)
		fiber_destroy(f);
	rlist_foreach_entry(f, &zombie_fibers, link)
		fiber_destroy(f);
}

int
fiber_add_hook(struct fiber *f, enum fiber_state state, fiber_hook_cb_t cb)
{
	assert(state > FIBER_CREATED && state < FIBER_DESTROYED);

	size_t hook = state - FIBER_CREATED - 1;

	if (unlikely(f->hook_sizes[hook] >= FIBER_HOOKS_MAX))
		return ENOMEM;

	f->hooks[hook][f->hook_sizes[hook]] = cb;
	f->hook_sizes[hook]++;

	return 0;
}

int
fiber_remove_hook(struct fiber *f, enum fiber_state state, fiber_hook_cb_t cb)
{
	assert(state > FIBER_CREATED && state < FIBER_DESTROYED);

	size_t hook = state - FIBER_CREATED - 1;
	for (size_t i = 0; i < f->hook_sizes[hook]; i++) {
		if (f->hooks[hook][i] != cb)
			continue;

		memmove(f->hooks[hook] + i, f->hooks[hook] + i + 1,
			sizeof(*f->hooks[hook]) * (FIBER_HOOKS_MAX - i - 1));
		f->hook_sizes[hook]--;
		return 0;
	}

	return EINVAL;
}

static void
fiber_info_print(struct tbuf *out, struct fiber *fiber)
{
	void *stack_top = fiber->coro.stack + fiber->coro.stack_size;

	tbuf_printf(out, "  - fid: %4i" CRLF, fiber->fid);
	tbuf_printf(out, "    name: %s" CRLF, fiber->name);
	tbuf_printf(out, "    stack: %p" CRLF, stack_top);
#ifdef ENABLE_BACKTRACE
	tbuf_printf(out, "    backtrace:" CRLF "%s",
		    backtrace(fiber->last_stack_frame,
			      fiber->coro.stack, fiber->coro.stack_size));
#endif /* ENABLE_BACKTRACE */
}

void
fiber_info(struct tbuf *out)
{
	struct fiber *fiber;

	tbuf_printf(out, "fibers:" CRLF);

	rlist_foreach_entry(fiber, &fibers, link)
		fiber_info_print(out, fiber);
	rlist_foreach_entry(fiber, &zombie_fibers, link)
		fiber_info_print(out, fiber);
}

void
fiber_init(void)
{
	rlist_init(&fibers);
	rlist_init(&ready_fibers);
	rlist_init(&zombie_fibers);
	fiber_registry = mh_i32ptr_init();

	memset(&sched, 0, sizeof(sched));
	sched.fid = FIBER_SCHED_FID;
	sched.gc_pool = palloc_create_pool("");
	fiber_set_name(&sched, "sched");

	fiber = &sched;
	last_used_fid = 100;

	sched.caller = &sched;
	rlist_init(&sched.ready_link);
	sched.state = FIBER_CREATED;
	sched.refs = 0;
	fiber_ref(&sched, 1);
	fiber_change_state(FIBER_STARTED);
	fiber_change_state(FIBER_RESUMED);

	ev_async_init(&ready_async, (void *)fiber_ready_async);
	ev_async_start(&ready_async);
}

void
fiber_free(void)
{
	ev_async_stop(&ready_async);
	/* Only clean up if initialized. */
	if (fiber_registry) {
		fiber_destroy_all();
		mh_i32ptr_destroy(fiber_registry);
	}

	// fiber_ref(&sched, -1);
}
