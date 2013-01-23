#ifndef TARANTOOL_FIBER_H_INCLUDED
#define TARANTOOL_FIBER_H_INCLUDED
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

/**
* @file
* @brief Fiber library
*/

#include "config.h"

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <tarantool_ev.h>
#include <sys/types.h> /* pid_t */

#include <coro.h>
#include <exception.h>
#include <rlist.h>

enum {
	/** Maximum length of the fiber name */
	FIBER_NAME_MAXLEN = 32,
	/** fid of the scheduler **/
	FIBER_SCHED_FID = 1
};

/**
 * @brief Inifity timeout for fiber_sleep
 * @see fiber_sleep
 */
extern const ev_tstamp FIBER_TIMEOUT_INFINITY;

/**
 * @brief The state of a fiber
 */
enum fiber_state {
	/** Fiber is just created by fiber_create */
	FIBER_CREATED,
	/** Fiber's body is started */
	FIBER_STARTED,
	/** Fiber is running */
	FIBER_RESUMED,
	/** Fiber is paused (control has been transferred to another fiber) */
	FIBER_PAUSED,
	/** Fiber's body is finished */
	FIBER_STOPPED,
	/** Fiber is destroyed and cannot be used anymore */
	FIBER_DESTROYED
};

/**
 * @brief Fiber flags
 */
enum fiber_flags {
	/** This fiber can be cancelled synchronously. */
	FIBER_CANCELLABLE    = (1 << 1),
	/** Indicates that a fiber has been cancelled. */
	FIBER_CANCEL         = (1 << 2),
	/** This fiber was created via stored procedures API. */
	FIBER_USER_MODE      = (1 << 3)
};

/** This exception is thrown by method that marked as "cancellation point" when
 * a fiber is cancelled.
 */
@interface FiberCancelException: tnt_Exception
@end

struct palloc_pool;

/**
 * @brief The Fiber
 */
struct fiber {
	/** @cond false **/
#ifdef ENABLE_BACKTRACE
	void *last_stack_frame;
#endif
	struct tarantool_coro coro;
	/* A garbage-collected memory pool. */
	struct palloc_pool *gc_pool;
	/** Fiber id. */
	uint32_t fid;

	/** Fiber state */
	enum fiber_state state;

	/** Fiber flags */
	enum fiber_flags flags;

	/** Session identifier */
	uint32_t sid;

	struct rlist link;
	struct rlist ready_link;

	/* ASCIIZ name of this fiber. */
	char name[FIBER_NAME_MAXLEN];

	/** Caller */
	struct fiber *caller;
	/** Body function */
	void (*body) (void);
	/** Arguments format */
	const void *args_format;
	/** Arguments list */
	va_list args;

	/** Reference counter */
	uint16_t refs;
	/** @endcond **/
};

/** @cond false **/
extern __thread struct fiber *fiber;
/** @endcond **/

/**
 * @brief Initialize the library
 */
void
fiber_init(void);

/**
 * @brief Denitialize the library
 */
void
fiber_free(void);

/**
 * @brief Create a new fiber with name @a name and function @a body.
 *
 * Takes a fiber from fiber cache, if it's not empty.
 * Can fail only if there is not enough memory for
 * the fiber structure or fiber stack.
 *
 * The created fiber automatically returns itself to the fiber cache when its
 * reference counter is set to zero.
 *
 * @param name of a new fiber
 * @param body a function to execute when fiber is resumed at first time.
 * @return pointer to a new fiber
 */
struct fiber *
fiber_new(const char *name, void (*body) (void));

/**
 * @brief Return the current fiber
 * @return the current fiber
 */
inline struct fiber *
fiber_self(void)
{
	return fiber;
}

/**
 * @brief Return the fid of @a f
 * @param f fiber
 * @return the fid of the @a f
 */
inline uint32_t
fiber_id(const struct fiber *f)
{
	return f->fid;
}

/**
 * @brief Change the name of @a f
 * @param f fiber
 * @param the name new value
 */
void
fiber_set_name(struct fiber *f, const char *name);

/**
 * @brief Return the name of @a f
 * @param f fiber
 * @return the name of @a f
 * @see fiber_set_name
 */
inline const char *
fiber_name(const struct fiber *f)
{
	return f->name;
}

/**
 * @brief Attach @a f to a session identified by sid.
 *
 * Session id of the session the fiber is running
 * on behalf of. The concept of an associated session
 * is similar to the concept of controlling tty
 * in a UNIX process. When a fiber is created,
 * its sid is 0. If it's running a request on behalf
 * of a user connection, it's sid is changed to module-
 * generated identifier of the session.
 *
 * @param f fiber
 * @param sid session id
 */
inline void
fiber_set_sid(struct fiber *f, uint32_t sid)
{
	f->sid = sid;
}

/**
 * @brief Return the session id of @f
 * @param f fiber
 * @return the session id of @a f
 * @see fiber_set_sid
 */
inline uint32_t
fiber_sid(const struct fiber *f)
{
	return f->sid;
}

/**
 * @brief Change the reference counter of @a f. The reference counter
 * is automatically incremented when fiber started (fiber_state => STARTED)
 * and automatically decremented when fiber stopped. Fiber with zero ref
 * counter is automatically recycled and reused in subsequents calls to
 * @link fiber_new @endlink. If you use fiber pointer somewhere
 * (for example, in EV watchers or in Lua), please do not forget to update
 * this counter.
 * @param f fiber
 * @param count
 */
void
fiber_ref(struct fiber *f, int count);

/**
 * @brief Return the current state of @a f
 * @param f fiber
 * @return the current state of @a f
 * @see fiber_state
 */
inline enum fiber_state
fiber_state(const struct fiber *f)
{
	return f->state;
}

/**
 * @brief Return @a true if @a flag are set in @a f.
 * @param f fiber
 * @param flag the flag to check
 * @return true if @a flag are set in @a f
 * @see enum fiber_flags
 */
inline bool
fiber_flag(const struct fiber *f, enum fiber_flags flag)
{
	return (f->flags & flag);
}

/**
 * @brief Set bit @a flag in the @a f
 * @param f fiber
 * @param the bit flag to set
 * @return previous state of the flag
 * @see enum fiber_flags
 */
inline bool
fiber_set_flag(struct fiber *f, enum fiber_flags flag)
{
	bool prev = fiber_flag(f, flag);
	f->flags |= flag;
	return prev;
}

/**
 * @brief Clear @a flag in the @a f
 * @param f fiber
 * @param the bit flag to clear
 * @return previous state of the flag
 * @see enum fiber_flags
 */
inline bool
fiber_clear_flag(struct fiber *f, enum fiber_flags flag)
{
	bool prev = fiber_flag(f, flag);
	f->flags &= ~flag;
	return prev;
}

/**
 * @brief Return a format of the current fibers arguments. A non-NULL value
 * indicates that some arguments were passed by the caller of the current fiber
 * using @link fiber_resume @endlink or were returned from the child (callee)
 * fiber using @link fiber_yield @endlink. The value itself is an user-specific
 * and may be used to identify the number of arguments, its types and sizes.
 *
 * A typical workflow example:
 * @code
 * // In this example we do not want to define any structs that should describe
 * // arguments and just use an address of a variable as an indentifer.
 * static int MY_FIBER_BODY_CALL_ARGS_TAG = 0;
 * static int MY_FIBER_BODY_RET_ARGS_TAG = 0;
 *
 * static void
 * my_fiber_body(void) {
 *	// perform some format checks here using the address of the variable
 *	assert(fiber_args_format() == &MY_FIBER_BODY_CALL_ARGS_TAG);
 *
 *	// init va_list and copy the fiber's arguments to it
 *	va_list ap;
 *	fiber_args_start(ap);
 *
 *	// extract first arg by pointer (value itself is on the caller stack)
 *	struct data *a = va_arg(ap, struct data *);
 *	// extract second arg by value (copied to our stack)
 *	int b = va_arg(ap, int);
 *	// free resources allocated by va_list
 *	fiber_args_end(ap);
 *
 *	// return one argument
 *	struct data c;
 *	fiber_yield(&MY_FIBER_BODY_RET_ARGS_TAG, &c);
 *	// a is not valid anymore (passed by the pointer)
 *	// b is valid (was copied)
 *	...
 * }
 *
 * void caller_body(void) {
 *	struct data a;
 *	int b;
 *	...
 *	struct fiber *f = fiber_create("test", my_fiber_body);
 *	fiber_resume(f, &MY_FIBER_BODY_CALL_ARGS_TAG, &a, b);
 *
 *	// perform some format checks here
 *	assert(fiber_args_format() == &MY_FIBER_BODY_RET_ARGS_TAG);
 *	va_list ap;
 *	fiber_args_start(ap);
 *	// extract by pointer (data itself is still on the callee's stack
 *	struct data *result = va_arg(ap, struct data *);
 *	fiber_args_end(ap);
 * }
 * @endcode
 *
 * @note Arguments passed using the stack of a fiber that has called
 * @link fiber_resume @endlink or @link fiber_yield @endlink). Therefore all
 * values are valid as long as the control flow is not transferred to another
 * fiber. You can implement any custom logic for handling arguments, but do not
 * forget to process it before a next yield point.
 *
 * @note All transfer function except resume/yield (@link fiber_sleep @endlink,
 * @link fiber_cancel @endlink) always clear arguments and set the format to
 * NULL. All non-transfer functions such as @link fiber_wakeup @endlink,
 * @link fiber_detach @endlink and EV watchers does not touch arguments.
 *
 * @see fiber_resume
 * @see fiber_yield
 * @return a format of arguments of the fiber
 */
inline const void *
fiber_args_format(void)
{
	return fiber_self()->args_format;
}

/**
 * @brief Return @a true if the current fiber has arguments
 * (i.e. @a fiber_args_format is not NULL).
 *
 * @return @a true if the current fiber has arguments
 * @see fiber_args_format
 */
inline bool
fiber_has_args(void)
{
	return (fiber_self()->args_format != NULL);
}

/**
 * @brief Initialize @a ap with arguments of the current fiber for subsequent
 * use by @link va_arg() @endlink. Each invocation to
 * @link fiber_args_start @endlink must match by a corresponding invocation of
 * @link fiber_args_end @endlink method.
 *
 * @param ap va_list to initialize
 * @see fiber_args_format
 * @see va_start
 */
inline void
fiber_args_start(va_list ap)
{
	assert(fiber_has_args());
	va_copy(ap, fiber_self()->args);
}

/**
 * @brief Clear @a ap. Each invocation to @link fiber_args_start @endlink
 * must match by a corresponding invocation of @link fiber_args_end @endlink
 * method.
 *
 * @see va_end
 * @see fiber_args_formats
 * @param ap
 */
inline void
fiber_args_end(va_list ap)
{
	assert(fiber_has_args());
	va_end(ap);
}

/**
 * @brief Transfer the control to @a callee with passing arguments identified
 * by @a args_format. The current fiber will be blocked until @a callee will
 * yield or will be cancelled.
 *
 * The first time you resume a fiber, it starts running its body. The callee
 * fiber can use @link fiber_yield @endlink to return the control to its caller.
 * If the callee has yielded, @link fiber_resume @endlink resumes it from a
 * point there it was yielded. A combination of resume/yield methods
 * can be used to organize producer-consumer workflows.
 *
 * Each alive fiber has only one associated caller. If the caller is not the
 * scheduler then the fiber is called "attached". An attached fiber transfers
 * the control to its caller only in the next three cases:
 *  a) By invoking @link fiber_yield @endlink
 *  b) On cancel
 *  c) On finish
 * In all other cases the control is returned to the scheduler, but the fiber
 * stays attached to its caller. Only @link fiber_resume @endlink and
 * @link fiber_detach @endlink (see below) methods change the caller of a fiber.
 *
 * A "detached" fiber loses the connection with its caller and always returns
 * back to the scheduler. The method @link fiber_detach @endlink can be used to
 * change the caller of a fiber to "sched". If an attached fiber has invoked
 * @link fiber_detach @endlink, the control IS NOT tranferred, but an original
 * caller will be woken up later by the scheduler. If a fiber is detached then
 * @link fiber_resume @endlink will change the caller value and attach
 * the callee fiber.
 *
 * An attempt to call @link fiber_resume @endlink on an attached fiber from
 * a different caller IS NOT supported intentionally. Please use
 * @link fiber_wakeup @endlink to implement such recursive logic.
 *
 * This method transfers control. This is a cancellation point.
 *
 * @note
 *
 * @note If called from the scheduler the method will launch fiber immediately
 * without waiting for next event loop iteration.
 * @param callee fiber to resume
 * @param args_format see @link fiber_args_format @endlink
 * @see fiber_args_format
 */
void
fiber_resume(struct fiber *callee, const void *args_format, ...);

/**
 * @brief The va_list version of @link fiber_resume @endlink.
 * The value of @a ap is undefined after the call.
 * @see stdarg(3)
 * @see fiber_resume
 */
void
fiber_vresume(struct fiber *callee, const void *args_format, va_list ap);

/**
 * @brief Transfers control to the caller of current fiber with passing
 * arguments identified by @a args_format.
 *
 * This method transfers control. This is a cancellation point.
 *
 * @param args_format see @link fiber_args_format @endlink
 * @see fiber_resume
 */
void
fiber_yield(const void *args_format, ...);

/**
 * @brief The va_list version of @link fiber_yield @endlink.
 * The value of @a ap is undefined after the call.
 * @see stdarg(3)
 * @see fiber_yield
 */
void
fiber_vyield(const void *args_format, va_list ap);

/**
 * @brief Detach current fiber from its caller, i.e. set caller of the
 * fiber to be "sched". The original caller will be wake up on subsequents event
 * loop iterations. The method does not transfer control from the current fiber.
 */
void
fiber_detach(void);

/**
* @brief Create a new ev_timer watcher with @a timeout, associate it
* with the current fiber and then transfer control the scheduler.
* The watcher will wake up the fiber on the timer event.
* Fiber's caller is not notified. Subsequents @link fiber_yield @endlink
* in the fiber return control to the caller.
*
* This method transfers control. This is a cancellation point.
* @return @a true if timeout exceeded and fiber was woken up by ev_timer or
* @a false otherwise.
*/
bool
fiber_sleep(ev_tstamp timeout);

/**
 * @brief Ask the scheduler to resume @a f on subsequents event loop iterations.
 * There is no guarantee how many iterations of the event loop it would take.
 * If fiber is waken up after calling this method, its arguments is set to NULL.
 *
 * This method does not transfers control. This is not the cancellation point.
 * @param f
 */
void
fiber_wakeup(struct fiber *f);

/**
 * @brief Create a new ev_child watcher with @a pid, associate it
 * with the current fiber and then transfer control the scheduler.
 * The watcher will wake up the fiber on the event.
 * @param pid a pid of child process
 * @return the pid exit status
 */
int
fiber_wait_for_child(pid_t pid);

void
fiber_gc(void);

/**
 * @brief Find a fiber by its fid
 * @param fid fiber id
 * @return a found fiber or NULL
 */
struct fiber *
fiber_find(uint32_t fid);

/**
 * @brief Cancel the fiber @a f **synchronously**.
 *
 * Note: this is not guaranteed to succeed, and requires a level
 * of cooperation on behalf of the fiber. A fiber may opt to set
 * FIBER_CANCELLABLE to false, and never test that it was
 * cancelled.  Such fiber can not ever be cancelled, and
 * for such fiber this call will lead to an infinite wait.
 * However, fiber_testcancel() is embedded to the rest of fiber_*
 * API (@sa fiber_yield(NULL)), which makes most of the fibers that opt in,
 * cancellable.
 *
 * Currently cancellation can only be synchronous: this call
 * returns only when the subject fiber has terminated.
 *
 * The fiber which is cancelled, has FiberCancelException raised
 * in it. For cancellation to work, this exception type should be
 * re-raised whenever (if) it is caught.
 *
 * @note If the fiber @a f is attached then its caller will be woken up
 * @note Stack resources is always clean up correctly. If you want to be sure
 * that all your external resources is clean up, please use @try @catch blocks
 * on cancellation points.
 */
void
fiber_cancel(struct fiber *f);

/**
 * @brief Test if this fiber is in a cancellable state and was indeed
 * cancelled, and raise an exception (FiberCancelException) if
 * that's the case.
 *
 * This method does not transfers control. This is a cancellation point.
 */
void fiber_testcancel(void);

struct tbuf;
void fiber_info(struct tbuf *out);
void fiber_schedule(ev_watcher *watcher, int event __attribute__((unused)));

#endif /* TARANTOOL_FIBER_H_INCLUDED */
