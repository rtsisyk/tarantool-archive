#include <stdio.h>

#include "unit.h"

#include <tarantool.h>
#include <util.h>
#include <exception.h>
#include <palloc.h>

#define DEBUG 1
#include <fiber.h>

void
_say(int level, const char *filename, int line, const char *error, const char *format, ...)
{
	(void) level;
	(void) filename;
	(void) line;
	(void) error;

	va_list ap;
	va_start(ap, format);
	printf("%3u/%s: ", fiber->fid, fiber->name);
	vprintf(format, ap);
	va_end(ap);
	printf("\n");
	fflush(stdout); /* force flush, strange that \n does not work */
}

/*
 * test_simple
 */

static void
simple_body(void)
{
	say_info("HEY!");
}


static void
sleep_body()
{
	while (true) {
		fiber_sleep(1.0);
	}
}

static void
test_simple(void)
{
	header();
	struct fiber *f = fiber_new("simple", simple_body);
	fiber_resume(f, NULL);
	footer();
}

/*
 * test_add
 */

static const int ADD_CALL_ARGS_TAG = 0;
static const int ADD_RET_ARGS_TAG = 0;

static void
add_body(void)
{
	while (true) {
		fiber_testcancel();
		assert(fiber_args_format() == &ADD_CALL_ARGS_TAG);
		va_list ap;
		fiber_args_start(ap);
		int a = va_arg(ap, int);
		int b = va_arg(ap, int);
		fiber_args_end(ap);

		int r = a + b;
		fiber_yield(&ADD_RET_ARGS_TAG, r);
	}
}

static void
test_add()
{
	header();

	struct fiber *add = fiber_new("add", add_body);
	fiber_set_flag(add, FIBER_CANCELLABLE);

	for (int a = 0, b = 1; a < 20; a += 3, b += 2) {
		say_info("----");
		say_info("add(%d, %d)", a, b);
		fiber_resume(add, &ADD_CALL_ARGS_TAG, a, b);
		assert(fiber_args_format() == &ADD_RET_ARGS_TAG);
		va_list ap;
		fiber_args_start(ap);
		int r = va_arg(ap, int);
		fiber_args_end(ap);
		say_info("add(%d, %d) => %d\n", a, b, r);
	}

	fiber_cancel(add);

	footer();
}

/*
 * test_resume_sleep
 */

static void
sleep_yield_body(void)
{
	while (true) {
		fiber_sleep(0.1);
		say_info("YIELD");
		fiber_yield(NULL);
	}
}

static void
test_resume_sleep_yield(void)
{
	header();
	struct fiber *f = fiber_new("sleep_yield", sleep_yield_body);
	fiber_set_flag(f, FIBER_CANCELLABLE);

	struct fiber *noise1 = fiber_new("simple1", simple_body);
	struct fiber *noise2 = fiber_new("simple2", simple_body);
	struct fiber *noise3 = fiber_new("simple3", simple_body);

	fiber_resume(f, NULL);
	say_info("RESUME");
	fiber_wakeup(noise1);
	fiber_resume(f, NULL);
	say_info("RESUME");
	fiber_wakeup(noise2);
	fiber_wakeup(noise3);
	fiber_resume(f, NULL);
	say_info("RESUME");

	fiber_cancel(f);
	footer();
}

/*
 * test_cancel_xxx
 */

static const int TEST_CANCEL_SLEEP_BODY_ARG_TAG = 0;

static void
test_cancel_sleepy_body()
{
	header();

	assert(fiber_args_format() == &TEST_CANCEL_SLEEP_BODY_ARG_TAG);
	va_list ap;
	fiber_args_start(ap);
	int fast = va_arg(ap, int);
	fiber_args_end(ap);

	const int COUNT = 2;
	struct fiber *fibers[COUNT];

	say_info("schedule begin");
	for (int i = 0; i < COUNT; i++) {
		fibers[i] = fiber_new("sleep", sleep_body);
		assert(fibers[i] != NULL);
		fiber_wakeup(fibers[i]);
		if (!fast)
			continue;
		fiber_set_flag(fibers[i], FIBER_CANCELLABLE);
	}
	say_info("schedule end");

	say_info("sleep begin");
	fiber_sleep(0.1);
	say_info("sleep end");

	say_info("cancel begin");
	for (int i = 0; i < COUNT; i++) {
		fiber_cancel(fibers[i]);
	}
	say_info("cancel end");
}

static void
test_cancel_sleepy_fast(void)
{
	header();
	struct fiber *f = fiber_new("cancel_sleepy_fast",
				       test_cancel_sleepy_body);
	fiber_resume(f, &TEST_CANCEL_SLEEP_BODY_ARG_TAG, 1U);
	footer();
}

static void
test_cancel_sleepy_slow(void)
{
	header();
	struct fiber *f = fiber_new("cancel_sleepy_fast",
				       test_cancel_sleepy_body);
	fiber_resume(f, &TEST_CANCEL_SLEEP_BODY_ARG_TAG, 1U);
	footer();
}

static void
test_cancel_created(void)
{
	header();

	const int COUNT = 20;
	struct fiber *fibers[COUNT];

	for (int i = 0; i < COUNT; i++) {
		fibers[i] = fiber_new("cancel", simple_body);
		assert(fibers[i] != NULL);
	}

	for (int i = 0; i < COUNT; i++) {
		fiber_cancel(fibers[i]);
	}

	footer();
}

/*
 * test_detach
 */
static void
detach_body(void)
{
	say_info("DETACH");
	say_info(" // now our caller is sched");
	say_info(" // previous caller is added to queue (last)");
	fiber_detach();

	say_info("YIELD");
	say_info(" // sched will resume fibers in FIFO order: simple1,2,3 -> main");
	/* return to sched -> noisex */
	fiber_yield(NULL);
}

static void
test_detach(void)
{
	header();
	struct fiber *f = fiber_new("detach", detach_body);

	struct fiber *noise1 = fiber_new("simple1", simple_body);
	struct fiber *noise2 = fiber_new("simple2", simple_body);
	struct fiber *noise3 = fiber_new("simple3", simple_body);

	fiber_wakeup(noise1);
	fiber_wakeup(noise2);
	fiber_wakeup(noise3);
	fiber_resume(f, NULL);
	say_info("RESUME");
	say_info("  // sched woke us up because callee has detached");

	footer();
}

/*
 * test_resume_self
 */

static void
resume_self_body(void)
{
	fiber_resume(fiber_self(), NULL);
}


static void
test_resume_self(void)
{
	struct fiber *f = fiber_new("resume_self", resume_self_body);
	fiber_resume(f, NULL);
}

/*
 * test_resume_loop
 */

static struct fiber *loop1;
static struct fiber *loop2;

static void
resume_loop_body1(void)
{
	fiber_resume(loop2, NULL);
}

static void
resume_loop_body2(void)
{
	fiber_resume(loop1, NULL);
}


static void
test_resume_loop(void)
{
	loop1 = fiber_new("loop1", resume_loop_body1);
	loop2 = fiber_new("loop2", resume_loop_body2);

	fiber_resume(loop1, NULL);

}

static void
sleep_timeout_body(void)
{
	bool is_timeout = fiber_sleep(FIBER_TIMEOUT_INFINITY);
	say_warn("is_timeout = %d", is_timeout);
}

/*
 * test_sleep_timeout
 */
static void
test_sleep_timeout(void)
{
	header();

	struct fiber *f = fiber_new("sleep_timeout", sleep_timeout_body);
	fiber_wakeup(f);
	fiber_sleep(0.1);
	fiber_resume(f, NULL);

	footer();
}

void
run(void)
{
	test_simple();
	test_add();
	test_resume_sleep_yield();
	test_cancel_sleepy_fast();
	test_cancel_sleepy_slow();
	test_cancel_created();
	test_detach();
	test_resume_self();
	test_resume_loop();
	test_sleep_timeout();
}


static struct fiber *main_fiber;

static void
idle(struct ev_idle *w, int revents)
{
	(void) w;
	(void) revents;

	if (fiber_state(main_fiber) >= FIBER_STOPPED) {
		ev_break(EVBREAK_ALL);
		return;
	}
}

int
main(void)
{
	ev_default_loop(EVFLAG_AUTO);

	palloc_init();
	fiber_init();

	struct ev_idle idle_watcher;
	ev_idle_init (&idle_watcher, idle);

	main_fiber = fiber_new("main", run);

	ev_idle_start(&idle_watcher);
	fiber_resume(main_fiber, NULL);

	say_info("ev enter loop");
	ev_loop(0);
	say_info("ev exit loop");

	fiber_free();
	palloc_free();

	say_warn("EXIT");

	return 0;
}

