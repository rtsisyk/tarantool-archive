#ifndef TARANTOOL_REFLECTION_H_INCLUDED
#define TARANTOOL_REFLECTION_H_INCLUDED
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

#include <stddef.h>
#include <assert.h>

#if defined(__cplusplus)
extern "C" {
#endif /* defined(__cplusplus) */

struct type;
struct method;

/**
 * Primitive C types
 */
enum ctype {
	CTYPE_VOID = 0,
	CTYPE_INT,
	CTYPE_CONST_CHAR_PTR
};

struct type {
	const char *name;
	const struct type *parent;
	const struct method *methods;
};

/**
 * Determine if the specified object is assignment-compatible with
 * the object represented by type.
 */
#define type_cast(T, obj) ({						\
		const struct type *t = (obj)->type;			\
		T *r = NULL;						\
		for (; t != NULL; t = t->parent) {			\
			if (&type_ ## T == (t)) {			\
				r = (T *) (t);				\
				break;					\
			}						\
		}							\
		(r);							\
	})

#if defined(__cplusplus)
/* Pointer to arbitrary C++ member function */
typedef void (type::*method_thiscall_f)(void);
#endif

enum { METHOD_ARG_MAX = 8 };

struct method {
	const struct type *type;
	const char *name;
	enum ctype rtype;
	enum ctype atype[METHOD_ARG_MAX];
	int nargs;

	union {
		/* Add extra space to get proper struct size in C */
		void *_spacer[2];
#if defined(__cplusplus)
		method_thiscall_f thiscall;
		static_assert(sizeof(thiscall) <= sizeof(_spacer),
			"sizeof(thiscall)");
#endif /* defined(__cplusplus) */
	};
};

#define type_foreach_method(m, method)					\
	for(const struct type *_m = (m); _m != NULL; _m = _m->parent)	\
		for (const struct method *(method) = _m->methods;	\
		     (method)->name != NULL; (method)++)

extern const struct method METHODS_END;

#if defined(__cplusplus)
} /* extern "C" */

/*
 * Begin of C++ syntax sugar
 */

/*
 * Initializer for struct type without methods
 */
inline type
make_type(const char *name, const type *parent)
{
	return (type) { name, parent, &METHODS_END };
}

/*
 * Initializer for struct type with methods
 */
inline type
make_type(const char *name, const type *parent, const method *methods)
{
	return (type) { name, parent, methods };
}

template<typename T> inline enum ctype ctypeof();
template<> inline enum ctype ctypeof<void>() { return CTYPE_VOID; }
template<> inline enum ctype ctypeof<int>() { return CTYPE_INT; }
template<> inline enum ctype ctypeof<const char *>() { return CTYPE_CONST_CHAR_PTR; }

/**
 * Initializer for R (T::*)(void) C++ member methods
 */
template<typename R, typename T> inline method
make_method(const struct type *type, const char *name,
	R (T::*method_arg)(void) const)
{
	/* TODO: sorry, unimplemented: non-trivial designated initializers */
	struct method m;
	m.type = type;
	m.name = name;
	m.rtype = ctypeof<R>();
	m.nargs = 0;
	m.thiscall = (method_thiscall_f) method_arg;
	return m;
}

/**
 * \cond false
 */
template<int N, typename R> inline bool
method_invokable_r(const struct method *method)
{
	if (method->nargs != N)
		return false;
	if (method->rtype != ctypeof<R>())
		return false;
	return true;
}

template<int N, typename R, typename A, typename... Args> inline bool
method_invokable_r(const struct method *method, A a, Args... args)
{
	if (method->atype[N] != ctypeof<A>())
		return false;
	return method_invokable_r<N + 1, R, Args... >(method, args...);
}
/**
 * \endcond false
 */

/**
 * Check if method is invokable with provided argument types
 */
template<typename R, typename... Args, typename T> inline bool
method_invokable(const struct method *method, T *object, Args... args)
{
	// assert(type_cast(type, object));
	(void) object;
	return method_invokable_r<0, R>(method, args...);
}

/**
 * Invoke method with object and provided arguments.
 */
template<typename R, typename... Args, typename T > inline R
method_invoke(const struct method *method, T *object, Args... args)
{
	assert(method_invokable<R>(method, object, args...));
	typedef R (T::*MemberFunction)(Args...);
	return (object->*(MemberFunction) method->thiscall)(args...);
}

#endif /* defined(__cplusplus) */

#endif /* TARANTOOL_REFLECTION_H_INCLUDED */
