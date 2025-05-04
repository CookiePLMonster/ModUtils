#pragma once

// Helper macro to instantiate a set of templated variables/functions and a function hooking multiple places in code en masse.
// This helper is meant to help improve compatibility with different modifications and/or application versions by easily lifting
// assumptions about the similarity of patched call sites and/or variable instances.

// HookEach works by automatically generating duplicate functions and/or variables, with instances templated by an index.
// The required amount of indices is determined automatically from the size of the std::array passed to a genetated HookEach_* function
// when applying the code patches.

// Cases where the code would typically benefit from HookEach:
// 1. Intercepting multiple call sites to the same function. With HookEach, each call site automagically gets its own "original function pointer" variable.
// 2. Intercepting multiple uses of a global variable or a constant. With HookEach, the code doesn't need to worry if some/all of those have been modified by another modification.

// Setting up HookEach for intercepting multiple call sites (the most common case):
// 1. Define a templated original function pointer variable. Template must be of type 'template<std::size_t Index>'.
// 2. Define a templated intercepted function. Template must be of type 'template<std::size_t Index>'.
// 3. Fill the body of an intercepted function, somewhere in that function invoke orgFuncPtr<Index>, where 'orgFuncPtr' is the variable defined in 1.
//    This will invoke a different orgFuncPtr for every instance of an intercepted function.
//    If possible, keep the index-agnostic part of the hook in a separate function, so the templated function stays as small as possible.
// 4. Initialize HookEach by adding HOOK_EACH_INIT(name, orgFuncPtr, patchedFunc), where 'name' is a custom name given to this pair of templated entities.
//    This name will act as a suffix of a generated HookEach_ function.
// 5. When applying code patches, create a std::array<> of call sites to patch, where each entry is a memory address to intercept.
// 6. Call HookEach_Name(array, InterceptCall) to apply code patches.

// For intercepting variables, similar steps can be taken, defining a replacement variable instead of a function in 2.
// A callable other than InterceptCall must also be passed to HookEach_*. This callable will be called for every tuple of (data, original, replaced)
// parameters, where 'data' are the std::array entries, and 'original' and 'replaced' are the variables defined ealier in HOOK_EACH_INIT.
// Additionally, if 'data' is a tuple or a pair, it will be expanded into individual variables and then passed to the callable.

// For more complex cases where identical patches must be applied on multiple arrays of addresses, two approaches can be used:
// 1. Use HOOK_EACH_INIT(name, counter, original, replaced) to define an unique alias with a non-zero counter.
// 2. Specify a non-zero count as a template parameter of HookEach_*.
// In both cases, each unique call then gets its own set of 'original' and 'replaced' instances.

#include <array>
#include <tuple>
#include <utility>
#include <type_traits>

namespace hook_each::details
{
	template <typename T>
	struct is_tuple_like : std::false_type {};

	template <typename... Args>
	struct is_tuple_like<std::tuple<Args...>> : std::true_type {};

	template <typename T1, typename T2>
	struct is_tuple_like<std::pair<T1, T2>> : std::true_type {};
};

#define HOOK_EACH_INIT_CTR(name, ctr, original, replaced) \
	template<std::size_t Ctr, typename T, std::size_t N, typename Func, std::size_t... I> \
	static void hook_each_impl_##name(const std::array<T, N>& elems, Func&& f, std::index_sequence<I...>) \
	{ \
		if constexpr (hook_each::details::is_tuple_like<T>::value) \
		{ \
			(std::apply([&f, &originalInner = original<(Ctr << 16) | I>, &replacedInner = replaced<(Ctr << 16) | I>](auto&&... params) { \
				f(std::forward<decltype(params)>(params)..., originalInner, replacedInner); \
			}, elems[I]), ...); \
		} \
		else \
		{ \
			(f(elems[I], original<(Ctr << 16) | I>, replaced<(Ctr << 16) | I>), ...); \
		} \
	} \
	\
	template<std::size_t Ctr = ctr, typename T, std::size_t N, typename Func> \
	static void HookEach_##name(const std::array<T, N>& elems, Func&& f) \
	{ \
		hook_each_impl_##name<Ctr>(elems, std::forward<Func>(f), std::make_index_sequence<N>{}); \
	}

#define HOOK_EACH_INIT(name, original, replaced) HOOK_EACH_INIT_CTR(name, 0, original, replaced)
