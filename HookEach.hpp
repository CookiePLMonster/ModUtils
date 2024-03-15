#pragma once

#include <tuple>
#include <utility>

#define HOOK_EACH_FUNC_CTR(name, ctr, origFunc, hook) \
	template<std::size_t Ctr, typename Tuple, std::size_t... I, typename Func> \
	static void _HookEachImpl_##name(Tuple&& tuple, std::index_sequence<I...>, Func&& f) \
	{ \
		(f(std::get<I>(tuple), origFunc<Ctr << 16 | I>, hook<Ctr << 16 | I>), ...); \
	} \
	\
	template<std::size_t Ctr = ctr, typename Vars, typename Func> \
	static void HookEach_##name(Vars&& vars, Func&& f) \
	{ \
		auto tuple = std::tuple_cat(std::forward<Vars>(vars)); \
		_HookEachImpl_##name<Ctr>(std::move(tuple), std::make_index_sequence<std::tuple_size_v<decltype(tuple)>>{}, std::forward<Func>(f)); \
	}

#define HOOK_EACH_FUNC(name, orig, hook) HOOK_EACH_FUNC_CTR(name, 0, orig, hook)
