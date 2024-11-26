#pragma once

// Switches:
// _MEMORY_NO_CRT - don't include anything "complex" like ScopedUnprotect or memset
// _MEMORY_DECLS_ONLY - don't include anything but macroes

#define WRAPPER __declspec(naked)
#define DEPRECATED __declspec(deprecated)
#define WRAPARG(a) ((int)a)

#ifdef _MSC_VER
#define EAXJMP(a) { _asm mov eax, a _asm jmp eax }
#define VARJMP(a) { _asm jmp a }
#elif defined(__GNUC__) || defined(__clang__)
#define EAXJMP(a) { __asm__ volatile("mov eax, %0\n" "jmp eax" :: "i" (a)); }
#define VARJMP(a) { __asm__ volatile("jmp %0" :: "m" (a)); }
#endif

#ifdef _MSC_VER
#define NOVMT __declspec(novtable)
#else
#define NOVMT
#endif

#define SETVMT(a) *((uintptr_t*)this) = (uintptr_t)a

#ifndef _MEMORY_DECLS_ONLY

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>
#include <cassert>

#ifndef _MEMORY_NO_CRT
#include <algorithm>
#include <initializer_list>
#include <utility>
#endif

namespace Memory
{
	enum class HookType
	{
		Call,
		Jump,
	};

	template<typename AT>
	inline AT DynBaseAddress(AT address)
	{
		static_assert(sizeof(AT) == sizeof(uintptr_t), "AT must be pointer sized");
	#ifdef _WIN64
		return (ptrdiff_t)GetModuleHandle(nullptr) - 0x140000000 + address;
	#else
		return (ptrdiff_t)GetModuleHandle(nullptr) - 0x400000 + address;
	#endif
	}

	template<typename T, typename AT>
	inline void		Patch(AT address, T value)
	{
		static_assert(sizeof(AT) == sizeof(uintptr_t), "AT must be pointer sized");
		*(T*)address = value;
	}

#ifndef _MEMORY_NO_CRT
	template<typename AT>
	inline void		Patch(AT address, std::initializer_list<uint8_t> list )
	{
		static_assert(sizeof(AT) == sizeof(uintptr_t), "AT must be pointer sized");
		uint8_t* addr = reinterpret_cast<uint8_t*>(address);
		std::copy( list.begin(), list.end(), addr );
	}
#endif

	template<typename AT>
	inline void		Nop(AT address, size_t count)
#ifndef _MEMORY_NO_CRT
	{
		static_assert(sizeof(AT) == sizeof(uintptr_t), "AT must be pointer sized");
		memset((void*)address, 0x90, count);
	}
#else
	{ do {
		*(uint8_t*)address++ = 0x90;
	} while ( --count != 0 ); }
#endif

	template<ptrdiff_t extraBytesAfterOffset = 0, typename Var, typename AT>
	inline void		WriteOffsetValue(AT address, Var var)
	{
		static_assert(sizeof(AT) == sizeof(uintptr_t), "AT must be pointer sized");
		intptr_t dstAddr = (intptr_t)address;
		intptr_t srcAddr;
		memcpy( &srcAddr, std::addressof(var), sizeof(srcAddr) );
		*(int32_t*)dstAddr = static_cast<int32_t>(srcAddr - dstAddr - (4 + extraBytesAfterOffset));
	}

	template<ptrdiff_t extraBytesAfterOffset = 0, typename Var, typename AT>
	inline void		ReadOffsetValue(AT address, Var& var)
	{
		static_assert(sizeof(AT) == sizeof(uintptr_t), "AT must be pointer sized");
		intptr_t srcAddr = (intptr_t)address;
		intptr_t dstAddr = srcAddr + (4 + extraBytesAfterOffset) + *(int32_t*)srcAddr;
		var = {};
		memcpy( std::addressof(var), &dstAddr, sizeof(dstAddr) );
	}

	template<typename AT, typename Func>
	inline void		InjectHook(AT address, Func hook)
	{
		WriteOffsetValue( (intptr_t)address + 1, hook );
	}

	template<typename AT, typename Func>
	inline void		InjectHook(AT address, Func hook, HookType type)
	{
		*(uint8_t*)address = type == HookType::Jump ? 0xE9 : 0xE8;
		InjectHook(address, hook);
	}

	template<typename Func, typename AT>
	inline void		ReadCall(AT address, Func& func)
	{
		ReadOffsetValue( (intptr_t)address+1, func );
	}

	template<typename AT>
	inline void*	ReadCallFrom(AT address, ptrdiff_t offset = 0)
	{
		uintptr_t addr;
		ReadCall( address, addr );
		return reinterpret_cast<void*>( addr + offset );
	}

	constexpr auto InterceptCall = [](auto address, auto&& func, auto&& hook)
	{
		ReadCall(address, func);
		InjectHook(address, hook);
	};

#ifndef _MEMORY_NO_CRT
	inline bool MemEquals(uintptr_t address, std::initializer_list<uint8_t> val)
	{
		const uint8_t* mem = reinterpret_cast<const uint8_t*>(address);
		return std::equal( val.begin(), val.end(), mem );
	}
#endif

	template<typename AT>
	inline AT Verify(AT address, uintptr_t expected)
	{
		static_assert(sizeof(AT) == sizeof(uintptr_t), "AT must be pointer sized");
		assert( uintptr_t(address) == expected );
		return address;
	}

	namespace DynBase
	{
		enum class HookType
		{
			Call,
			Jump,
		};

		using Memory::DynBaseAddress;

		template<typename T, typename AT>
		inline void		Patch(AT address, T value)
		{
			Memory::Patch(DynBaseAddress(address), value);
		}

#ifndef _MEMORY_NO_CRT
		template<typename AT>
		inline void		Patch(AT address, std::initializer_list<uint8_t> list )
		{
			Memory::Patch(DynBaseAddress(address), std::move(list));
		}
#endif

		template<typename AT>
		inline void		Nop(AT address, size_t count)
		{
			Memory::Nop(DynBaseAddress(address), count);
		}

		template<ptrdiff_t extraBytesAfterOffset = 0, typename Var, typename AT>
		inline void		WriteOffsetValue(AT address, Var var)
		{
			Memory::WriteOffsetValue<extraBytesAfterOffset>(DynBaseAddress(address), var);
		}

		template<ptrdiff_t extraBytesAfterOffset = 0, typename Var, typename AT>
		inline void		ReadOffsetValue(AT address, Var& var)
		{
			Memory::ReadOffsetValue<extraBytesAfterOffset>(DynBaseAddress(address), var);
		}

		template<typename AT, typename Func>
		inline void		InjectHook(AT address, Func hook)
		{
			Memory::InjectHook(DynBaseAddress(address), hook);
		}

		template<typename AT, typename Func>
		inline void		InjectHook(AT address, Func hook, HookType type)
		{
			Memory::InjectHook(DynBaseAddress(address), hook, static_cast<Memory::HookType>(type));
		}

		template<typename Func, typename AT>
		inline void		ReadCall(AT address, Func& func)
		{
			Memory::ReadCall(DynBaseAddress(address), func);
		}

		template<typename AT>
		inline void*	ReadCallFrom(AT address, ptrdiff_t offset = 0)
		{
			return Memory::ReadCallFrom(DynBaseAddress(address), offset);
		}

		constexpr auto InterceptCall = [](auto address, auto&& func, auto&& hook)
		{
			Memory::InterceptCall(DynBaseAddress(address), func, hook);
		};

#ifndef _MEMORY_NO_CRT
		inline bool MemEquals(uintptr_t address, std::initializer_list<uint8_t> val)
		{
			return Memory::MemEquals(DynBaseAddress(address), std::move(val));
		}

		template<typename AT>
		inline AT Verify(AT address, uintptr_t expected)
		{
			return Memory::Verify(address, DynBaseAddress(expected));
		}
#endif
	};

	namespace VP
	{
		enum class HookType
		{
			Call,
			Jump,
		};

		using Memory::DynBaseAddress;

		template<typename T, typename AT>
		inline void		Patch(AT address, T value)
		{
			DWORD		dwProtect;
			VirtualProtect((void*)address, sizeof(T), PAGE_EXECUTE_READWRITE, &dwProtect);
			Memory::Patch( address, value );
			VirtualProtect((void*)address, sizeof(T), dwProtect, &dwProtect);
		}

#ifndef _MEMORY_NO_CRT
		template<typename AT>
		inline void		Patch(AT address, std::initializer_list<uint8_t> list )
		{
			DWORD		dwProtect;
			VirtualProtect((void*)address, list.size(), PAGE_EXECUTE_READWRITE, &dwProtect);
			Memory::Patch(address, std::move(list));
			VirtualProtect((void*)address, list.size(), dwProtect, &dwProtect);
		}
#endif

		template<typename AT>
		inline void		Nop(AT address, size_t count)
		{
			DWORD		dwProtect;
			VirtualProtect((void*)address, count, PAGE_EXECUTE_READWRITE, &dwProtect);
			Memory::Nop( address, count );
			VirtualProtect((void*)address, count, dwProtect, &dwProtect);
		}

		template<ptrdiff_t extraBytesAfterOffset = 0, typename Var, typename AT>
		inline void		WriteOffsetValue(AT address, Var var)
		{
			DWORD		dwProtect;

			VirtualProtect((void*)address, 4, PAGE_EXECUTE_READWRITE, &dwProtect);
			Memory::WriteOffsetValue<extraBytesAfterOffset>(address, var);
			VirtualProtect((void*)address, 4, dwProtect, &dwProtect);
		}

		template<ptrdiff_t extraBytesAfterOffset = 0, typename Var, typename AT>
		inline void		ReadOffsetValue(AT address, Var& var)
		{
			Memory::ReadOffsetValue<extraBytesAfterOffset>(address, var);
		}

		template<typename AT, typename Func>
		inline void		InjectHook(AT address, Func hook)
		{
			DWORD		dwProtect;

			VirtualProtect((void*)((DWORD_PTR)address + 1), 4, PAGE_EXECUTE_READWRITE, &dwProtect);
			Memory::InjectHook( address, hook );
			VirtualProtect((void*)((DWORD_PTR)address + 1), 4, dwProtect, &dwProtect);
		}

		template<typename AT, typename Func>
		inline void		InjectHook(AT address, Func hook, HookType type)
		{
			DWORD		dwProtect;

			VirtualProtect((void*)address, 5, PAGE_EXECUTE_READWRITE, &dwProtect);
			Memory::InjectHook( address, hook, static_cast<Memory::HookType>(type) );
			VirtualProtect((void*)address, 5, dwProtect, &dwProtect);
		}

		template<typename Func, typename AT>
		inline void		ReadCall(AT address, Func& func)
		{
			Memory::ReadCall(address, func);
		}

		template<typename AT>
		inline void*	ReadCallFrom(AT address, ptrdiff_t offset = 0)
		{
			return Memory::ReadCallFrom(address, offset);
		}

		constexpr auto InterceptCall = [](auto address, auto&& func, auto&& hook)
		{
			DWORD		dwProtect;

			VirtualProtect((void*)address, 5, PAGE_EXECUTE_READWRITE, &dwProtect);
			Memory::InterceptCall(address, func, hook);
			VirtualProtect((void*)address, 5, dwProtect, &dwProtect);
		};

#ifndef _MEMORY_NO_CRT
		inline bool MemEquals(uintptr_t address, std::initializer_list<uint8_t> val)
		{
			return Memory::MemEquals(address, std::move(val));
		}
#endif

		template<typename AT>
		inline AT Verify(AT address, uintptr_t expected)
		{
			return Memory::Verify(address, expected);
		}

		namespace DynBase
		{
			enum class HookType
			{
				Call,
				Jump,
			};

			using Memory::DynBaseAddress;

			template<typename T, typename AT>
			inline void		Patch(AT address, T value)
			{
				VP::Patch(DynBaseAddress(address), value);
			}

#ifndef _MEMORY_NO_CRT
			template<typename AT>
			inline void		Patch(AT address, std::initializer_list<uint8_t> list )
			{
				VP::Patch(DynBaseAddress(address), std::move(list));
			}
#endif

			template<typename AT>
			inline void		Nop(AT address, size_t count)
			{
				VP::Nop(DynBaseAddress(address), count);
			}

			template<ptrdiff_t extraBytesAfterOffset = 0, typename Var, typename AT>
			inline void		WriteOffsetValue(AT address, Var var)
			{
				VP::WriteOffsetValue<extraBytesAfterOffset>(DynBaseAddress(address), var);
			}

			template<ptrdiff_t extraBytesAfterOffset = 0, typename Var, typename AT>
			inline void		ReadOffsetValue(AT address, Var& var)
			{
				VP::ReadOffsetValue<extraBytesAfterOffset>(DynBaseAddress(address), var);
			}

			template<typename AT, typename Func>
			inline void		InjectHook(AT address, Func hook)
			{
				VP::InjectHook(DynBaseAddress(address), hook);
			}

			template<typename AT, typename Func>
			inline void		InjectHook(AT address, Func hook, HookType type)
			{
				VP::InjectHook(DynBaseAddress(address), hook, static_cast<VP::HookType>(type));
			}

			template<typename Func, typename AT>
			inline void		ReadCall(AT address, Func& func)
			{
				Memory::ReadCall(DynBaseAddress(address), func);
			}

			template<typename AT>
			inline void*	ReadCallFrom(AT address, ptrdiff_t offset = 0)
			{
				return Memory::ReadCallFrom(DynBaseAddress(address), offset);
			}

			constexpr auto InterceptCall = [](auto address, auto&& func, auto&& hook)
			{
				VP::InterceptCall(DynBaseAddress(address), func, hook);
			};

#ifndef _MEMORY_NO_CRT
			inline bool MemEquals(uintptr_t address, std::initializer_list<uint8_t> val)
			{
				return Memory::MemEquals(DynBaseAddress(address), std::move(val));
			}
#endif

			template<typename AT>
			inline AT Verify(AT address, uintptr_t expected)
			{
				return Memory::Verify(address, DynBaseAddress(expected));
			}

		};
	};
};

#endif
