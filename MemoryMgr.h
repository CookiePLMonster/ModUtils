#pragma once

// Switches:
// _MEMORY_DECLS_ONLY - don't include anything but macroes

#define WRAPPER __declspec(naked)
#define DEPRECATED __declspec(deprecated)

#ifdef _MSC_VER
#define EAXJMP(a) { _asm mov eax, a _asm jmp eax }
#define VARJMP(a) { _asm jmp a }
#define WRAPARG(a) ((int)a)
#else
#define EAXJMP(a) __asm__ volatile("mov eax, %0\n" "jmp eax" :: "i" (a));
#define VARJMP(a) __asm__ volatile("jmp %0" :: "m" (a));
#define WRAPARG(a)
#endif

#ifdef _MSC_VER
#define NOVMT __declspec(novtable)
#else
#define NOVMT
#endif

#define SETVMT(a) *((uintptr_t*)this) = (uintptr_t)a

#ifndef _MEMORY_DECLS_ONLY

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdint>
#include <cstring>
#include <cassert>

#include <initializer_list>
#include <utility>

namespace Memory
{
	namespace details
	{
		enum class HookType
		{
			Call,
			Jump,
		};
	}

	using details::HookType;

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
		std::memcpy(reinterpret_cast<void*>(address), std::addressof(value), sizeof(value));
	}

	template<typename AT>
	inline void		Patch(AT address, std::initializer_list<uint8_t> list)
	{
		static_assert(sizeof(AT) == sizeof(uintptr_t), "AT must be pointer sized");
		std::memcpy(reinterpret_cast<void*>(address), list.begin(), list.size() * sizeof(decltype(list)::value_type));
	}

	template<typename Var, typename AT>
	inline void		Read(AT address, Var& var)
	{
		static_assert(sizeof(AT) == sizeof(uintptr_t), "AT must be pointer sized");
		std::memcpy(reinterpret_cast<void*>(std::addressof(var)), reinterpret_cast<const void*>(address), sizeof(var));
	}

	template<typename AT>
	inline void		Nop(AT address, size_t count)
	{
		static_assert(sizeof(AT) == sizeof(uintptr_t), "AT must be pointer sized");
		std::memset(reinterpret_cast<void*>(address), 0x90, count);
	}

	template<typename Var, typename AT>
	inline void		WriteOffsetValue(AT address, Var var, ptrdiff_t bytesAfterDisplacement = 0)
	{
		static_assert(sizeof(AT) == sizeof(uintptr_t), "AT must be pointer sized");
		const intptr_t dstAddr = intptr_t(address);
		intptr_t srcAddr;
		std::memcpy(&srcAddr, std::addressof(var), sizeof(srcAddr));
		Patch(address, static_cast<int32_t>(srcAddr - dstAddr - (4 + bytesAfterDisplacement)));
	}

	template<typename Var, typename AT>
	inline void		ReadOffsetValue(AT address, Var& var, ptrdiff_t bytesAfterDisplacement = 0)
	{
		static_assert(sizeof(AT) == sizeof(uintptr_t), "AT must be pointer sized");
		int32_t offset;
		Read(address, offset);

		const intptr_t srcAddr = intptr_t(address);
		const intptr_t dstAddr = srcAddr + (4 + bytesAfterDisplacement) + offset;
		std::memcpy(std::addressof(var), &dstAddr, sizeof(dstAddr));
	}

	template<typename Var, typename AT>
	inline void		WriteMemDisplacement(AT address, Var var, [[maybe_unused]] ptrdiff_t bytesAfterDisplacement = 0)
	{
#ifdef _M_X64
		WriteOffsetValue(address, var, bytesAfterDisplacement);
#else
		Patch(address, var);
#endif
	}

	template<typename Var, typename AT>
	inline void		ReadMemDisplacement(AT address, Var& var, [[maybe_unused]] ptrdiff_t bytesAfterDisplacement = 0)
	{
#ifdef _M_X64
		ReadOffsetValue(address, var, bytesAfterDisplacement);
#else
		Read(address, var);
#endif
	}

	inline auto InterceptMemDisplacement = [](auto address, auto& orig, auto& var, ptrdiff_t bytesAfterDisplacement = 0)
	{
		ReadMemDisplacement(address, orig, bytesAfterDisplacement);
		WriteMemDisplacement(address, std::addressof(var), bytesAfterDisplacement);
	};

	template<typename AT, typename Func>
	inline void		InjectHook(AT address, Func hook)
	{
		WriteOffsetValue(intptr_t(address) + 1, hook);
	}

	template<typename AT, typename Func>
	inline void		InjectHook(AT address, Func hook, HookType type)
	{
		Patch<uint8_t>(address, type == HookType::Jump ? 0xE9 : 0xE8);
		InjectHook(address, hook);
	}

	template<typename Func, typename AT>
	inline void		ReadCall(AT address, Func& func)
	{
		ReadOffsetValue(intptr_t(address) + 1, func);
	}

	template<typename AT>
	inline void*	ReadCallFrom(AT address, ptrdiff_t offset = 0)
	{
		uintptr_t addr;
		ReadCall(address, addr);
		return reinterpret_cast<void*>(addr + offset);
	}

	inline auto InterceptCall = [](auto address, auto& func, auto&& hook)
	{
		ReadCall(address, func);
		InjectHook(address, hook);
	};

	inline bool MemEquals(uintptr_t address, std::initializer_list<uint8_t> val)
	{
		return std::memcmp(reinterpret_cast<const void*>(address), val.begin(), val.size() * sizeof(decltype(val)::value_type)) == 0;
	}

	template<typename AT>
	inline AT Verify(AT address, uintptr_t expected)
	{
		static_assert(sizeof(AT) == sizeof(uintptr_t), "AT must be pointer sized");
		assert(uintptr_t(address) == expected);
		return address;
	}

	namespace DynBase
	{
		using details::HookType;
		using Memory::DynBaseAddress;

		template<typename T, typename AT>
		inline void		Patch(AT address, T value)
		{
			Memory::Patch(DynBaseAddress(address), value);
		}

		template<typename AT>
		inline void		Patch(AT address, std::initializer_list<uint8_t> list )
		{
			Memory::Patch(DynBaseAddress(address), std::move(list));
		}

		template<typename Var, typename AT>
		inline void		Read(AT address, Var& var)
		{
			Memory::Read(DynBaseAddress(address), var);
		}

		template<typename AT>
		inline void		Nop(AT address, size_t count)
		{
			Memory::Nop(DynBaseAddress(address), count);
		}

		template<typename Var, typename AT>
		inline void		WriteOffsetValue(AT address, Var var, ptrdiff_t bytesAfterDisplacement = 0)
		{
			Memory::WriteOffsetValue(DynBaseAddress(address), var, bytesAfterDisplacement);
		}

		template< typename Var, typename AT>
		inline void		ReadOffsetValue(AT address, Var& var, ptrdiff_t bytesAfterDisplacement = 0)
		{
			Memory::ReadOffsetValue(DynBaseAddress(address), var, bytesAfterDisplacement);
		}

		template<typename Var, typename AT>
		inline void		WriteMemDisplacement(AT address, Var var, ptrdiff_t bytesAfterDisplacement = 0)
		{
			Memory::WriteMemDisplacement(DynBaseAddress(address), var, bytesAfterDisplacement);
		}

		template<typename Var, typename AT>
		inline void		ReadMemDisplacement(AT address, Var& var, ptrdiff_t bytesAfterDisplacement = 0)
		{
			Memory::ReadMemDisplacement(DynBaseAddress(address), var, bytesAfterDisplacement);
		}

		inline auto InterceptMemDisplacement = [](auto address, auto& orig, auto& var, ptrdiff_t bytesAfterDisplacement = 0)
		{
			Memory::InterceptMemDisplacement(DynBaseAddress(address), orig, var, bytesAfterDisplacement);
		};

		template<typename AT, typename Func>
		inline void		InjectHook(AT address, Func hook)
		{
			Memory::InjectHook(DynBaseAddress(address), hook);
		}

		template<typename AT, typename Func>
		inline void		InjectHook(AT address, Func hook, HookType type)
		{
			Memory::InjectHook(DynBaseAddress(address), hook, type);
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

		constexpr auto InterceptCall = [](auto address, auto& func, auto&& hook)
		{
			Memory::InterceptCall(DynBaseAddress(address), func, hook);
		};

		inline bool MemEquals(uintptr_t address, std::initializer_list<uint8_t> val)
		{
			return Memory::MemEquals(DynBaseAddress(address), std::move(val));
		}

		template<typename AT>
		inline AT Verify(AT address, uintptr_t expected)
		{
			return Memory::Verify(address, DynBaseAddress(expected));
		}
	};

	namespace VP
	{
		using details::HookType;
		using Memory::DynBaseAddress;

		template<typename T, typename AT>
		inline void		Patch(AT address, T value)
		{
			DWORD		dwProtect;
			VirtualProtect((void*)address, sizeof(T), PAGE_EXECUTE_READWRITE, &dwProtect);
			Memory::Patch(address, value);
			VirtualProtect((void*)address, sizeof(T), dwProtect, &dwProtect);
		}

		template<typename AT>
		inline void		Patch(AT address, std::initializer_list<uint8_t> list )
		{
			DWORD		dwProtect;
			VirtualProtect((void*)address, list.size(), PAGE_EXECUTE_READWRITE, &dwProtect);
			Memory::Patch(address, std::move(list));
			VirtualProtect((void*)address, list.size(), dwProtect, &dwProtect);
		}

		using Memory::Read;

		template<typename AT>
		inline void		Nop(AT address, size_t count)
		{
			DWORD		dwProtect;
			VirtualProtect((void*)address, count, PAGE_EXECUTE_READWRITE, &dwProtect);
			Memory::Nop(address, count);
			VirtualProtect((void*)address, count, dwProtect, &dwProtect);
		}

		template<typename Var, typename AT>
		inline void		WriteOffsetValue(AT address, Var var, ptrdiff_t bytesAfterDisplacement = 0)
		{
			DWORD		dwProtect;

			VirtualProtect((void*)address, 4, PAGE_EXECUTE_READWRITE, &dwProtect);
			Memory::WriteOffsetValue(address, var, bytesAfterDisplacement);
			VirtualProtect((void*)address, 4, dwProtect, &dwProtect);
		}

		using Memory::ReadOffsetValue;

		template<typename Var, typename AT>
		inline void		WriteMemDisplacement(AT address, Var var, ptrdiff_t bytesAfterDisplacement = 0)
		{
			DWORD		dwProtect;

			VirtualProtect((void*)address, 4, PAGE_EXECUTE_READWRITE, &dwProtect);
			Memory::WriteMemDisplacement(address, var, bytesAfterDisplacement);
			VirtualProtect((void*)address, 4, dwProtect, &dwProtect);
		}

		using Memory::ReadMemDisplacement;

		inline auto InterceptMemDisplacement = [](auto address, auto& orig, auto& var, ptrdiff_t bytesAfterDisplacement = 0)
		{
			DWORD		dwProtect;

			VirtualProtect((void*)address, 5, PAGE_EXECUTE_READWRITE, &dwProtect);
			Memory::InterceptMemDisplacement(address, orig, var, bytesAfterDisplacement);
			VirtualProtect((void*)address, 5, dwProtect, &dwProtect);
		};

		template<typename AT, typename Func>
		inline void		InjectHook(AT address, Func hook)
		{
			DWORD		dwProtect;

			VirtualProtect((void*)((DWORD_PTR)address + 1), 4, PAGE_EXECUTE_READWRITE, &dwProtect);
			Memory::InjectHook(address, hook);
			VirtualProtect((void*)((DWORD_PTR)address + 1), 4, dwProtect, &dwProtect);
		}

		template<typename AT, typename Func>
		inline void		InjectHook(AT address, Func hook, HookType type)
		{
			DWORD		dwProtect;

			VirtualProtect((void*)address, 5, PAGE_EXECUTE_READWRITE, &dwProtect);
			Memory::InjectHook(address, hook, type);
			VirtualProtect((void*)address, 5, dwProtect, &dwProtect);
		}

		using Memory::ReadCall;
		using Memory::ReadCallFrom;

		constexpr auto InterceptCall = [](auto address, auto& func, auto&& hook)
		{
			DWORD		dwProtect;

			VirtualProtect((void*)address, 5, PAGE_EXECUTE_READWRITE, &dwProtect);
			Memory::InterceptCall(address, func, hook);
			VirtualProtect((void*)address, 5, dwProtect, &dwProtect);
		};

		using Memory::MemEquals;
		using Memory::Verify;

		namespace DynBase
		{
			using details::HookType;
			using Memory::DynBaseAddress;

			template<typename T, typename AT>
			inline void		Patch(AT address, T value)
			{
				VP::Patch(DynBaseAddress(address), value);
			}

			template<typename AT>
			inline void		Patch(AT address, std::initializer_list<uint8_t> list)
			{
				VP::Patch(DynBaseAddress(address), std::move(list));
			}

			template<typename Var, typename AT>
			inline void		Read(AT address, Var& var)
			{
				VP::Read(DynBaseAddress(address), var);
			}

			template<typename AT>
			inline void		Nop(AT address, size_t count)
			{
				VP::Nop(DynBaseAddress(address), count);
			}

			template<typename Var, typename AT>
			inline void		WriteOffsetValue(AT address, Var var, ptrdiff_t bytesAfterDisplacement = 0)
			{
				VP::WriteOffsetValue(DynBaseAddress(address), var, bytesAfterDisplacement);
			}

			template<typename Var, typename AT>
			inline void		ReadOffsetValue(AT address, Var& var, ptrdiff_t bytesAfterDisplacement = 0)
			{
				VP::ReadOffsetValue(DynBaseAddress(address), var, bytesAfterDisplacement);
			}

			template<typename Var, typename AT>
			inline void		WriteMemDisplacement(AT address, Var var, ptrdiff_t bytesAfterDisplacement = 0)
			{
				VP::WriteMemDisplacement(DynBaseAddress(address), var, bytesAfterDisplacement);
			}

			template<typename Var, typename AT>
			inline void		ReadMemDisplacement(AT address, Var& var, ptrdiff_t bytesAfterDisplacement = 0)
			{
				VP::ReadMemDisplacement(DynBaseAddress(address), var, bytesAfterDisplacement);
			}

			inline auto InterceptMemDisplacement = [](auto address, auto& orig, auto& var, ptrdiff_t bytesAfterDisplacement = 0)
			{
				VP::InterceptMemDisplacement(DynBaseAddress(address), orig, var, bytesAfterDisplacement);
			};

			template<typename AT, typename Func>
			inline void		InjectHook(AT address, Func hook)
			{
				VP::InjectHook(DynBaseAddress(address), hook);
			}

			template<typename AT, typename Func>
			inline void		InjectHook(AT address, Func hook, HookType type)
			{
				VP::InjectHook(DynBaseAddress(address), hook, type);
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

			constexpr auto InterceptCall = [](auto address, auto& func, auto&& hook)
			{
				VP::InterceptCall(DynBaseAddress(address), func, hook);
			};

			inline bool MemEquals(uintptr_t address, std::initializer_list<uint8_t> val)
			{
				return Memory::MemEquals(DynBaseAddress(address), std::move(val));
			}

			template<typename AT>
			inline AT Verify(AT address, uintptr_t expected)
			{
				return Memory::Verify(address, DynBaseAddress(expected));
			}

		};
	};
};

#endif
