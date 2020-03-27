#pragma once

// This header file is intended to streamline the process of hooking inside executables by hooking into WinAPI functions
// It is intended to be included in a separate compilation unit after defining the following:

// #define HOOKED_FUNCTION WinAPIFunction - must be a define or else the plugin will patch into itself
// #define HOOKED_LIBRARY "LIBRARY.DLL"
// windows.h also must be included already (you probably had to include it to define the above)

// When integrated properly, the following function shall be exposed:
// void OnInitializeHook() - called once from the hooked WinAPI function

// The following exports are added to the binary:
// void InitializeASI()
// uint32_t GetBuildNumber() - returns revision/build number as defined in VersionInfo.lua (if defined)

// Hooks will be initialized by first attempting to patch IAT of the main module
// If this fails, selected WinAPI export will be hooked directly

#include "Utils/MemoryMgr.h"

#define STRINGIZE(s) STRINGIZE2(s)
#define STRINGIZE2(s) #s

extern void OnInitializeHook();

namespace HookInit
{
static void ProcHook()
{
	static bool bPatched = false;
	if ( !std::exchange(bPatched, true) )
	{
		OnInitializeHook();
	}
}

// Helper to extract parameters from the function
template <typename>
struct wrap_winapi_function_helper;

template <typename Result, typename... Args>
struct wrap_winapi_function_helper<Result WINAPI (Args...)>
{
	static inline Result (WINAPI *origFunction)(Args...);
	static Result WINAPI Hook(Args... args)
	{
		ProcHook();
		return origFunction(std::forward<Args>(args)...);
	}

	static inline uint8_t origCode[5];
	static Result WINAPI OverwritingHook(Args... args)
	{
		Memory::VP::Patch(origFunction, { origCode[0], origCode[1], origCode[2], origCode[3], origCode[4] });
		return Hook(std::forward<Args>(args)...);
	}
};

using wrapped_function = wrap_winapi_function_helper<decltype(HOOKED_FUNCTION)>;

static void ReplaceFunction(void** funcPtr)
{
	DWORD dwProtect;

	VirtualProtect(funcPtr, sizeof(*funcPtr), PAGE_READWRITE, &dwProtect);
	wrapped_function::origFunction = **reinterpret_cast<decltype(wrapped_function::origFunction)*>(funcPtr);

	*funcPtr = wrapped_function::Hook;
	VirtualProtect(funcPtr, sizeof(*funcPtr), dwProtect, &dwProtect);
}

static bool PatchIAT()
{
	const DWORD_PTR instance = reinterpret_cast<DWORD_PTR>(GetModuleHandle(nullptr));
	const PIMAGE_NT_HEADERS ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(instance + reinterpret_cast<PIMAGE_DOS_HEADER>(instance)->e_lfanew);

	// Find IAT
	PIMAGE_IMPORT_DESCRIPTOR pImports = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(instance + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for ( ; pImports->Name != 0; pImports++ )
	{
		if ( _stricmp(reinterpret_cast<const char*>(instance + pImports->Name), HOOKED_LIBRARY) == 0 )
		{
			if ( pImports->OriginalFirstThunk != 0 )
			{
				const PIMAGE_IMPORT_BY_NAME* pFunctions = reinterpret_cast<PIMAGE_IMPORT_BY_NAME*>(instance + pImports->OriginalFirstThunk);

				for ( ptrdiff_t j = 0; pFunctions[j] != nullptr; j++ )
				{
					if ( strcmp(reinterpret_cast<const char*>(instance + pFunctions[j]->Name), STRINGIZE(HOOKED_FUNCTION)) == 0 )
					{
						void** pAddress = reinterpret_cast<void**>(instance + pImports->FirstThunk) + j;
						ReplaceFunction(pAddress);
						return true;
					}
				}
			}
			else
			{
				// This will only work if nobody else beats us to it - which is fine, because a fallback exists
				void** pFunctions = reinterpret_cast<void**>(instance + pImports->FirstThunk);

				for ( ptrdiff_t j = 0; pFunctions[j] != nullptr; j++ )
				{
					if ( pFunctions[j] == HOOKED_FUNCTION )
					{
						ReplaceFunction(&pFunctions[j]);
						return true;					
					}
				}
			}
		}
	}
	return false;
}

static bool PatchIAT_ByPointers()
{
	wrapped_function::origFunction = HOOKED_FUNCTION;
	memcpy(wrapped_function::origCode, wrapped_function::origFunction, sizeof(wrapped_function::origCode));

#ifdef _WIN64
	Trampoline* trampoline = Trampoline::MakeTrampoline(wrapped_function::origFunction);
	Memory::VP::InjectHook(wrapped_function::origFunction, trampoline->Jump(&wrapped_function::OverwritingHook), PATCH_JUMP);
#else
	Memory::VP::InjectHook(wrapped_function::origFunction, wrapped_function::OverwritingHook, PATCH_JUMP);
#endif
	return true;
}

static void InstallHooks()
{
	bool getStartupInfoHooked = PatchIAT();
	if ( !getStartupInfoHooked )
	{
		PatchIAT_ByPointers();
	}
}

}

extern "C"
{
	static LONG InitCount = 0;
	__declspec(dllexport) void InitializeASI()
	{
		if ( _InterlockedCompareExchange(&InitCount, 1, 0) != 0 ) return;
		HookInit::InstallHooks();
	}

#if defined(rsc_RevisionID) && defined(rsc_BuildID)
	__declspec(dllexport) uint32_t GetBuildNumber()
	{
		return (rsc_RevisionID << 8) | rsc_BuildID;
	}
#endif
}