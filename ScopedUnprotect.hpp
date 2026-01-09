#pragma once

// A lightweight object that removes the write protection from the code section or the entire module for as long as the object is in scope (in the style of std::lock_guard).
// This object is meant to be used in the scope where memory patches take place, as a convenient alternative to unprotecting and re-protecting
// the individual memory addresses continuously. Once the protect object goes out of scope, the original protection gets restored.

// Usage recommendations:
// * When unprotecting the code section, it is recommended to use ScopedUnprotect::SectionOrFullModule, to account for unusual executables
//   with renamed sections.
// * If more sections (e.g. .rdata) need to be unprotected afterwards, ScopedUnprotect::Section may be safely used, as it'll be a no-op
//   in the case where the previous call unprotected the entire module.

// The ScopedUnprotect object should not be discarded - you will get a compiler warning if you do that.

#include <forward_list>
#include <string_view>

#include <cstring>

class [[nodiscard]] ScopedUnprotect
{
public:
	static ScopedUnprotect Section(HINSTANCE hInstance, std::string_view name, bool* outFoundSection = nullptr)
	{
		ScopedUnprotect result;
		bool foundSection = false;

		const intptr_t moduleBase = reinterpret_cast<intptr_t>(hInstance);
		PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hInstance);
		PIMAGE_NT_HEADERS ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(moduleBase + dosHeader->e_lfanew);
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);

		for (SIZE_T i = 0, j = ntHeader->FileHeader.NumberOfSections; i < j; ++i)
		{
			const char* NameCh = reinterpret_cast<const char*>(section[i].Name);
			if (std::string_view(NameCh, strnlen_s(NameCh, std::size(section[i].Name))) == name)
			{
				LPCVOID SectionBase = reinterpret_cast<char*>(hInstance) + section[i].VirtualAddress;
				const SIZE_T VirtualSize = section[i].Misc.VirtualSize;
				result.UnprotectRange(SectionBase, VirtualSize);
				foundSection = true;
			}
		}

		if (outFoundSection != nullptr)
		{
			*outFoundSection = foundSection;
		}
		return result;
	}

	static ScopedUnprotect FullModule(HINSTANCE hInstance)
	{
		ScopedUnprotect result;

		const intptr_t moduleBase = reinterpret_cast<intptr_t>(hInstance);
		PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hInstance);
		PIMAGE_NT_HEADERS ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(moduleBase + dosHeader->e_lfanew);
		result.UnprotectRange(hInstance, ntHeader->OptionalHeader.SizeOfImage);

		return result;
	}

	static ScopedUnprotect SectionOrFullModule(HINSTANCE hInstance, std::string_view name)
	{
		bool foundSection = false;
		ScopedUnprotect result = Section(hInstance, name, &foundSection);
		if (!foundSection)
		{
			result = FullModule(hInstance);
		}
		return result;
	}

	ScopedUnprotect(ScopedUnprotect&&) = default;
	ScopedUnprotect& operator=(ScopedUnprotect&&) = default;

private:
	ScopedUnprotect() = default;

	ScopedUnprotect(const ScopedUnprotect&) = delete;
	ScopedUnprotect& operator=(const ScopedUnprotect&) = delete;

	void UnprotectRange(LPCVOID BaseAddress, SIZE_T Size)
	{
		SIZE_T QueriedSize = 0;
		while (QueriedSize < Size)
		{
			MEMORY_BASIC_INFORMATION MemoryInf;

			if (VirtualQuery(BaseAddress, &MemoryInf, sizeof(MemoryInf)) != sizeof(MemoryInf))
			{
				return;
			}
			if (MemoryInf.State == MEM_COMMIT && (MemoryInf.Type & MEM_IMAGE) != 0 &&
				(MemoryInf.Protect & (PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY|PAGE_READWRITE|PAGE_WRITECOPY)) == 0)
			{
				DWORD dwOldProtect;
				const bool wasExecutable = (MemoryInf.Protect & (PAGE_EXECUTE|PAGE_EXECUTE_READ)) != 0;
				if (VirtualProtect(MemoryInf.BaseAddress, MemoryInf.RegionSize, wasExecutable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE, &dwOldProtect) != FALSE)
				{
					m_regionsToReprotect.emplace_front(MemoryInf.BaseAddress, MemoryInf.RegionSize, MemoryInf.Protect);
				}
			}
			QueriedSize += MemoryInf.RegionSize;
			BaseAddress = reinterpret_cast<const char*>(BaseAddress) + MemoryInf.RegionSize;
		}
	}

private:
	class ReprotectRegion
	{
	public:
		ReprotectRegion(LPVOID Address, SIZE_T Size, DWORD Protect)
			: Address(Address), Size(Size), Protect(Protect)
		{
		}

		~ReprotectRegion()
		{
			DWORD dwOldProtect;
			VirtualProtect(Address, Size, Protect, &dwOldProtect);
		}

	private:
		LPVOID Address;
		SIZE_T Size;
		DWORD Protect;
	};

	std::forward_list<ReprotectRegion> m_regionsToReprotect;
};
