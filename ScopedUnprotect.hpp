#pragma once

#include <forward_list>
#include <tuple>
#include <memory>

// Object that removes write protection from the code section or the entire module for as long as the object is in scope
namespace ScopedUnprotect
{
	class Unprotect
	{
	public:
		~Unprotect()
		{
			for ( auto& it : m_queriedProtects )
			{
				DWORD dwOldProtect;
				VirtualProtect( std::get<0>(it), std::get<1>(it), std::get<2>(it), &dwOldProtect );
			}
		}

	protected:
		Unprotect() = default;

		void UnprotectRange( DWORD_PTR BaseAddress, SIZE_T Size )
		{
			SIZE_T QueriedSize = 0;
			while ( QueriedSize < Size )
			{
				MEMORY_BASIC_INFORMATION MemoryInf;
				DWORD dwOldProtect;

				VirtualQuery( (LPCVOID)(BaseAddress + QueriedSize), &MemoryInf, sizeof(MemoryInf) );
				if ( MemoryInf.State == MEM_COMMIT && (MemoryInf.Type & MEM_IMAGE) != 0 &&
					(MemoryInf.Protect & (PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY|PAGE_READWRITE|PAGE_WRITECOPY)) == 0 )
				{
					const bool wasExecutable = (MemoryInf.Protect & (PAGE_EXECUTE|PAGE_EXECUTE_READ)) != 0;
					VirtualProtect( MemoryInf.BaseAddress, MemoryInf.RegionSize, wasExecutable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE, &dwOldProtect );
					m_queriedProtects.emplace_front( MemoryInf.BaseAddress, MemoryInf.RegionSize, MemoryInf.Protect );
				}
				QueriedSize += MemoryInf.RegionSize;
			}
		}

	private:
		std::forward_list< std::tuple< LPVOID, SIZE_T, DWORD > >	m_queriedProtects;
	};

	class Section : public Unprotect
	{
	public:
		Section( HINSTANCE hInstance, const char* name )
		{
			PIMAGE_NT_HEADERS		ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hInstance + ((PIMAGE_DOS_HEADER)hInstance)->e_lfanew);
			PIMAGE_SECTION_HEADER	pSection = IMAGE_FIRST_SECTION(ntHeader);

			for ( SIZE_T i = 0, j = ntHeader->FileHeader.NumberOfSections; i < j; ++i, ++pSection )
			{
				if ( strncmp( (const char*)pSection->Name, name, IMAGE_SIZEOF_SHORT_NAME ) == 0 )
				{
					const DWORD_PTR VirtualAddress = (DWORD_PTR)hInstance + pSection->VirtualAddress;
					const SIZE_T VirtualSize = pSection->Misc.VirtualSize;
					UnprotectRange( VirtualAddress, VirtualSize );

					m_locatedSection = true;
					break;
				}
			}
		};

		bool	SectionLocated() const { return m_locatedSection; }

	private:
		bool	m_locatedSection = false;
	};

	class FullModule : public Unprotect
	{
	public:
		FullModule( HINSTANCE hInstance )
		{
			PIMAGE_NT_HEADERS		ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hInstance + ((PIMAGE_DOS_HEADER)hInstance)->e_lfanew);
			UnprotectRange( (DWORD_PTR)hInstance, ntHeader->OptionalHeader.SizeOfImage );
		}
	};

	inline std::unique_ptr<Unprotect> UnprotectSectionOrFullModule( HINSTANCE hInstance, const char* name )
	{
		std::unique_ptr<Section> section = std::make_unique<Section>( hInstance, name );
		if ( !section->SectionLocated() )
		{
			return std::make_unique<FullModule>( hInstance );
		}
		return section;
	}
};
