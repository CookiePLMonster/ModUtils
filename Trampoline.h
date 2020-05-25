#pragma once

// Trampolines are useless on x86 arch
#ifdef _WIN64

#include <cassert>
#include <memory>

// Trampoline class for big (>2GB) jumps
// Never needed in 32-bit processes so in those cases this does nothing but forwards to Memory functions
// NOTE: Each Trampoline class allocates a page of executable memory for trampolines and does NOT free it when going out of scope
class Trampoline
{
public:
	template<typename T>
	static Trampoline* MakeTrampoline( T addr )
	{
		return MakeTrampoline( uintptr_t(addr) );
	}

	template<typename Func>
	LPVOID Jump( Func func )
	{
		union member_cast
		{
			LPVOID addr;
			Func funcPtr;
		} cast;
		static_assert( sizeof(cast.addr) == sizeof(cast.funcPtr), "member_cast failure!" );

		cast.funcPtr = func;
		return CreateCodeTrampoline( cast.addr );
	}

	template<typename T>
	T* Pointer( size_t align = alignof(T) )
	{
		return static_cast<T*>(GetNewSpace( sizeof(T), align ));
	}

	template<typename T>
	T& Reference( size_t align = alignof(T) )
	{
		return *Pointer<T>( align );
	}


private:
	static Trampoline* MakeTrampoline( uintptr_t addr )
	{
		Trampoline* current = ms_first;
		while ( current != nullptr )
		{
			if ( current->FeasibleForAddresss( addr ) ) return current;

			current = current->m_next;
		}

		SYSTEM_INFO systemInfo;
		GetSystemInfo( &systemInfo );

		void* space = FindAndAllocateMem(addr, systemInfo.dwAllocationGranularity);
		void* usableSpace = reinterpret_cast<char*>(space) + sizeof(Trampoline);
		return new( space ) Trampoline( usableSpace, systemInfo.dwAllocationGranularity - sizeof(Trampoline) );
	}


	Trampoline( const Trampoline& ) = delete;
	Trampoline& operator=( const Trampoline& ) = delete;

	explicit Trampoline( void* memory, size_t size )
		: m_next( std::exchange( ms_first, this ) ), m_pageMemory( memory ), m_spaceLeft( size )
	{
	}

	static constexpr size_t SINGLE_TRAMPOLINE_SIZE = 12;
	bool FeasibleForAddresss( uintptr_t addr ) const
	{
		return IsAddressFeasible( (uintptr_t)m_pageMemory, addr ) && m_spaceLeft >= SINGLE_TRAMPOLINE_SIZE;
	}

	LPVOID CreateCodeTrampoline( LPVOID addr )
	{
		uint8_t* trampolineSpace = static_cast<uint8_t*>(GetNewSpace( SINGLE_TRAMPOLINE_SIZE, 1 ));

		// Create trampoline code
		const uint8_t prologue[] = { 0x48, 0xB8 };
		const uint8_t epilogue[] = { 0xFF, 0xE0 };

		memcpy( trampolineSpace, prologue, sizeof(prologue) );
		memcpy( trampolineSpace + 2, &addr, sizeof(addr) );
		memcpy( trampolineSpace + 10, epilogue, sizeof(epilogue) );

		return trampolineSpace;
	}

	LPVOID GetNewSpace( size_t size, size_t alignment )
	{
		void* space = std::align( alignment, size, m_pageMemory, m_spaceLeft );
		if ( space != nullptr )
		{
			m_pageMemory = static_cast<uint8_t*>(m_pageMemory) + size;
			m_spaceLeft -= size;
		}
		else
		{
			assert( !"Out of trampoline space!" );
		}
		return space;
	}

	static LPVOID FindAndAllocateMem( const uintptr_t addr, DWORD size )
	{
		uintptr_t curAddr = addr;
		// Find the first unallocated page after 'addr' and try to allocate a page for trampolines there
		while ( true )
		{
			MEMORY_BASIC_INFORMATION MemoryInf;
			if ( VirtualQuery( (LPCVOID)curAddr, &MemoryInf, sizeof(MemoryInf) ) == 0 ) break;
			if ( MemoryInf.State == MEM_FREE && MemoryInf.RegionSize >= size )
			{
				// Align up to allocation granularity
				uintptr_t alignedAddr = uintptr_t(MemoryInf.BaseAddress);
				alignedAddr = (alignedAddr + size - 1) & ~uintptr_t(size - 1);

				if ( !IsAddressFeasible( alignedAddr, addr ) ) break;

				LPVOID mem = VirtualAlloc( (LPVOID)alignedAddr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
				if ( mem != nullptr )
				{
					return mem;
				}
			}
			curAddr += MemoryInf.RegionSize;
		}
		return nullptr;
	}

	static bool IsAddressFeasible( uintptr_t trampolineOffset, uintptr_t addr )
	{
		const ptrdiff_t diff = trampolineOffset - addr;
		return diff >= INT32_MIN && diff <= INT32_MAX;
	}

	Trampoline* m_next = nullptr;
	void* m_pageMemory = nullptr;
	size_t m_spaceLeft = 0;

	static inline Trampoline* ms_first = nullptr;
};


#endif