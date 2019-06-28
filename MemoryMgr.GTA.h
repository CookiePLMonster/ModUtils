#pragma once

#include "MemoryMgr.h"

#include <variant>
#include "Patterns.h"

namespace Memory
{
	struct PatternAndOffset
	{
		PatternAndOffset( std::string_view pattern, ptrdiff_t offset = 0 )
			: pattern(std::move(pattern)), offset(offset)
		{
		}

		std::string_view pattern;
		ptrdiff_t offset;
	};

	using AddrVariant = std::variant<uintptr_t, PatternAndOffset>;

	namespace internal
	{
		inline signed char* GetVer()
		{
			static signed char	bVer = -1;
			return &bVer;
		}

		inline bool* GetEuropean()
		{
			static bool			bEuropean;
			return &bEuropean;
		}

		inline uintptr_t GetDummy()
		{
			static uintptr_t		dwDummy;
			return reinterpret_cast<uintptr_t>(&dwDummy);
		}
	}
}

namespace Memory
{
	namespace internal
	{
		inline uintptr_t HandlePattern( const PatternAndOffset& pattern )
		{
			void* addr = hook::get_pattern( pattern.pattern, pattern.offset );
			return reinterpret_cast<uintptr_t>(addr);
		}

#if defined _GTA_III
		inline void InitializeVersions()
		{
			signed char*	bVer = GetVer();

			if ( *bVer == -1 )
			{
				if (*(uint32_t*)0x5C1E75 == 0xB85548EC) *bVer = 0;
				else if (*(uint32_t*)0x5C2135 == 0xB85548EC) *bVer = 1;
				else if (*(uint32_t*)0x5C6FD5 == 0xB85548EC) *bVer = 2;
			}
		}

#elif defined _GTA_VC

		inline void InitializeVersions()
		{
			signed char*	bVer = GetVer();

			if ( *bVer == -1 )
			{
				if (*(uint32_t*)0x667BF5 == 0xB85548EC) *bVer = 0;
				else if (*(uint32_t*)0x667C45 == 0xB85548EC) *bVer = 1;
				else if (*(uint32_t*)0x666BA5 == 0xB85548EC) *bVer = 2;
			}
		}

#elif defined _GTA_SA

		inline bool TryMatch_10()
		{
			if ( *(uint32_t*)DynBaseAddress(0x82457C) == 0x94BF )
			{
				// 1.0 US
				*GetVer() = 0;
				*GetEuropean() = false;
				return true;
			}
			if ( *(uint32_t*)DynBaseAddress(0x8245BC) == 0x94BF )
			{
				// 1.0 EU
				*GetVer() = 0;
				*GetEuropean() = true;
				return true;
			}
			return false;
		}

		inline bool TryMatch_11()
		{
			if ( *(uint32_t*)DynBaseAddress(0x8252FC) == 0x94BF )
			{
				// 1.01 US
				*GetVer() = 1;
				*GetEuropean() = false;
				return true;
			}
			if ( *(uint32_t*)DynBaseAddress(0x82533C) == 0x94BF )
			{
				// 1.01 EU
				*GetVer() = 1;
				*GetEuropean() = true;
				return true;
			}
			return false;
		}

		inline bool TryMatch_30()
		{
			if (*(uint32_t*)DynBaseAddress(0x85EC4A) == 0x94BF )
			{
				// 3.0
				*GetVer() = 2;
				*GetEuropean() = false;
				return true;
			}
			return false;
		}

		inline bool TryMatch_newsteam_r1()
		{
			if ( *(uint32_t*)DynBaseAddress(0x858D21) == 0x3539F633 )
			{
				// newsteam r1
				*GetVer() = 3;
				*GetEuropean() = false;
				return true;
			}
			return false;
		}

		inline bool TryMatch_newsteam_r2()
		{
			if ( *(uint32_t*)DynBaseAddress(0x858D51) == 0x3539F633 )
			{
				// newsteam r2
				*GetVer() = 4;
				*GetEuropean() = false;
				return true;
			}
			return false;
		}

		inline bool TryMatch_newsteam_r2_lv()
		{
			if ( *(uint32_t*)DynBaseAddress(0x858C61) == 0x3539F633 )
			{
				// newsteam r2 lv
				*GetVer() = 5;
				*GetEuropean() = false;
				return true;
			}
			return false;
		}

		inline void InitializeVersions()
		{
			if ( *GetVer() == -1 )
			{
				if ( TryMatch_10() ) return;
				if ( TryMatch_11() ) return;
				if ( TryMatch_30() ) return;
				if ( TryMatch_newsteam_r1() ) return;
				if ( TryMatch_newsteam_r2() ) return;
				if ( TryMatch_newsteam_r2_lv() ) return;
			}
		}

		inline void InitializeRegion_10()
		{
			signed char*	bVer = GetVer();

			if ( *bVer == -1 )
			{
				if ( !TryMatch_10() )
				{
		#ifdef assert
					assert(!"AddressByRegion_10 on non-1.0 EXE!");
		#endif
				}
			}
		}

		inline void InitializeRegion_11()
		{
			signed char*	bVer = GetVer();

			if ( *bVer == -1 )
			{
				if ( !TryMatch_11() )
				{
		#ifdef assert
					assert(!"AddressByRegion_11 on non-1.01 EXE!");
		#endif
				}
			}
		}

		inline uintptr_t AdjustAddress_10(uintptr_t address10)
		{
			if ( *GetEuropean() )
			{		
				if ( address10 >= 0x746720 && address10 < 0x857000 )
				{
					if ( address10 >= 0x7BA940 )
						address10 += 0x40;
					else
						address10 += 0x50;
				}
			}
			return address10;
		}

		inline uintptr_t AdjustAddress_11(uintptr_t address11)
		{
			if ( !(*GetEuropean()) && address11 > 0x746FA0 )
			{
				if ( address11 < 0x7BB240 )
					address11 -= 0x50;
				else
					address11 -= 0x40;
			}
			return address11;
		}

		inline uintptr_t AddressByVersion(AddrVariant address10, AddrVariant address11, AddrVariant addressSteam, AddrVariant addressNewsteamR2, AddrVariant addressNewsteamR2_LV)
		{
			InitializeVersions();

			signed char	bVer = *GetVer();

			switch ( bVer )
			{
			case 1:
				if ( auto pao = std::get_if<PatternAndOffset>(&address11) ) return HandlePattern( *pao );
				else
				{
					const uintptr_t addr = *std::get_if<uintptr_t>(&address11);
		#ifdef assert
					assert(addr);
		#endif

					// Safety measures - if null, return dummy var pointer to prevent a crash
					if ( addr == 0 )
						return GetDummy();

					// Adjust to US if needed
					return AdjustAddress_11(addr);
				}
			case 2:
				if ( auto pao = std::get_if<PatternAndOffset>(&addressSteam) ) return HandlePattern( *pao );
				else
				{
					const uintptr_t addr = *std::get_if<uintptr_t>(&addressSteam);
		#ifdef assert
					assert(addr);
		#endif
					// Safety measures - if null, return dummy var pointer to prevent a crash
					if ( addr == 0 )
						return GetDummy();

					return addr;
				}
			case 3:
				return GetDummy();
			case 4:
				if ( auto pao = std::get_if<PatternAndOffset>(&addressNewsteamR2) ) return HandlePattern( *pao );
				else
				{
					const uintptr_t addr = *std::get_if<uintptr_t>(&addressNewsteamR2);
		#ifdef assert
					assert(addr);
		#endif
					if ( addr == 0 )
						return GetDummy();

					return DynBaseAddress(addr);
				}
			case 5:
				if ( auto pao = std::get_if<PatternAndOffset>(&addressNewsteamR2) ) return HandlePattern( *pao );
				else
				{
					const uintptr_t addr = *std::get_if<uintptr_t>(&addressNewsteamR2_LV);
		#ifdef assert
					assert(addr);
		#endif
					if ( addr == 0 )
						return GetDummy();

					return DynBaseAddress(addr);
				}
			default:
				if ( auto pao = std::get_if<PatternAndOffset>(&address10) ) return HandlePattern( *pao );
				else
				{
					const uintptr_t addr = *std::get_if<uintptr_t>(&address10);
		#ifdef assert
					assert(addr);
		#endif
					// Adjust to EU if needed
					return AdjustAddress_10(addr);
				}
			}
		}

		inline uintptr_t AddressByRegion_10(uintptr_t address10)
		{
			InitializeRegion_10();

			// Adjust to EU if needed
			return AdjustAddress_10(address10);
		}

		inline uintptr_t AddressByRegion_11(uintptr_t address11)
		{
			InitializeRegion_11();

			// Adjust to US if needed
			return AdjustAddress_11(address11);
		}

#else

		inline void InitializeVersions()
		{
		}

#endif

#if defined _GTA_III || defined _GTA_VC

		inline uintptr_t AddressByVersion(uintptr_t address10, uintptr_t address11, uintptr_t addressSteam)
		{
			InitializeVersions();

			signed char		bVer = *GetVer();

			switch ( bVer )
			{
			case 1:
#ifdef assert
				assert(address11);
#endif
				return address11;
			case 2:
#ifdef assert
				assert(addressSteam);
#endif
				return addressSteam;
			default:
#ifdef assert
				assert(address10);
#endif
				return address10;
			}
		}

#endif

	}
}

#if defined _GTA_III || defined _GTA_VC

template<typename T>
inline T AddressByVersion(uintptr_t address10, uintptr_t address11, uintptr_t addressSteam)
{
	return T(Memory::internal::AddressByVersion( address10, address11, addressSteam ));
}

#elif defined _GTA_SA

template<typename T>
inline T AddressByVersion(Memory::AddrVariant address10, Memory::AddrVariant address11, Memory::AddrVariant addressSteam)
{
	return T(Memory::internal::AddressByVersion( std::move(address10), std::move(address11), std::move(addressSteam), 0, 0 ));
}

template<typename T>
inline T AddressByVersion(Memory::AddrVariant address10, Memory::AddrVariant address11, Memory::AddrVariant addressSteam, Memory::AddrVariant addressNewsteamR2, Memory::AddrVariant addressNewsteamR2_LV)
{
	return T(Memory::internal::AddressByVersion( std::move(address10), std::move(address11), std::move(addressSteam), std::move(addressNewsteamR2), std::move(addressNewsteamR2_LV) ));
}

template<typename T>
inline T AddressByVersion(Memory::AddrVariant address10, Memory::AddrVariant addressNewsteam)
{
	return T(Memory::internal::AddressByVersion( std::move(address10), 0, 0, addressNewsteam, addressNewsteam ));
}

template<typename T>
inline T AddressByRegion_10(uintptr_t address10)
{
	return T(Memory::internal::AddressByRegion_10(address10));
}

template<typename T>
inline T AddressByRegion_11(uintptr_t address11)
{
	return T(Memory::internal::AddressByRegion_11(address11));
}

#endif

namespace Memory
{
	struct VersionInfo
	{
		int8_t version;
		bool european;
	};

	inline VersionInfo GetVersion()
	{
		Memory::internal::InitializeVersions();
		return { *Memory::internal::GetVer(), *Memory::internal::GetEuropean() };
	}
};
