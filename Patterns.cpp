/*
 * This file is part of the CitizenFX project - http://citizen.re/
 *
 * See LICENSE and MENTIONS in the root of the source tree for information
 * regarding licensing.
 */

#include "Patterns.h"

#define WIN32_LEAN_AND_MEAN

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <algorithm>

#if PATTERNS_USE_HINTS
#include <map>
#endif


#if PATTERNS_USE_HINTS

// from boost someplace
template <std::uint64_t FnvPrime, std::uint64_t OffsetBasis>
struct basic_fnv_1
{
	std::uint64_t operator()(std::string_view text) const
	{
		std::uint64_t hash = OffsetBasis;
		for (auto it : text)
		{
			hash *= FnvPrime;
			hash ^= it;
		}

		return hash;
	}
};

static constexpr std::uint64_t fnv_prime = 1099511628211u;
static constexpr std::uint64_t fnv_offset_basis = 14695981039346656037u;

typedef basic_fnv_1<fnv_prime, fnv_offset_basis> fnv_1;

#endif

namespace hook
{
static scan_segments get_all_sections_with_flag_internal(void* module, uint32_t flag)
{
	scan_segments result;

	assert(module != nullptr);

	const intptr_t moduleBase = reinterpret_cast<intptr_t>(module);
	PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
	PIMAGE_NT_HEADERS ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(moduleBase + dosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);

	bool bCanMerge = false;
	for (SIZE_T i = 0, j = ntHeader->FileHeader.NumberOfSections; i < j; ++i)
	{
		if ((section[i].Characteristics & flag) != 0)
		{
			const intptr_t start = moduleBase + section[i].VirtualAddress;
			const intptr_t end = start + section[i].Misc.VirtualSize;
			if (bCanMerge)
			{
				// Merge adjacent sections, as there's technically nothing preventing patterns from crossing them.
				if (result.back().second == start)
				{
					result.back().second = end;
					continue;
				}
			}

			result.emplace_back(start, end);
			bCanMerge = true;
		}
	}

	return result;
}

scan_segments get_all_readable_sections(void* module)
{
	return get_all_sections_with_flag_internal(module, IMAGE_SCN_MEM_READ);
}

scan_segments get_all_code_sections(void* module)
{
	return get_all_sections_with_flag_internal(module, IMAGE_SCN_CNT_CODE);
}

scan_segments get_section_by_name(void* module, std::string_view name)
{
	scan_segments result;

	assert(module != nullptr);

	const intptr_t moduleBase = reinterpret_cast<intptr_t>(module);
	PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
	PIMAGE_NT_HEADERS ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(moduleBase + dosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);

	for (SIZE_T i = 0, j = ntHeader->FileHeader.NumberOfSections; i < j; ++i)
	{
		const char* NameCh = reinterpret_cast<const char*>(section[i].Name);
		if (std::string_view(NameCh, strnlen_s(NameCh, std::size(section[i].Name))) == name)
		{
			const intptr_t start = moduleBase + section[i].VirtualAddress;
			const intptr_t end = start + section[i].Misc.VirtualSize;
			result.emplace_back(start, end);
		}
	}

	return result;
}


const scan_segments& details::get_default_scan_segments()
{
	static const scan_segments defaultSegments = get_all_readable_sections(GetModuleHandle(nullptr));
	return defaultSegments;
}

#if PATTERNS_USE_HINTS
static auto& getHints()
{
	static std::multimap<uint64_t, uintptr_t> hints;
	return hints;
}
#endif

static void TransformPattern(std::string_view pattern, pattern_string& data, pattern_string& mask)
{
	uint8_t tempDigit = 0;
	bool tempFlag = false;

	auto tol = [] (char ch) -> uint8_t
	{
		if (ch >= 'A' && ch <= 'F') return uint8_t(ch - 'A' + 10);
		if (ch >= 'a' && ch <= 'f') return uint8_t(ch - 'a' + 10);
		return uint8_t(ch - '0');
	};

	for (auto ch : pattern)
	{
		if (ch == ' ')
		{
			continue;
		}
		else if (ch == '?')
		{
			data.push_back(0);
			mask.push_back(0);
		}
		else if ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f'))
		{
			uint8_t thisDigit = tol(ch);

			if (!tempFlag)
			{
				tempDigit = thisDigit << 4;
				tempFlag = true;
			}
			else
			{
				tempDigit |= thisDigit;
				tempFlag = false;

				data.push_back(tempDigit);
				mask.push_back(0xFF);
			}
		}
	}
}

namespace details
{

void basic_pattern_impl::Initialize(std::string_view pattern)
{
	// get the hash for the base pattern
#if PATTERNS_USE_HINTS
	m_hash = fnv_1()(pattern);
#endif

	// transform the base pattern from IDA format to canonical format
	TransformPattern(pattern, m_bytes, m_mask);

#if PATTERNS_USE_HINTS
	// if there's hints, try those first
#if PATTERNS_CAN_SERIALIZE_HINTS
	if (m_rangeStart == reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr)))
#endif
	{
		auto range = getHints().equal_range(m_hash);

		if (range.first != range.second)
		{
			std::for_each(range.first, range.second, [&] (const auto& hint)
			{
				ConsiderHint(hint.second);
			});

			// if the hints succeeded, we don't need to do anything more
			if (!m_matches.empty())
			{
				m_matched = true;
				return;
			}
		}
	}
#endif
}

void basic_pattern_impl::EnsureMatches(uint32_t maxCount)
{
	if (m_matched)
	{
		return;
	}

	auto matchSuccess = [this, maxCount] (uintptr_t address)
	{
#if PATTERNS_USE_HINTS
		getHints().emplace(m_hash, address);
#else
		(void)address;
#endif

		return (m_matches.size() == maxCount);
	};

	const uint8_t* pattern = m_bytes.data();
	const uint8_t* mask = m_mask.data();
	const size_t maskSize = m_mask.size();
	const size_t lastWild = m_mask.find_last_not_of(uint8_t(0xFF));

	ptrdiff_t Last[256];

	std::fill(std::begin(Last), std::end(Last), lastWild == std::string::npos ? -1 : static_cast<ptrdiff_t>(lastWild) );

	for ( ptrdiff_t i = 0; i < static_cast<ptrdiff_t>(maskSize); ++i )
	{
		if ( Last[ pattern[i] ] < i )
		{
			Last[ pattern[i] ] = i;
		}
	}

	for (const auto& segment : m_scanSegments)
	{
		for (intptr_t i = segment.first, end = segment.second - maskSize; i <= end;)
		{
			uint8_t* ptr = reinterpret_cast<uint8_t*>(i);
			ptrdiff_t j = maskSize - 1;

			while((j >= 0) && pattern[j] == (ptr[j] & mask[j])) j--;

			if(j < 0)
			{
				m_matches.emplace_back(ptr);

				if (matchSuccess(i))
				{
					break;
				}
				i++;
			}
			else i += std::max(ptrdiff_t(1), j - Last[ ptr[j] ]);
		}
	}

	m_matched = true;
}

bool basic_pattern_impl::ConsiderHint(uintptr_t offset)
{
	uint8_t* ptr = reinterpret_cast<uint8_t*>(offset);

#if PATTERNS_CAN_SERIALIZE_HINTS
	const uint8_t* pattern = m_bytes.data();
	const uint8_t* mask = m_mask.data();

	for (size_t i = 0, j = m_mask.size(); i < j; i++)
	{
		if (pattern[i] != (ptr[i] & mask[i]))
		{
			return false;
		}
	}
#endif

	m_matches.emplace_back(ptr);

	return true;
}

#if PATTERNS_USE_HINTS && PATTERNS_CAN_SERIALIZE_HINTS
void basic_pattern_impl::hint(uint64_t hash, uintptr_t address)
{
	auto& hints = getHints();

	auto range = hints.equal_range(hash);

	for (auto it = range.first; it != range.second; ++it)
	{
		if (it->second == address)
		{
			return;
		}
	}

	hints.emplace(hash, address);
}
#endif

}
}
