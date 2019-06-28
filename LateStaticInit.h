#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <functional>


class LateStaticInit
{
public:
	explicit LateStaticInit( std::function<void()> func )
		: m_initFunc( std::move(func) )
	{
		m_next = ms_head;
		ms_head = this;
	}

	static bool TryApplyWithPredicate(std::function<bool()> pred)
	{
		if (pred())
		{
			// Predicate succeeded - immediately apply everything and return
			Apply();
			return true;
		}

		ms_predicate = std::move(pred);

		// Predicate failed - create a thread and keep trying the predicate until it succeeds
		HANDLE initThread = CreateThread( nullptr, 0, ThreadProc, nullptr, 0, nullptr );
		SetThreadPriority( initThread, THREAD_PRIORITY_ABOVE_NORMAL );
		CloseHandle( initThread );

		return false;
	}

private:
	static void Apply()
	{
		LateStaticInit* head = nullptr;
		std::swap( head, ms_head );

		while ( head != nullptr )
		{
			head->m_initFunc();
			head = head->m_next;
		}
	}

	static DWORD WINAPI ThreadProc( LPVOID lpParameter )
	{
		while ( true )
		{
			const bool predicateResult = ms_predicate();
			Sleep(1); // Deliberarely sleeping AFTER checking the predicate!
			if ( predicateResult )
			{
				Apply();
				break;
			}
		}

		return 0;
	}

	std::function<void()> m_initFunc;
	LateStaticInit* m_next;

	static inline LateStaticInit* ms_head = nullptr;
	static inline std::function<bool()> ms_predicate;
};

#define LATE_STATIC_INIT_INTERNAL( func, suffix ) static LateStaticInit __LATESTATICINIT__ ## suffix( [&]() { func } )

#define LATE_STATIC_INIT( prefix, func ) LATE_STATIC_INIT_INTERNAL( func, prefix )
