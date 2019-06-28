#pragma once

template<typename T>
class BasicDelimStringReader
{
public:
	BasicDelimStringReader( size_t size )
		: m_buffer( new T[size] ), m_size( size )
	{
		Reset();
	}

	~BasicDelimStringReader()
	{
		delete[] m_buffer;
	}

	inline T* GetBuffer() const
	{
		return m_buffer;
	}

	inline size_t GetSize() const
	{
		return m_size;
	}

	const T* GetString( size_t* size = nullptr )
	{
		if ( *m_cursor == '\0' )
		{
			if ( size != nullptr ) *size = 0;
			return nullptr;
		}
		const T* curString = m_cursor;
		size_t len = 0;

		while ( *m_cursor++ != '\0' ) len++;

		if ( size != nullptr ) *size = len;
		return curString;
	}

	inline void Reset()
	{
		m_cursor = m_buffer;
	}

private:
	T* const m_buffer;
	const T* m_cursor;
	const size_t m_size;
};

typedef BasicDelimStringReader<char> DelimStringReader;
typedef BasicDelimStringReader<wchar_t> WideDelimStringReader;