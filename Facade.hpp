#pragma once

// A set of helper macroes to instantiate Facade classes.
// A Facade may be used with those binaries where data layouts change between different supported versions. Instead of writing out separate class definitions
// for every layout existing in the binaries and branching on runtime, we instantiate a thin, temporary object, consisting only of references and const pointers
// that acts as a middleman between the hook code and the underlying object, redirecting writes and reads according to the data layout read from the binary on runtime.

// To set up a Facade class interfacing a theoretical DynamicClass:
// 1. Define a DynamicClassFacade class (or any other name).
// 2. For every field of DynamicClass, declare a Facade field using:
//    * FACADE_MEMBER(type, name) - if the field is present in all versions of the binary.
//    * FACADE_OPTIONAL_MEMBER(type, name) - if the field is present only in some versions.
//    * FACADE_STABLE_MEMBER(type, name, offset) - if the field has an offset that is guaranteed to be consistent across binaries.
// 3. Define a DynamicClassFacade constructor taking a DynamicClass* as an argument, and for every Facade field, include FACADE_INIT_MEMBER(obj, name) in the initializer list.
//    If you forget to include any fields, you will get a compilation error.
// 4. In the place where you'd usually read/modify the binary's code, locate the class field offsets on runtime (e.g. with Patterns), or hardcode them according to the binary version
//    (not recommended). Use FACADE_SET_MEMBER_OFFSET(class, name, offset) to set that offset. If you forget to set any fields,
//    you will get an assertion error when the Facade class is instantiated.
//    * If the binary lacks an optional field, use FACADE_MARK_MEMBER_ABSENT(class, name) to signal that to the Facade.

// Facade classes should be instantiated on demand and kept on the stack, avoid persisting them. In every place in the code you want to read or write to the DynamicClass object,
// instantiate a Facade instead:
// DynamicClassFacade facade(obj);
// And then read/write from/to the Facade object as if it was a DynamicClass object.
// Mandatory fields have semantics as close to values as possible (with one exception, read below), while optional fields have std::optional-like semantics,
// where a boolean operator can be used to determine if the field is present in the binary, and the field is used like a pointer.
// Other than the implicit conversion operators, both mandatory and optional fields offer a .value() method, identical to std::optional.
// Optional fields also offer .value_or(default_value) and has_value().

// The runtime cost is expected to be negligible, regardless of how many fields a Facade defines. Fully optimized, non-debug builds appear to only initialize the specific fields
// that are used in a particular context, so if a Facade with 200 fields is used in a function that only accesses 2 of them, only those 2 fields should be initialized,
// the remaining initializations are easily optimized out.

// VIRTUAL METHODS:
// When calling virtual methods of DynamicClass, you can use the original pointer directly, using a Facade for this provides no benefit.
// HOWEVER, if the virtual method table layout changes across binary versions, you can read the VMT pointer (typically the first pointer in the class)
// and then set up a Facade of __thiscall function pointers or method pointers over it. Then, you can use the Facade as you would use real virtual methods,
// except you need to explicitly pass DynamicClass* as the first argument to each call (as a 'this' pointer).
// Similarly, optional Facade members may be used to call virtual methods that may be absent from specific binary versions.
// You can define and use method Facades in one of the two ways:
// 1. FACADE_MEMBER(void(__thiscall*)(DynamicClass* _this, /*args...*/), m_methodPtr);
//    Usage: facade.m_methodPtr(obj, /*args...*/);
//
// 2. FACADE_MEMBER(void(DynamicClass::*)(/*args...*/), m_methodPtr);
//    Usage: (obj->*facade.m_methodPtr.value())(/*args...*/);
//      (in this case, the use of .value() is mandatory)

// GOTCHAS AND USAGE LIMITATIONS:
// 1. Class fields that are classes themselves cannot have their fields accessed through the dot operator. Use operator -> or .value(), much like when dereferencing a std::reference_wrapper.
//    BAD:
//      facade.innerClass.count = 0;
//    GOOD:
//      facade.innerClass->count = 0;
//     OR:
//      facade.innerClass.value().count = 0;
// 2. Const object pointers can only be used to instantiate Facades where -all- fields are const. This might be fine for small Facade classes, but gets out of control with more fields quickly.
//    As an alternative, consider constructing a const Facade class from an object pointer with constness casted away (if present):
//      const DynamicClassFacade facade(std::remove_const(obj));
//    Const Facades behave like const objects, and they forbid any writes to the underlying class fields.
// 3. C-style arrays cannot be Facade members. Use std::array, as it is guaranteed to have an identical layout to a plain C array.
// 4. FACADE_MEMBER cannot accept template types with a comma in it (like an aforementioned std::array). Use a typedef or an 'using' type alias.

#include <cassert>
#include <cstddef>
#include <memory>
#include <type_traits>
#include <utility>

namespace facade::details
{
	static constexpr std::size_t MEMBER_UNINITIALIZED = static_cast<std::size_t>(-1);
	static constexpr std::size_t MEMBER_ABSENT = static_cast<std::size_t>(-2);

	template<typename T>
	class field_wrapper
	{
	public:
		using is_optional = std::false_type;

		field_wrapper(void* obj, size_t offset)
			: m_ref(*reinterpret_cast<T*>(reinterpret_cast<char*>(obj) + offset))
		{
			assert(offset != MEMBER_UNINITIALIZED);
		}

		field_wrapper(const void* obj, size_t offset)
			: m_ref(*reinterpret_cast<T*>(reinterpret_cast<const char*>(obj) + offset))
		{
			static_assert(std::is_const_v<T>, "Facades constructed from a const object may only have const fields");
			assert(offset != MEMBER_UNINITIALIZED);
		}

		field_wrapper() = delete;

		inline field_wrapper& operator=(const T& val)
		{
			m_ref = val;
			return *this;
		}
		inline field_wrapper& operator=(T&& val)
		{
			m_ref = std::move(val);
			return *this;
		}

		template<typename... Args>
		inline decltype(auto) operator[](Args&&... args) { return m_ref.operator[](std::forward<Args>(args)...); }
		template<typename... Args>
		inline decltype(auto) operator[](Args&&... args) const { return std::as_const(m_ref).operator[](std::forward<Args>(args)...); }

		template<typename... Args>
		inline decltype(auto) operator()(Args&&... args) { return m_ref(std::forward<Args>(args)...); }
		template<typename... Args>
		inline decltype(auto) operator()(Args&&... args) const { return std::as_const(m_ref)(std::forward<Args>(args)...); }

		inline T& value() { return m_ref; }
		inline const T& value() const { return m_ref; }

		inline operator T&() { return m_ref; }
		inline operator const T&() const { return m_ref; }
		inline T* operator->() { return std::addressof(m_ref); }
		inline const T* operator->() const { return std::addressof(m_ref); }
		inline decltype(auto) operator*() { return *m_ref; }
		inline decltype(auto) operator*() const { return *std::as_const(m_ref); }

	private:
		T& m_ref;
	};

	template<typename T>
	class optional_field_wrapper
	{
	public:
		using is_optional = std::true_type;

		optional_field_wrapper(void* obj, size_t offset)
			: m_ptr(offset != MEMBER_ABSENT ? reinterpret_cast<T*>(reinterpret_cast<char*>(obj) + offset) : nullptr)
		{
			assert(offset != MEMBER_UNINITIALIZED);
		}

		optional_field_wrapper(const void* obj, size_t offset)
			: m_ptr(offset != MEMBER_ABSENT ? reinterpret_cast<T*>(reinterpret_cast<const char*>(obj) + offset) : nullptr)
		{
			static_assert(std::is_const_v<T>, "Facades constructed from a const object may only have const fields");
			assert(offset != MEMBER_UNINITIALIZED);
		}

		optional_field_wrapper() = delete;

		inline bool has_value() const { return m_ptr != nullptr; }

		inline T& value() { return **this; }
		inline const T& value() const { return **this; }

		template<typename U = std::remove_cv_t<T>>
		inline T value_or(U&& default_value) const
		{
			return has_value() ? **this : static_cast<T>(std::forward<U>(default_value));
		}

		inline explicit operator bool() const { return has_value(); }

		inline T* operator->() { assert(m_ptr != nullptr); return m_ptr; }
		inline const T* operator->() const { assert(m_ptr != nullptr); return m_ptr; }
		inline T& operator*() { assert(m_ptr != nullptr); return *m_ptr; }
		inline const T& operator*() const { assert(m_ptr != nullptr); return *std::as_const(m_ptr); }

	private:
		T* const m_ptr;
	};
}

#define FACADE_MEMBER(type, name) \
	facade::details::field_wrapper<type> name; \
	static inline std::size_t _offs_ ## name = facade::details::MEMBER_UNINITIALIZED;

#define FACADE_OPTIONAL_MEMBER(type, name) \
	facade::details::optional_field_wrapper<type> name; \
	static inline std::size_t _offs_ ## name = facade::details::MEMBER_UNINITIALIZED;

#define FACADE_STABLE_MEMBER(type, name, offset) \
	facade::details::field_wrapper<type> name; \
	static constexpr std::size_t _offs_ ## name = offset;

#define FACADE_INIT_MEMBER(obj, name) \
	name(obj, _offs_ ## name)

#define FACADE_SET_MEMBER_OFFSET(cls, name, offset) \
	cls::_offs_ ## name = offset;

#define FACADE_MARK_MEMBER_ABSENT(cls, name) \
	static_assert(decltype(cls:: ## name)::is_optional::value, "Only optional facade members can be marked absent"); cls::_offs_ ## name = facade::details::MEMBER_ABSENT;
