// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.
//
// Machinery for creating type-erased interface classes with value semantics.
// Needs help through an external Python script generating a bunch of boiler
// plate code.

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>

#include <hilti/base/intrusive-ptr.h>
#include <hilti/base/optional-ref.h>
#include <hilti/base/util.h>

namespace hilti::util::type_erasure {

// If this defined, we track the number of type-erased instances by their
// actual type, and then print out a summary of the top types at the end as
// part of the timing summary.
//
// #define HILTI_TYPE_ERASURE_PROFILE

namespace trait {
class TypeErased {};
class Singleton {};
} // namespace trait

namespace detail {

#ifdef HILTI_TYPE_ERASURE_PROFILE
struct Counters {
    int64_t max = 0;
    int64_t current = 0;

    void increment() {
        ++max;
        ++current;
    }
    void decrement() { --current; }
};

inline auto& instance_counters() {
    static std::unordered_map<std::string, Counters> global_counters;
    return global_counters;
}
#endif

} // namespace detail

extern void summary(std::ostream& out);

/** Internal base class defining the type-erased interface. */
class ConceptBase : public intrusive_ptr::ManagedObject {
public:
    virtual const std::type_info& typeid_() const = 0;
    virtual std::string typename_() const = 0;
    virtual uintptr_t identity() const = 0; // Returns unique identity of current value

    // For internal use only.
    virtual std::pair<const ConceptBase*, const void*> _childAs(const std::type_info& ti) const = 0;
    virtual std::pair<ConceptBase*, void*> _childAs(const std::type_info& ti) = 0;
};

/** Internal base class for implementation of type-erased concept. */
template<typename T, typename Concept, typename... ConceptArgs>
class ModelBase : public Concept {
public:
    ModelBase(T data, ConceptArgs&&... args) : Concept(std::forward<ConceptArgs>(args)...), _data(std::move(data)) {
#ifdef HILTI_TYPE_ERASURE_PROFILE
        detail::instance_counters()[typeid(T).name()].increment();
#endif
    }

    ~ModelBase() override {
#ifdef HILTI_TYPE_ERASURE_PROFILE
        detail::instance_counters()[typeid(T).name()].decrement();
#endif
    }

    ModelBase() = delete;
    ModelBase(const ModelBase&) = default;
    ModelBase(ModelBase&&) noexcept = default;
    ModelBase& operator=(const ModelBase&) = default;
    ModelBase& operator=(ModelBase&&) noexcept = default;


    const T& data() const { return this->_data; }
    T& data() { return _data; }

    uintptr_t identity() const final {
        if constexpr ( std::is_base_of<trait::TypeErased, T>::value )
            return _data.data()->identity(); // NOLINT

        return reinterpret_cast<uintptr_t>(&_data);
    }

    const std::type_info& typeid_() const final { return typeid(T); }

    std::string typename_() const final {
        // Get the inner name if we store a type erased type in turn.
        if constexpr ( std::is_base_of<trait::TypeErased, T>::value )
            return data().typename_(); // NOLINT

        return hilti::util::typename_<T>();
    }

    std::pair<const ConceptBase*, const void*> _childAs(const std::type_info& ti) const final {
        const ConceptBase* base = nullptr;

        if constexpr ( std::is_base_of<trait::TypeErased, T>::value )
            base = _data.data().get(); //NOLINT

        if ( typeid(_data) == ti )
            return {base, &_data};

        return {base, nullptr};
    }

    std::pair<ConceptBase*, void*> _childAs(const std::type_info& ti) final {
        ConceptBase* base = nullptr;

        if constexpr ( std::is_base_of<trait::TypeErased, T>::value )
            base = _data.data().get(); //NOLINT

        if ( typeid(_data) == ti )
            return {base, &_data};

        return {base, nullptr};
    }

private:
    T _data;
};

/** Base class for the publicly visible, type-erased interface class. */
template<typename Trait, typename Concept, template<typename T> typename Model, typename... ConceptArgs>
class ErasedBase : public trait::TypeErased {
public:
    ErasedBase() = default;
    ErasedBase(const ErasedBase& other) = default;
    ErasedBase(ErasedBase&& other) noexcept = default;
    ErasedBase& operator=(const ErasedBase& other) = default;
    ErasedBase& operator=(ErasedBase&& other) noexcept = default;
    virtual ~ErasedBase() = default; // Make class polymorphic

    template<typename T, IF_DERIVED_FROM(T, Trait)>
    ErasedBase(T t, ConceptArgs&&... args)
        : _data(make_intrusive<Model<T>>(std::move(t), std::forward<ConceptArgs>(args)...)) {}

    ErasedBase& operator=(IntrusivePtr<Concept> data) {
        _data = std::move(data);
        ;
        return *this;
    }

    /**
     * Returns type information for the contained type. If multiple
     * type-erased objects are nested, it will return the information for the
     * inner-most type.
     */
    const std::type_info& typeid_() const {
        assert(_data);
        return _data->typeid_();
    }

    /**
     * Returns C++ type name for the contained type. If multiple type-erased
     * objects are nested, it will return the information for the inner-most
     * type.
     */
    std::string typename_() const { return _data ? _data->typename_() : "<nullptr>"; }

    /**
     * Casts the contained object into a specified type. This will aborts
     * execution if the cast is not possible.
     */
    template<typename T>
    const T& as() const {
        if ( auto p = _tryAs<T>() )
            return *p;

        std::cerr << hilti::util::fmt("internal error: unexpected type, want %s but have %s",
                                      hilti::util::typename_<T>(), typename_())
                  << std::endl;
        hilti::util::abort_with_backtrace();
    }

    /**
     * Casts the contained object into a specified type. This will aborts
     * execution if the cast is not possible.
     */
    template<typename T>
    T& as() {
        if ( auto p = _tryAs<T>() )
            return *p;

        std::cerr << hilti::util::fmt("internal error: unexpected type, want %s but have %s",
                                      hilti::util::typename_<T>(), typename_())
                  << std::endl;
        hilti::util::abort_with_backtrace();
    }

    /**
     * Returns true if the contained object can be casted into a specified
     * type.
     */
    template<typename T>
    bool isA() const {
        return _tryAs<T>() != nullptr;
    }

    /** Attempts to cast the contained object into a specified type. */
    template<typename T>
    optional_ref<const T> tryAs() const {
        if ( auto p = _tryAs<T>() )
            return *p;

        return {};
    }

    /** For internal use. */
    auto& data() const { return _data; }

    /** For internal use. */
    auto& data() { return _data; }

    /** For internal use. */
    uintptr_t identity() const { return _data ? _data->identity() : 0; }

private:
    template<typename T>
    const T* _tryAs() const {
        if constexpr ( std::is_base_of<ErasedBase, T>::value )
            return static_cast<const T*>(this);

        if ( typeid(Model<T>) == typeid(*_data) )
            return &(::hilti::cast_intrusive<const Model<T>>(_data))->data();

        std::pair<const ConceptBase*, const void*> c = {_data.get(), nullptr};

        while ( c.first ) {
            c = c.first->_childAs(typeid(T));

            if ( c.second )
                return static_cast<const T*>(c.second);
        }

        return nullptr;
    }

    template<typename T>
    T* _tryAs() {
        if constexpr ( std::is_base_of<ErasedBase, T>::value )
            return static_cast<T*>(this);

        if ( typeid(Model<T>) == typeid(*_data) )
            return &(hilti::cast_intrusive<Model<T>>(_data))->data();

        std::pair<ConceptBase*, void*> c = {_data.get(), nullptr};

        while ( c.first ) {
            c = c.first->_childAs(typeid(T));

            if ( c.second )
                return static_cast<T*>(c.second);
        }

        return nullptr;
    }

    // See https://stackoverflow.com/questions/18709647/shared-pointer-to-an-immutable-type-has-value-semantics
    IntrusivePtr<Concept> _data;
};

} // namespace hilti::util::type_erasure
