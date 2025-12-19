
#ifndef HYSBURG_ANY_H
#define HYSBURG_ANY_H

#include <typeinfo>
#include <new>
#include <memory>

#include "Util.hpp"

namespace hysburg
{

struct Any
{
    void(*deleter)(void *) = nullptr;
    const std::type_info &type;
    char buff[0];

    explicit Any(const std::type_info &tp) noexcept: type(tp)
    {}

    NO_COPY(Any)

    template<typename T>
    T* as() noexcept
    {
        return reinterpret_cast<T*>(buff);
    }

    template<typename T>
    T* is() noexcept
    {
        return LIKELY(typeid(T) == type) ? reinterpret_cast<T*>(buff) : nullptr;
    }
};

}


namespace std
{
    template <>
    struct default_delete<hysburg::Any>
    {
        void operator()(hysburg::Any *any) const noexcept
        {
            any->deleter(any->buff);
            free(any);
        }
    };
}

namespace hysburg
{
    using AnyPtr = std::unique_ptr<Any>;

    template <typename T, typename ...Args>
    AnyPtr makeAny(Args&&... args) {
        auto ptr = ::new(malloc(sizeof(Any) + sizeof(T)))Any(typeid(T));
        ptr->deleter = [](void *ptr) { std::destroy_at(static_cast<T*>(ptr)); };
        ::new (ptr->buff) T(std::forward<Args>(args)...);
        return AnyPtr(ptr);
    }

    template <typename T, typename ...Args>
    T* makeAnyIn(AnyPtr &out, Args&&... args) {
        out = makeAny<T>(std::forward<Args>(args)...);
        return out->as<T>();
    }
}


#endif // HYSBURG_ANY_H