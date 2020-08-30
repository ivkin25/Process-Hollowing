#pragma once

#include <type_traits>
#include <Windows.h>

class ProcedurePointer
{
public:
    explicit ProcedurePointer(FARPROC pointer);

    template <typename T, typename = std::enable_if_t<std::is_function<T>::value>>
    operator T *() const
    {
        return reinterpret_cast<T*>(_pointer);
    }

private:
    FARPROC _pointer;
};