#pragma once

#include <Windows.h>

class ProcedurePointer
{
public:
    explicit ProcedurePointer(FARPROC pointer);

    template <typename T>
    operator T *() const
    {
        return reinterpret_cast<T*>(_pointer);
    }

private:
    FARPROC _pointer;
};