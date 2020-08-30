#pragma once

#include <Windows.h>
#include "ProcedurePointer.hpp"

class DLLFunctionsLoader
{
public:
    explicit DLLFunctionsLoader(LPCSTR dllName);
    ~DLLFunctionsLoader();
    
    ProcedurePointer operator[](LPCSTR procedureName) const;

private:
    HMODULE _module;
};