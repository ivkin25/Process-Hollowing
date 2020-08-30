#include "DLLFunctionsLoader.hpp"

DLLFunctionsLoader::DLLFunctionsLoader(LPCSTR dllName) :
    _module(LoadLibraryA(dllName))
{}

DLLFunctionsLoader::~DLLFunctionsLoader()
{
    FreeLibrary(_module);
}

ProcedurePointer DLLFunctionsLoader::operator[](LPCSTR procedureName) const
{
    return ProcedurePointer(GetProcAddress(_module, procedureName));
}