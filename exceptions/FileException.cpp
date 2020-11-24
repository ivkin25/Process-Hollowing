#include "FileException.hpp"

FileException::FileException(const std::string& message) :
    std::runtime_error(message)
{ }