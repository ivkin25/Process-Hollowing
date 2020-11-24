#include "IncompatibleImagesException.hpp"

IncompatibleImagesException::IncompatibleImagesException(const std::string& message) :
    std::runtime_error(message.c_str())
{ }