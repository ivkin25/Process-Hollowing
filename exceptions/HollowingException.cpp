#include "HollowingException.hpp"

HollowingException::HollowingException(const std::string& message) :
    std::runtime_error(message)
{ }