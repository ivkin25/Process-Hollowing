#include <stdexcept>
#include <string>

#ifndef HOLLOWING_EXCEPTION_H
#define HOLLOWING_EXCEPTION_H

class HollowingException : public std::runtime_error
{
public:
    HollowingException(const std::string& message);
};

#endif