#include <stdexcept>
#include <string>

#ifndef FILE_EXCEPTION_H
#define FILE_EXCEPTION_H

class FileException : public std::runtime_error
{
public:
    FileException(const std::string& message);
};

#endif