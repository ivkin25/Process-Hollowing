#include <stdexcept>
#include <string>

#ifndef IMAGE_WINDOWS_BITNESS_EXCEPTION_H
#define IMAGE_WINDOWS_BITNESS_EXCEPTION_H

class ImageWindowsBitnessException : public std::runtime_error
{
public:
    ImageWindowsBitnessException(const std::string& message);
};

#endif