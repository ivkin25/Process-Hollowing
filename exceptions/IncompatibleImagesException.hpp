#include <stdexcept>
#include <string>

#ifndef INCOMPATIBLE_IMAGES_EXCEPTION_H
#define INCOMPATIBLE_IMAGES_EXCEPTION_H

class IncompatibleImagesException : public std::runtime_error
{
public:
    IncompatibleImagesException(const std::string& message);
};

#endif