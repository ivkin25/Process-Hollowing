#include "ImageWindowsBitnessException.hpp"

ImageWindowsBitnessException::ImageWindowsBitnessException(const std::string& message) :
    std::runtime_error(message.c_str())
{ }