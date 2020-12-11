#include "HollowingInterface.hpp"
#ifdef _WIN64
    #include "Hollowing64Bit.hpp"
#endif
#include "Hollowing32Bit.hpp"
#include "exceptions/IncompatibleImagesException.hpp"
#include <string>
#include <iostream>
#include <memory>

const int IMAGE_PATH_ARGUMENT_INDEX = 0;
const int TARGET_PATH_ARGUMENT_INDEX = 1;
const int PAYLOAD_PATH_ARGUMENT_INDEX = 2;
const int REQUIRED_COMMAND_LINE_ARGUMENTS = 2 + 1; // Plus one because of the always-included path of the image

template<typename T>
bool tryConstructProcessHollowing(std::unique_ptr<HollowingInterface>& holderPointer, std::string& exceptionMessage,
    const std::string& targetPath, const std::string& payloadPath)
{
    try
    {
        holderPointer = std::make_unique<T>(targetPath, payloadPath);

        return true;
    }
    catch (IncompatibleImagesException& exception)
    {
        exceptionMessage = exception.what();

        return false;
    }
}

int main(int argc, char* argv[])
{
    if (argc < REQUIRED_COMMAND_LINE_ARGUMENTS)
    {
        std::cerr << "Not enough arguments!" << std::endl;
        std::cerr << "Format: " + std::string(argv[IMAGE_PATH_ARGUMENT_INDEX]) + " <Target_Path> <Payload_Path>" << std::endl;

        return 1;
    }

    std::unique_ptr<HollowingInterface> hollowing;
    std::string targetPath(argv[TARGET_PATH_ARGUMENT_INDEX]);
    std::string payloadPath(argv[PAYLOAD_PATH_ARGUMENT_INDEX]);

#ifdef _WIN64
    std::string hollowing64Exception;
    std::string hollowing32Exception;

    if (!(tryConstructProcessHollowing<Hollowing64Bit>(hollowing, hollowing64Exception, targetPath, payloadPath) ||
          tryConstructProcessHollowing<Hollowing32Bit>(hollowing, hollowing32Exception, targetPath, payloadPath)))
    {
        std::cerr << "Failed to hollow 64 bit: " << hollowing64Exception << std::endl;
        std::cerr << "Failed to hollow 32 bit: " << hollowing32Exception << std::endl;
        std::cerr << std::endl << "Cannot proceed!" << std::endl;

        return 1;
    }
#else
    std::string exceptionMessage;

    if (!tryConstructProcessHollowing<Hollowing32Bit>(hollowing, exceptionMessage, targetPath, payloadPath))
    {
        std::cerr << "Failed to hollow 32 bit: " << exceptionMessage << std::endl;
        std::cerr << std::endl << "Cannot proceed!" << std::endl;

        return 1;
    }
#endif

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