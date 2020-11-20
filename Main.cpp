#include "HollowingFunctions.hpp"
#include "Hollowing64Bit.hpp"
#include "Hollowing32Bit.hpp"
#include <string>

template<typename T>
bool tryConstructProcessHollowing(HollowingFunctions** value, const std::string target, const std::string& payload)
{
    try
    {
        *value = new T(target, payload);

        return true;
    }
    catch (...)
    {
        return false;
    }
}

int main(int argc, char* argv[])
{
    return 0;
}