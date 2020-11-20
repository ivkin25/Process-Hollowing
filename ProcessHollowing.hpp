#include "HollowingFunctions.hpp"
#include "Hollowing64Bit.hpp"
#include "Hollowing32Bit.hpp"

#ifndef PROCESS_HOLLOWING_H
#define PROCESS_HOLLOWING_H

class ProcessHollowing
{
public:
    ProcessHollowing(const std::string& targetPath, const std::string& payloadPath);
    
    void hollow();

private:
    HollowingFunctions* _architectureHollowing;
};

#endif