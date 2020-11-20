#include "ProcessHollowing.hpp"

ProcessHollowing::ProcessHollowing(const std::string& targetPath, const std::string& payloadPath)
{
    try
    {
        _architectureHollowing = new Hollowing64Bit(targetPath, payloadPath);
    }
    catch(...)
    {
        try
        {
            _architectureHollowing = new Hollowing32Bit(targetPath, payloadPath);
        }
        catch(...)
        {
            std::cout << "The target and the payload are incompatible!" << std::endl;
            throw "";
        }
        
    }
    
}

void ProcessHollowing::hollow()
{
    _architectureHollowing->hollow();
}