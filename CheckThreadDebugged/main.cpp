#include <winternl.h>
#include <iostream>
#include "CurrentThreadStatus.h"

int main()
{
    CurrentThreadStatus current_thread_status;

    // while (true)
    // {
        if (current_thread_status.IsHandleOpenedByExternalProcess())
        {
            std::cout << "Current thread is opened by external process." << std::endl;
        }
        Sleep(5000);
    // }
}