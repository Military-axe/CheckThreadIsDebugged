#pragma once
#include <Windows.h>
#include <vector>
#include <cstdint>
#include "util.h"

class CurrentThreadStatus
{
private:
    HANDLE _fake_thread_handle;
    HANDLE _real_thread_handle;

public:
    std::vector<uint16_t> open_list;

public:
    CurrentThreadStatus();
    ~CurrentThreadStatus();

    static HANDLE GetRealThreadHandle();
    bool IsHandleOpenedByExternalProcess();
};
