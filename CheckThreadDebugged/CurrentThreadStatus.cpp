#include "CurrentThreadStatus.h"
#include "util.h"

CurrentThreadStatus::CurrentThreadStatus()
{
    this->_fake_thread_handle = GetCurrentThread();
    this->_real_thread_handle = CurrentThreadStatus::GetRealThreadHandle();
}

/// @brief 检查当前线程句柄是否被外部进程打开
/// 如果被外部进程打开则记录打开进程的pid到类的open_list属性中
/// @return
/// 如果句柄被打开，则返回true
/// 如果句柄被关闭，则返回false
bool CurrentThreadStatus::IsHandleOpenedByExternalProcess()
{
    NtQuerySystemInformationPtr NtQuerySystemInformation = GetNtQuerySystemInformationPtr();
    if (NtQuerySystemInformation == nullptr)
    {
        return false;
    }

    if (!NtQuerySystemInformation)
    {
        return false;
    }

    ULONG handleInfoSize = 0x10000;
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = nullptr;

    while (true)
    {
        handleInfo = static_cast<PSYSTEM_HANDLE_INFORMATION_EX>(malloc(handleInfoSize));
        if (!handleInfo)
        {
            return false;
        }

        NTSTATUS status = NtQuerySystemInformation(SystemExtendedHandleInformation, handleInfo, handleInfoSize, &handleInfoSize);

        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            free(handleInfo);
            continue;
        }

        if (status != 0)
        {
            free(handleInfo);
            return false;
        }
        break;
    }

    uint64_t currentProcessId = GetCurrentProcessId();
    bool isOpenedByExternalProcess = false;

    for (uint32_t i = 0; i < handleInfo->handle_count; i++)
    {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handle = handleInfo->handles[i];
        if (handle.pid != currentProcessId &&
            handle.handle_value == reinterpret_cast<uint64_t>(this->_real_thread_handle) &&
            handle.pid > 4)
        {

            this->open_list.push_back(handle.pid);
            isOpenedByExternalProcess = true;
        }
    }

    free(handleInfo);
    return isOpenedByExternalProcess;
}

/// @brief 获取当前线程的真实句柄
/// @return
/// 如果获取成功，则返回当前真实线程句柄;
/// 如果获取失败则返回nullptr;
HANDLE CurrentThreadStatus::GetRealThreadHandle()
{
    // 获取当前线程的伪句柄
    HANDLE hThread = GetCurrentThread();
    HANDLE hRealHandle = nullptr;
    HANDLE hProcess = GetCurrentProcess();

    if (!DuplicateHandle(hProcess,
                         hThread,
                         hProcess,
                         &hRealHandle,
                         0,
                         false,
                         DUPLICATE_SAME_ACCESS))
    {
        return nullptr;
    }

    return hRealHandle;
}

CurrentThreadStatus::~CurrentThreadStatus()
{
    if (this->_real_thread_handle)
    {
        CloseHandle(this->_real_thread_handle);
    }

    this->_real_thread_handle = nullptr;
    this->_fake_thread_handle = nullptr;
}