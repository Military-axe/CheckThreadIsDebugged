use anyhow::{Error, Result};
use log::{debug, error, info, warn};
use std::{env::set_var, ffi::c_void, io, mem::size_of, process::exit};
use windows::{
    core::PCWSTR,
    Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS},
    Win32::{
        Foundation::{
            CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, FALSE, HANDLE, LUID, NTSTATUS,
            STATUS_INFO_LENGTH_MISMATCH, STATUS_SUCCESS,
        },
        Security::{
            AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_DEBUG_NAME,
            TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_PRIVILEGES_ATTRIBUTES, TOKEN_QUERY,
        },
        System::Threading::{
            GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken, PROCESS_DUP_HANDLE,
            PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        },
    },
};

#[repr(C)]
#[derive(Debug, Clone)]
pub struct SystemHandleTableEntryInfo {
    pub unique_process_id: u16,
    pub creator_back_trace_index: u16,
    pub object_type_index: u8,
    pub handle_attributes: u8,
    pub handle_value: u16,
    pub object: *mut c_void,
    pub granted_access: u32,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct SystemHandleInformation {
    pub number_of_handles: u32,
    pub handles: [SystemHandleTableEntryInfo; 1],
}

#[derive(Debug, Clone, Default)]
pub struct HandleInfo {
    pub pid: u32,
    pub handle: HANDLE,
}

#[derive(Debug, Clone, Default)]
pub struct ThreadStatus {
    pub thread_handle: HANDLE,
    pub open_count: u32,
    pub pid_list: Vec<u32>,
}

impl ThreadStatus {
    pub fn init(&mut self) -> Result<()> {
        let thread_handle: HANDLE = unsafe { GetCurrentThread() };
        let process_handle = unsafe { GetCurrentProcess() };
        let mut real_thread_handle: HANDLE = HANDLE::default();

        unsafe {
            DuplicateHandle(
                process_handle,
                thread_handle,
                process_handle,
                &mut real_thread_handle,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )
        }?;

        self.thread_handle = real_thread_handle;
        debug!("Get current thread handle successfully");

        Ok(())
    }

    pub fn query_system_information() -> Result<Vec<u8>> {
        let mut handle_info_size: usize = 0x10000;
        let mut handle_info_buffer: Vec<u8> = Vec::with_capacity(handle_info_size);
        let mut status: NTSTATUS = STATUS_INFO_LENGTH_MISMATCH;
        let mut return_length: u32 = 0;

        while status == STATUS_INFO_LENGTH_MISMATCH {
            handle_info_buffer.clear();
            handle_info_size = return_length as usize;
            handle_info_buffer.reserve(handle_info_size);
            status = unsafe {
                NtQuerySystemInformation(
                    SYSTEM_HANDLE_INFORMATION,
                    handle_info_buffer.as_mut_ptr() as *mut c_void,
                    handle_info_size as u32,
                    &mut return_length,
                )
            };
        }

        if status != STATUS_SUCCESS {
            error!("NtQuerySystemInformation failed! status: {:?}", status);
            return Err(Error::msg("NtQuerySystemInformation failed!"));
        }

        debug!("NtQuerySystemInformation query system handle infomation successfully");

        Ok(handle_info_buffer)
    }

    pub fn check(&mut self) -> Result<()> {
        if self.thread_handle.is_invalid() {
            self.init()?;
            self.open_count = 0;
            self.pid_list.clear();
        }

        let system_information: Vec<u8> = ThreadStatus::query_system_information()?;

        let handle_info: *const SystemHandleInformation =
            system_information.as_ptr() as *const SystemHandleInformation;
        let handle_info_ref: &SystemHandleInformation = unsafe { &*handle_info };
        let handles_ptr: *const SystemHandleTableEntryInfo = handle_info_ref.handles.as_ptr();

        for i in 0..handle_info_ref.number_of_handles {
            let handle: *const SystemHandleTableEntryInfo = unsafe { handles_ptr.add(i as usize) };
            let real_handle_info: HandleInfo;
            unsafe {
                let uid: u32 = (*handle).unique_process_id.into();
                let val: u32 = (*handle).handle_value.into();

                if uid <= 4 {
                    continue;
                }

                match copy_handle(uid, val) {
                    Ok(data) => real_handle_info = data,
                    Err(err) => {
                        warn!("copy process {:?} handle {:?} error: {:?}", uid, val, err);
                        continue;
                    }
                }
                debug!("{:?}", real_handle_info);
            }

            if real_handle_info.handle == self.thread_handle {
                self.open_count += 1;
                if !self.pid_list.contains(&real_handle_info.pid) {
                    self.pid_list.push(real_handle_info.pid);
                }
            }
        }

        debug!("Show this process all handle information successfully");
        Ok(())
    }
}

pub const SYSTEM_HANDLE_INFORMATION: SYSTEM_INFORMATION_CLASS = SYSTEM_INFORMATION_CLASS(16);

fn set_privilege(token: HANDLE, lpsz_privilege: PCWSTR, b_enable_privilege: u32) -> Result<()> {
    let mut luid: LUID = LUID::default();
    unsafe { LookupPrivilegeValueW(None, lpsz_privilege, &mut luid) }?;

    let tp: TOKEN_PRIVILEGES = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: TOKEN_PRIVILEGES_ATTRIBUTES(b_enable_privilege),
        }],
    };

    unsafe {
        AdjustTokenPrivileges(
            token,
            FALSE,
            Some(&tp),
            size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            None,
        )
    }?;

    Ok(())
}

fn up_privilege() -> Result<()> {
    let mut token: HANDLE = HANDLE::default();
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    }?;

    set_privilege(token, SE_DEBUG_NAME, 1)?;
    unsafe { CloseHandle(token) }?;
    Ok(())
}

fn copy_handle(process_id: u32, handle_value: u32) -> Result<HandleInfo> {
    let process_handle: HANDLE = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE,
            false,
            process_id,
        )?
    };

    let thread_handle: HANDLE = HANDLE(handle_value as *mut c_void);
    let mut real_thread_handle: HANDLE = HANDLE::default();
    unsafe {
        DuplicateHandle(
            process_handle,
            thread_handle,
            process_handle,
            &mut real_thread_handle,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    }?;

    unsafe { CloseHandle(process_handle)? };

    Ok(HandleInfo {
        pid: process_id,
        handle: real_thread_handle,
    })
}

fn pause() {
    println!("Press Enter to continue...");
    let mut input: String = String::new();
    io::stdin().read_line(&mut input).unwrap();
    println!("Program resumed.");
}

fn main() -> Result<()> {
    set_var("RUST_LOG", "debug");
    env_logger::init();

    up_privilege()?;

    info!("upper privilege successfully");

    let mut thread_status: ThreadStatus = ThreadStatus::default();
    thread_status.check()?;
    println!("{:?}", thread_status);

    pause();

    Ok(())
}
