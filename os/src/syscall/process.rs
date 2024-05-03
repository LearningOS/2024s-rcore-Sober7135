//! Process management syscalls

use crate::{
    config::MAX_SYSCALL_NUM,
    mm::translated_byte_buffer,
    task::{
        change_program_brk, current_user_token, exit_current_and_run_next, get_current_task_info,
        suspend_current_and_run_next, TaskStatus,
    },
    timer::{get_time_ms, get_time_us},
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    pub status: TaskStatus,
    /// The numbers of syscall called by task
    pub syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    pub time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    use core::mem::size_of;
    trace!("kernel: sys_get_time");

    let chunks =
        translated_byte_buffer(current_user_token(), _ts as *const u8, size_of::<TimeVal>());

    let us = get_time_us();
    let value = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(&value as *const TimeVal as *const u8, size_of::<TimeVal>())
    };

    let mut offset = 0;

    for chunk in chunks {
        chunk.copy_from_slice(&bytes[offset..offset + chunk.len()]);
        offset += chunk.len();
    }

    0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(ti: *mut TaskInfo) -> isize {
    use core::mem::size_of;

    trace!("kernel: sys_task_info");
    let chunks =
        translated_byte_buffer(current_user_token(), ti as *const u8, size_of::<TaskInfo>());

    let info = get_current_task_info();
    let value = TaskInfo {
        status: TaskStatus::Running,
        syscall_times: info.1,
        time: get_time_ms() - info.0,
    };

    let bytes = unsafe {
        core::slice::from_raw_parts(
            &value as *const TaskInfo as *const u8,
            size_of::<TaskInfo>(),
        )
    };

    let mut offset = 0;

    for chunk in chunks {
        chunk.copy_from_slice(&bytes[offset..offset + chunk.len()]);
        offset += chunk.len();
    }

    0
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    trace!("kernel: sys_mmap NOT IMPLEMENTED YET!");
    -1
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    trace!("kernel: sys_munmap NOT IMPLEMENTED YET!");
    -1
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
