#![allow(missing_docs)]
#![deny(warnings)]

extern crate libc;
use std::mem;

use self::libc::{
    c_char,
    int32_t,
    uint8_t,
    uint16_t,
    uint32_t,
    uint64_t };

/* the following events that user-space can register for */
//#define FAN_ACCESS              0x00000001      /* File was accessed */
///File was accessed
pub const FAN_ACCESS: uint32_t = 0x00000001;      /* File was accessed */
//#define FAN_MODIFY              0x00000002      /* File was modified */
///File was modified
pub const FAN_MODIFY: uint32_t = 0x00000002;      /* File was modified */
//#define FAN_CLOSE_WRITE         0x00000008      /* Writtable file closed */
///Writtable file closed
pub const FAN_CLOSE_WRITE: uint32_t = 0x00000008;      /* Writtable file closed */
//#define FAN_CLOSE_NOWRITE       0x00000010      /* Unwrittable file closed */
///Unwrittable file closed
pub const FAN_CLOSE_NOWRITE: uint32_t = 0x00000010;      /* Unwrittable file closed */
//#define FAN_OPEN                0x00000020      /* File was opened */
///File was opened
pub const FAN_OPEN: uint32_t = 0x00000020;      /* File was opened */

//#define FAN_Q_OVERFLOW          0x00004000      /* Event queued overflowed */
///Event queued overflowed
pub const FAN_Q_OVERFLOW: uint32_t = 0x00004000;      /* Event queued overflowed */

//#define FAN_OPEN_PERM           0x00010000      /* File open in perm check */
///File open in perm check
pub const FAN_OPEN_PERM: uint32_t = 0x00010000;      /* File open in perm check */
//#define FAN_ACCESS_PERM         0x00020000      /* File accessed in perm check */
///File accessed in perm check
pub const FAN_ACCESS_PERM: uint32_t = 0x00020000;      /* File accessed in perm check */

//#define FAN_ONDIR               0x40000000      /* event occurred against dir */
///Event occured against dir
pub const FAN_ONDIR: uint32_t = 0x40000000;      /* event occurred against dir */

//#define FAN_EVENT_ON_CHILD      0x08000000      /* interested in child events */
///Interested in child events
pub const FAN_EVENT_ON_CHILD: uint32_t = 0x08000000;      /* interested in child events */

/* helper events */
//#define FAN_CLOSE               (FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE) /* close */
///Close
pub const FAN_CLOSE: uint32_t = (FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE); /* close */

/* flags used for fanotify_init() */
//#define FAN_CLOEXEC             0x00000001
///Flag used for fanotify_init()
pub const FAN_CLOEXEC: uint32_t = 0x00000001;
//#define FAN_NONBLOCK            0x00000002
///Flag used for fanotify_init()
pub const FAN_NONBLOCK: uint32_t = 0x00000002;

/* These are NOT bitwise flags.  Both bits are used togther.  */
///These are not bitwise flags. Both bits are used together.
pub const FAN_CLASS_NOTIF: uint32_t = 0x00000000;
///These are not bitwise flags. Both bits are used together.
pub const FAN_CLASS_CONTENT: uint32_t = 0x00000004;
///These are not bitwise flags. Both bits are used together.
pub const FAN_CLASS_PRE_CONTENT: uint32_t = 0x00000008;

//#define FAN_UNLIMITED_QUEUE     0x00000010
///These are not bitwise flags. Both bits are used together.
pub const FAN_UNLIMITED_QUEUE: uint32_t = 0x00000010;
//#define FAN_UNLIMITED_MARKS     0x00000020
///These are not bitwise flags. Both bits are used together.
pub const FAN_UNLIMITED_MARKS: uint32_t = 0x00000020;

//#define FAN_ALL_INIT_FLAGS      (FAN_CLOEXEC | FAN_NONBLOCK | pub const FAN_ALL_INIT_FLAGS: uint32_t = (FAN_CLOEXEC | FAN_NONBLOCK |                                  FAN_ALL_CLASS_BITS | FAN_UNLIMITED_QUEUE |                                 FAN_UNLIMITED_MARKS)

/* flags used for fanotify_modify_mark() */
///Flags used for fanotify_modify_mark()
pub const FAN_MARK_ADD: uint32_t = 0x00000001;
///Flags used for fanotify_modify_mark()
pub const FAN_MARK_REMOVE: uint32_t = 0x00000002;
///Flags used for fanotify_modify_mark()
pub const FAN_MARK_DONT_FOLLOW: uint32_t = 0x00000004;
///Flags used for fanotify_modify_mark()
pub const FAN_MARK_ONLYDIR: uint32_t = 0x00000008;
///Flags used for fanotify_modify_mark()
pub const FAN_MARK_MOUNT: uint32_t = 0x00000010;
///Flags used for fanotify_modify_mark()
pub const FAN_MARK_IGNORED_MASK: uint32_t = 0x00000020;
///Flags used for fanotify_modify_mark()
pub const FAN_MARK_IGNORED_SURV_MODIFY: uint32_t = 0x00000040;
///Flags used for fanotify_modify_mark()
pub const FAN_MARK_FLUSH: uint32_t = 0x00000080;

/*
 * All of the events - we build the list by hand so that we can add flags in
 * the future and not break backward compatibility.  Apps will get only the
 * events that they originally wanted.  Be sure to add new events here!
 */
//#define FAN_ALL_EVENTS (FAN_ACCESS |pub const FAN_ALL_EVENTS: uint32_t = (FAN_ACCESS |                        FAN_MODIFY |                        FAN_CLOSE |                        FAN_OPEN)

/*
 * All events which require a permission response from userspace
 */
//#define FAN_ALL_PERM_EVENTS (FAN_OPEN_PERM |pub const FAN_ALL_PERM_EVENTS: uint32_t = (FAN_OPEN_PERM |                             FAN_ACCESS_PERM)

//#define FAN_ALL_OUTGOING_EVENTS (FAN_ALL_EVENTS |pub const FAN_ALL_OUTGOING_EVENTS: uint32_t = (FAN_ALL_EVENTS |                                 FAN_ALL_PERM_EVENTS |                                 FAN_Q_OVERFLOW)

//#define FANOTIFY_METADATA_VERSION       3
///placeholder
pub const FANOTIFY_METADATA_VERSION: uint8_t = 3;
/*
struct fanotify_event_metadata {
        __u32 event_len;
        __u8 vers;
        __u8 reserved;
        __u16 metadata_len;
        __aligned_u64 mask;
        __s32 fd;
        __s32 pid;
};*/
///placeholder
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug,Copy,Clone)]
pub struct fanotify_event_metadata {
///placeholder
    pub event_len: uint32_t,
///placeholder
    pub vers: uint8_t,
///placeholder
    pub reserved: uint8_t,
///placeholder
    pub metadata_len: uint16_t,
///placeholder
    pub mask: uint64_t,
///placeholder
    pub fd: int32_t,
///placeholder
    pub pid: int32_t,
}
pub unsafe fn fan_event_next(meta: *const fanotify_event_metadata, total_len: &mut isize) -> *const fanotify_event_metadata {
    *total_len -= (*meta).event_len as isize;
    //println!("Adding {} to {:p}",((*meta).event_len),meta);
    let ret = (meta as u64 + ((*meta).event_len) as u64) as *const fanotify_event_metadata;
    //println!("Returning {:p}",ret);
    return ret;
}
pub unsafe fn fan_event_ok(meta: *const fanotify_event_metadata, total_len: &mut isize) -> bool {
    //println!("len = {}, size = {}, event_len = {}",total_len, mem::size_of::<fanotify_event_metadata>(), (*meta).event_len);
    *total_len >= mem::size_of::<fanotify_event_metadata>() as isize &&
        (*meta).event_len >= mem::size_of::<fanotify_event_metadata>() as u32 &&
        (*meta).event_len <= *total_len as u32
}

#[allow(non_camel_case_types)]
#[repr(C)]
///placeholder
pub struct fanotify_response {
///placeholder
    pub fd: int32_t,
///placeholder
    pub response: uint32_t,
}

/* Legit userspace responses to a _PERM event */
//#define FAN_ALLOW       0x01
///placeholder
pub const FAN_ALLOW: uint32_t = 0x01;
//#define FAN_DENY        0x02
///placeholder
pub const FAN_DENY: uint32_t = 0x02;
/* No fd set in event */
///placeholder
pub const FAN_NOFD: int32_t = -1;

extern {
/* Create and initialize fanotify group.  */
    pub fn fanotify_init(__flags: uint32_t, __event_f_flags: uint32_t) -> int32_t;

/* Add, remove, or modify an fanotify mark on a filesystem object.  */
    pub fn fanotify_mark(__fanotify_fd: int32_t, __flags: uint32_t,
                         __mask: uint64_t, __dfd: int32_t, __pathname: *const c_char) ->int32_t;
}
pub use self::libc::{
    close,
    read,
};
