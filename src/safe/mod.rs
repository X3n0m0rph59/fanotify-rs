extern crate libc;
use std::fs;
use std::io;
use sys;

pub struct Fanotify {
    pub fd: i32,
    blocking: bool,
}

#[derive(Debug)]
pub struct FanotifyEv {
    pub filename: String,
    pub mask: u64,
    pub fd: i32,
    pub pid: i32,
}

//Event types
pub const FAN_ACCESS: u64 = 0x1;
pub const FAN_MODIFY: u64 = 0x2;
pub const FAN_CLOSE_WRITE: u64 = 0x8;
pub const FAN_CLOSE_NOWRITE: u64 = 0x10;
pub const FAN_OPEN: u64 = 0x20;
const AT_FDCWD: i32 = -100;

//Flags used for fanotify_mark()
pub const FAN_MARK_ADD: u32 = 0x00000001;
pub const FAN_MARK_REMOVE: u32 = 0x00000002;
pub const FAN_MARK_DONT_FOLLOW: u32 = 0x00000004;
pub const FAN_MARK_ONLYDIR: u32 = 0x00000008;
pub const FAN_MARK_MOUNT: u32 = 0x00000010;
pub const FAN_MARK_IGNORED_MASK: u32 = 0x00000020;
pub const FAN_MARK_IGNORED_SURV_MODIFY: u32 = 0x00000040;
pub const FAN_MARK_FLUSH: u32 = 0x00000080;

impl FanotifyEv {
    pub fn from_fanotify_event_metadata(
        meta: *const sys::fanotify_event_metadata,
    ) -> Result<FanotifyEv, io::Error> {
        unsafe {
            let proc_path = format!("/proc/self/fd/{}", (*meta).fd);
            let filename = String::from(fs::read_link(proc_path)?.to_str().unwrap());
            Ok(FanotifyEv {
                filename: filename,
                mask: (*meta).mask,
                fd: (*meta).fd,
                pid: (*meta).pid,
            })
        }
    }
}

impl Drop for FanotifyEv {
    fn drop(&mut self) {
        unsafe {
            sys::close(self.fd);
        }
    }
}

impl Fanotify {
    fn new(flags: u32, event_f_flags: u32) -> Result<Fanotify, io::Error> {
        let mut fnot = Fanotify {
            fd: 0,
            blocking: false,
        };

        unsafe {
            fnot.fd = sys::fanotify_init(flags, event_f_flags);
        };

        if fnot.fd == -1 {
            return Err(io::Error::last_os_error());
        }

        Ok(fnot)
    }

    pub fn new_blocking() -> Result<Fanotify, io::Error> {
        match Fanotify::new(sys::FAN_CLASS_NOTIF | sys::FAN_UNLIMITED_QUEUE | sys::FAN_UNLIMITED_MARKS, 0) {
            Ok(mut fnot) => {
                fnot.blocking = true;
                return Ok(fnot);
            }

            Err(fnot) => return Err(fnot),
        };
    }

    pub fn new_nonblocking() -> Result<Fanotify, io::Error> {
        Fanotify::new(sys::FAN_NONBLOCK | sys::FAN_UNLIMITED_QUEUE | sys::FAN_UNLIMITED_MARKS, 0)
    }

    pub fn add_mount(&self, event_mask: u64, path: String) -> Result<(), io::Error> {
        unsafe {
            match sys::fanotify_mark(
                self.fd,
                FAN_MARK_ADD | FAN_MARK_MOUNT,
                event_mask,
                AT_FDCWD,
                path.as_ptr() as *const _,
            ) {
                0 => return Ok(()),
                _ => return Err(io::Error::last_os_error()),
            };
        };
    }

    pub fn add_file(&self, event_mask: u64, path: String) -> Result<(), io::Error> {
        unsafe {
            match sys::fanotify_mark(
                self.fd,
                FAN_MARK_ADD,
                event_mask,
                AT_FDCWD,
                path.as_ptr() as *const _,
            ) {
                0 => return Ok(()),
                _ => return Err(io::Error::last_os_error()),
            };
        };
    }

    pub fn remove_file(&self, event_mask: u64, path: String) -> Result<(), io::Error> {
        unsafe {
            match sys::fanotify_mark(
                self.fd,
                FAN_MARK_REMOVE,
                event_mask,
                AT_FDCWD,
                path.as_ptr() as *const _,
            ) {
                0 => return Ok(()),
                _ => return Err(io::Error::last_os_error()),
            };
        };
    }

    pub fn get_events(&self) -> Result<Vec<FanotifyEv>, io::Error> {
        let readable_bytes: libc::size_t = 0;
        unsafe {
            if libc::ioctl(self.fd, libc::FIONREAD, &readable_bytes as *const usize) < 0 {
                return Err(io::Error::last_os_error());
            }

            if readable_bytes <= 0 {
                return Err(io::Error::new(io::ErrorKind::Other, "nothing to read"));
            }

            let mut vec: Vec<u8> = Vec::with_capacity(readable_bytes);
            let ptr = vec.as_mut_ptr();
            let mut readbytes = libc::read(self.fd, ptr as *mut libc::c_void, readable_bytes);
            if readbytes < 0 {
                return Err(io::Error::last_os_error());
            }

            let mut events: Vec<FanotifyEv> = Vec::with_capacity(readable_bytes);
            let mut event = ptr as *const sys::fanotify_event_metadata;
            while sys::fan_event_ok(event, &mut readbytes) {
                events.push(FanotifyEv::from_fanotify_event_metadata(event).unwrap());
                event = sys::fan_event_next(event, &mut readbytes);
            }
            
            return Ok(events);
        };
    }
}
