// for posterity, basic libc::epoll wrapper; superseded by mio-based poller.rs for cross-platform compat

use std::{io, collections::HashMap, os::fd::{AsRawFd, RawFd}};

use crate::syscall;

pub struct Epoll {
    pub fd: RawFd,
    pub watched: HashMap<RawFd, libc::epoll_event>,
    pub events: Vec<libc::epoll_event>
}

impl Epoll {
    pub fn new() -> Self {
        Self {
            fd: Epoll::epoll_create().expect("epoll create worked"),
            watched: HashMap::new(),
            events: Vec::with_capacity(1024)
        }
    }

    fn epoll_create() -> io::Result<RawFd> {
        let fd = syscall!(epoll_create1(0))?;
        if let Ok(flags) = syscall!(fcntl(fd, libc::F_GETFD)) {
            // FD_CLOEXEC - close-on-exec, I guess to avoid "leaking" this fd..?
            let _ = syscall!(fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC));
        }

        Ok(fd)
    }

    fn add_or_replace(&mut self, fd: RawFd, mut event: libc::epoll_event) -> io::Result<()> {
        match self.watched.get(&fd) {
            Some(_) => {
                println!("epoll_ctl_mod {fd}");
                syscall!(epoll_ctl(self.fd, libc::EPOLL_CTL_MOD, fd, &mut event))?;
            },
            None => {
                println!("epoll_ctl_add {fd}");
                syscall!(epoll_ctl(self.fd, libc::EPOLL_CTL_ADD, fd, &mut event))?;
                self.watched.insert(fd, event);
            }
        };

        Ok(())
    }

    fn delete(&mut self, fd: RawFd) -> io::Result<()> {
        if self.watched.get(&fd).is_some() {
            println!("epoll_ctl_del {fd}");
            self.watched.remove(&fd);
            syscall!(epoll_ctl(self.fd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut()))?;
        }
        Ok(())
    }
}

// copied from mio via https://zupzup.org/epoll-with-rust/
#[allow(unused_macros)]
macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        let res = unsafe { libc::$fn($($arg, )*) };
        if res == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}
