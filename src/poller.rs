use std::{io, io::ErrorKind, time::Duration};

use mio::{event::Source, Events, Interest, Poll, Token};

/// Mio-backed poller with an epoll-like API.
pub struct Poller {
    pub poll: Poll,
    pub events: Events,
}

impl Poller {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            poll: Poll::new()?,
            events: Events::with_capacity(1024),
        })
    }

    /// Register a new source or update its interest if already present.
    pub fn add_or_replace<S: Source + ?Sized>(&mut self, source: &mut S, key: u64, interest: Interest) -> io::Result<()> {
        let token = Token(key as usize);

        match self.poll.registry().register(source, token, interest) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                self.poll.registry().reregister(source, token, interest)?;
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// Remove a source from the poller.
    pub fn delete<S: Source + ?Sized>(&mut self, source: &mut S) -> io::Result<()> {
        self.poll.registry().deregister(source)
    }

    /// Wait for readiness events, returning how many were collected.
    pub fn poll(&mut self, timeout: Option<Duration>) -> io::Result<usize> {
        self.events.clear();
        self.poll.poll(&mut self.events, timeout)?;
        Ok(self.events.iter().count())
    }

    /// Iterate over the most recently collected events.
    pub fn iter_events(&self) -> impl Iterator<Item = PollEvent> + '_ {
        self.events.iter().map(|event| PollEvent {
            key: event.token().0 as u64,
            readable: event.is_readable(),
            writable: event.is_writable(),
            read_closed: event.is_read_closed(),
            write_closed: event.is_write_closed(),
            error: event.is_error(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollEvent {
    pub key: u64,
    pub readable: bool,
    pub writable: bool,
    pub read_closed: bool,
    pub write_closed: bool,
    pub error: bool,
}
