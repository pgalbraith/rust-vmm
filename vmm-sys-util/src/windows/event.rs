// Copyright 2026 rust-vmm Authors or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Windows counterpart of the platform-independent event notification
//! interface in `unix/event.rs`, backed by [`crate::eventfd::EventFd`].

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, RawHandle};
use std::result;

use crate::eventfd::EventFd;
pub use crate::eventfd::{EFD_CLOEXEC, EFD_NONBLOCK, EFD_SEMAPHORE};

bitflags::bitflags! {
    /// Flags for the event notifier and consumer.
    pub struct EventFlag: u8 {
        /// Non-blocking flag
        const NONBLOCK = 1 << 0;
        /// Close-on-exec flag
        const CLOEXEC = 1 << 1;
    }
}

/// Signals an event to notify a peer, backed on Windows by a named event object.
#[derive(Debug)]
pub struct EventNotifier {
    event: EventFd,
}

impl EventNotifier {
    /// Signal the event.
    pub fn notify(&self) -> result::Result<(), io::Error> {
        self.event.write(1)
    }

    /// Clone this EventNotifier.
    pub fn try_clone(&self) -> result::Result<EventNotifier, io::Error> {
        Ok(EventNotifier {
            event: self.event.try_clone()?,
        })
    }
}

impl AsRawHandle for EventNotifier {
    fn as_raw_handle(&self) -> RawHandle {
        self.event.as_raw_handle()
    }
}

impl FromRawHandle for EventNotifier {
    unsafe fn from_raw_handle(handle: RawHandle) -> Self {
        EventNotifier {
            event: EventFd::from_raw_handle(handle),
        }
    }
}

impl IntoRawHandle for EventNotifier {
    fn into_raw_handle(self) -> RawHandle {
        self.event.into_raw_handle()
    }
}

/// Consumes a signaled event, backed on Windows by a named event object.
#[derive(Debug)]
pub struct EventConsumer {
    event: EventFd,
}

impl EventConsumer {
    /// Consume a pending signal, if any.
    ///
    /// Unlike Linux, this does not block: [`crate::epoll::Epoll`] resets the
    /// handle itself when reporting it ready, so this isn't usable as a
    /// standalone "block until signaled" primitive on Windows.
    pub fn consume(&self) -> result::Result<(), io::Error> {
        self.event.try_consume()
    }

    /// Clone this EventConsumer.
    pub fn try_clone(&self) -> result::Result<EventConsumer, io::Error> {
        Ok(EventConsumer {
            event: self.event.try_clone()?,
        })
    }
}

impl AsRawHandle for EventConsumer {
    fn as_raw_handle(&self) -> RawHandle {
        self.event.as_raw_handle()
    }
}

impl FromRawHandle for EventConsumer {
    unsafe fn from_raw_handle(handle: RawHandle) -> Self {
        EventConsumer {
            event: EventFd::from_raw_handle(handle),
        }
    }
}

impl IntoRawHandle for EventConsumer {
    fn into_raw_handle(self) -> RawHandle {
        self.event.into_raw_handle()
    }
}

/// Create a new EventNotifier and EventConsumer, backed by a single named
/// event object duplicated into two independent handles.
///
/// # Arguments
///
/// * `flags` - Flags to set, such as `EventFlag::NONBLOCK`. `EventFlag::CLOEXEC`
///   has no effect on Windows.
pub fn new_event_consumer_and_notifier(
    flags: EventFlag,
) -> result::Result<(EventConsumer, EventNotifier), io::Error> {
    let mut efd_flags = 0;
    if flags.contains(EventFlag::NONBLOCK) {
        efd_flags |= EFD_NONBLOCK;
    }
    let event = EventFd::new(efd_flags)?;
    let event_clone = event.try_clone()?;
    Ok((
        EventConsumer { event },
        EventNotifier { event: event_clone },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notify_and_consume() {
        let (consumer, notifier) = new_event_consumer_and_notifier(EventFlag::empty())
            .expect("Failed to create notifier and consumer");
        notifier.notify().unwrap();
        assert!(consumer.consume().is_ok());
    }

    #[test]
    fn test_clone() {
        let (consumer, notifier) = new_event_consumer_and_notifier(EventFlag::empty())
            .expect("Failed to create notifier and consumer");
        let cloned_notifier = notifier.try_clone().expect("Failed to clone notifier");
        let cloned_consumer = consumer.try_clone().expect("Failed to clone consumer");

        cloned_notifier.notify().unwrap();
        assert!(cloned_consumer.consume().is_ok());
    }

    #[test]
    fn test_consume_does_not_block_when_unsignaled() {
        // consume() must tolerate an already-unsignaled event (the normal
        // post-Epoll::wait case), regardless of EventFlag::NONBLOCK.
        let (consumer, _notifier) = new_event_consumer_and_notifier(EventFlag::empty())
            .expect("Failed to create notifier and consumer");
        assert!(consumer.consume().is_ok());
    }

    #[test]
    fn test_from_raw_handle() {
        let (consumer, notifier) = new_event_consumer_and_notifier(EventFlag::empty())
            .expect("Failed to create notifier and consumer");
        let handle = notifier.into_raw_handle();
        // SAFETY: handle came from `into_raw_handle` above and is not closed.
        let notifier = unsafe { EventNotifier::from_raw_handle(handle) };
        notifier.notify().unwrap();
        assert!(consumer.consume().is_ok());
    }
}
