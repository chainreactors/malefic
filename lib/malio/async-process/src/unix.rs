//! Unix-specific extensions.

use std::ffi::OsStr;
use std::io;
use std::os::unix::process::CommandExt as _;

use cfg_if::cfg_if;

use crate::Command;

cfg_if! {
    if #[cfg(any(target_os = "vxworks", target_os = "espidf", target_os = "horizon", target_os = "vita"))] {
        type UserId = u16;
        type GroupId = u16;
    } else if #[cfg(target_os = "nto")] {
        // Both IDs are signed, see `sys/target_nto.h` of the QNX Neutrino SDP.
        // Only positive values should be used, see e.g.
        // https://www.qnx.com/developers/docs/7.1/#com.qnx.doc.neutrino.lib_ref/topic/s/setuid.html
        type UserId = i32;
        type GroupId = i32;
    } else {
        type UserId = u32;
        type GroupId = u32;
    }
}

/// Unix-specific extensions to the [`Command`] builder.
///
/// This trait is sealed: it cannot be implemented outside `async-process`.
/// This is so that future additional methods are not breaking changes.
pub trait CommandExt: crate::sealed::Sealed {
    /// Sets the child process's user ID. This translates to a
    /// `setuid` call in the child process. Failure in the `setuid`
    /// call will cause the spawn to fail.
    fn uid(&mut self, id: UserId) -> &mut Command;

    /// Similar to `uid`, but sets the group ID of the child process. This has
    /// the same semantics as the `uid` field.
    fn gid(&mut self, id: GroupId) -> &mut Command;

    /// Performs all the required setup by this `Command`, followed by calling
    /// the `execvp` syscall.
    ///
    /// On success this function will not return, and otherwise it will return
    /// an error indicating why the exec (or another part of the setup of the
    /// `Command`) failed.
    ///
    /// `exec` not returning has the same implications as calling
    /// [`std::process::exit`] – no destructors on the current stack or any other
    /// thread’s stack will be run. Therefore, it is recommended to only call
    /// `exec` at a point where it is fine to not run any destructors. Note,
    /// that the `execvp` syscall independently guarantees that all memory is
    /// freed and all file descriptors with the `CLOEXEC` option (set by default
    /// on all file descriptors opened by the standard library) are closed.
    ///
    /// This function, unlike `spawn`, will **not** `fork` the process to create
    /// a new child. Like spawn, however, the default behavior for the stdio
    /// descriptors will be to inherited from the current process.
    ///
    /// # Notes
    ///
    /// The process may be in a "broken state" if this function returns in
    /// error. For example the working directory, environment variables, signal
    /// handling settings, various user/group information, or aspects of stdio
    /// file descriptors may have changed. If a "transactional spawn" is
    /// required to gracefully handle errors it is recommended to use the
    /// cross-platform `spawn` instead.
    fn exec(&mut self) -> io::Error;

    /// Set executable argument
    ///
    /// Set the first process argument, `argv[0]`, to something other than the
    /// default executable path.
    fn arg0<S>(&mut self, arg: S) -> &mut Command
    where
        S: AsRef<OsStr>;
}

impl crate::sealed::Sealed for Command {}
impl CommandExt for Command {
    fn uid(&mut self, id: UserId) -> &mut Command {
        self.inner.uid(id);
        self
    }

    fn gid(&mut self, id: GroupId) -> &mut Command {
        self.inner.gid(id);
        self
    }

    fn exec(&mut self) -> io::Error {
        self.inner.exec()
    }

    fn arg0<S>(&mut self, arg: S) -> &mut Command
    where
        S: AsRef<OsStr>,
    {
        self.inner.arg0(arg);
        self
    }
}
