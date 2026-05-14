//! Identifying facts about the host, gathered once at agent startup and sent
//! to the controller as the `Hello` frame.

use rsansible_wire::{msg, Message};

pub async fn gather(agent_version: &str) -> Message {
    let arch = match std::env::consts::ARCH {
        "x86_64" => msg::arch::X86_64,
        "aarch64" => msg::arch::AARCH64,
        "arm" | "armv7" => msg::arch::ARM,
        "riscv64" => msg::arch::RISCV64,
        _ => msg::arch::UNKNOWN,
    };
    let os = match std::env::consts::OS {
        "linux" => msg::os::LINUX,
        "macos" => msg::os::DARWIN,
        "freebsd" => msg::os::FREEBSD,
        _ => msg::os::UNKNOWN,
    };

    // rustix wraps the uname / getuid / getgid syscalls without forcing us off
    // `forbid(unsafe_code)`. No libc link, plays nicely with musl-static.
    let un = rustix::system::uname();
    let kernel = format!(
        "{} {} {}",
        un.sysname().to_string_lossy(),
        un.release().to_string_lossy(),
        un.machine().to_string_lossy(),
    );
    let hostname = un.nodename().to_string_lossy().to_string();
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();

    msg::hello(arch, os, kernel, hostname, uid, gid, agent_version.to_string())
}
