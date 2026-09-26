#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("This application only runs on Linux and macOS hosts.");

pub const DEFAULT_GDB_ADDR: &str = "127.0.0.1:1234";
pub const DEFAULT_KD_SOCKET: &str = "/tmp/ntoseye-kd.sock";
pub const DEFAULT_KDNET_ADDR: &str = "0.0.0.0:50000";

/// A live debug transport. The one enum every host (CLI, MCP, Python SDK)
/// parses its backend choice into; [`session::Session::open`] builds from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// KD over a serial pipe (Unix socket).
    Kd,
    /// KD over UDP (KDNET); needs a key.
    KdNet,
    /// Classic Microsoft KD over a physical USB debug connection.
    KdUsb,
    /// QEMU GDB stub.
    Gdb,
    /// Passive host-memory introspection, no debug transport.
    Memory,
}

impl Backend {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Kd => "kd",
            Self::KdNet => "kdnet",
            Self::KdUsb => "kdusb",
            Self::Gdb => "gdb",
            Self::Memory => "memory",
        }
    }

    /// The transport endpoint used when the host passes no `connect`; `None`
    /// for the passive memory backend, which has no endpoint at all.
    pub const fn default_endpoint(self) -> Option<&'static str> {
        match self {
            Self::Kd => Some(DEFAULT_KD_SOCKET),
            Self::KdNet => Some(DEFAULT_KDNET_ADDR),
            Self::KdUsb => None,
            Self::Gdb => Some(DEFAULT_GDB_ADDR),
            Self::Memory => None,
        }
    }
}

impl std::str::FromStr for Backend {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "kd" => Ok(Self::Kd),
            "kdnet" => Ok(Self::KdNet),
            "kdusb" => Ok(Self::KdUsb),
            "gdb" => Ok(Self::Gdb),
            "memory" => Ok(Self::Memory),
            other => Err(format!(
                "unknown backend '{other}': expected 'kd', 'kdnet', 'kdusb', 'gdb', or 'memory'"
            )),
        }
    }
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// What to attach to: a crash dump, or a live VM over one [`Backend`].
#[derive(Clone, Debug)]
pub enum TargetSpec {
    Dump(std::path::PathBuf),
    Live {
        backend: Backend,
        /// Transport endpoint; `None` means the backend's default.
        connect: Option<String>,
        /// KDNET encryption key (four base-36 components).
        kdnet_key: Option<String>,
        memory_source: kd::KdMemorySource,
    },
}

impl TargetSpec {
    /// Reject argument combinations that cannot work before touching any
    /// transport, with the same wording for every host.
    pub fn validate(&self) -> error::Result<()> {
        let invalid = |message: &str| error::Error::InvalidArgument(message.to_string());
        let Self::Live {
            backend,
            connect,
            kdnet_key,
            memory_source,
        } = self
        else {
            return Ok(());
        };
        match backend {
            Backend::KdNet if kdnet_key.is_none() => {
                return Err(invalid("kdnet backend requires a key"));
            }
            Backend::Kd | Backend::KdUsb | Backend::Gdb | Backend::Memory
                if kdnet_key.is_some() =>
            {
                return Err(invalid("key is only valid for the kdnet backend"));
            }
            Backend::KdUsb if connect.as_deref().is_none_or(str::is_empty) => {
                return Err(invalid(
                    "kdusb backend requires a target name via --connect",
                ));
            }
            Backend::Memory if connect.is_some() => {
                return Err(invalid("memory backend does not use a connect endpoint"));
            }
            _ => {}
        }
        #[cfg(not(target_os = "linux"))]
        if matches!(backend, Backend::KdUsb) {
            return Err(invalid("kdusb backend is only supported on Linux hosts"));
        }
        if !matches!(backend, Backend::Kd | Backend::KdNet | Backend::KdUsb)
            && *memory_source != kd::KdMemorySource::Auto
        {
            return Err(invalid(
                "memory_source is only valid for kd, kdnet, and kdusb backends",
            ));
        }
        Ok(())
    }

    /// The resolved transport endpoint for a live spec (`None` for dumps and
    /// the memory backend).
    pub fn endpoint(&self) -> Option<&str> {
        match self {
            Self::Dump(_) => None,
            Self::Live {
                backend, connect, ..
            } => connect.as_deref().or(backend.default_endpoint()),
        }
    }
}

#[macro_use]
pub mod output;

pub mod backend;
pub mod breakpoints;
pub mod bugchecks;
pub mod bytes;
#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "cli")]
pub mod configure;
pub mod cpu_state;
#[cfg(feature = "dap")]
pub mod dap;
pub mod dbg_backend;
pub mod debugger_data;
pub mod diagnostics;
pub mod disasm;
pub mod dmp;
pub mod dump_writer;
pub mod error;
pub mod exception_policy;
pub mod expr;
pub mod gdb;
#[cfg(feature = "gdbserver")]
pub mod gdbserver;
pub mod guest;
pub mod host;
pub mod kd;
pub mod kuser_shared;
pub mod layout;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod memory;
pub mod memory_backend;
pub mod ntstatus;
pub mod pe;
pub mod phys;
#[cfg(feature = "python")]
pub mod python;
#[cfg(feature = "repl")]
pub mod repl;
pub mod session;
#[cfg(feature = "mcp")]
pub mod structured;
pub mod symbols;
pub mod target;
#[cfg(any(feature = "dap", feature = "gdbserver"))]
mod termination;
pub mod trapframe;
pub mod triage;
pub mod triage_report;
pub mod types;
pub mod typeview;
#[cfg(feature = "repl")]
pub mod ui;
pub mod unwind;
#[cfg(any(feature = "mcp", feature = "python"))]
pub mod view;


#[cfg(test)]
mod backend_contract_tests {
    use super::{Backend, TargetSpec};
    use crate::kd::KdMemorySource;

    #[test]
    fn kdusb_backend_parses_and_has_no_default_endpoint() {
        let backend: Backend = "kdusb".parse().expect("kdusb backend should parse");
        assert_eq!(backend, Backend::KdUsb);
        assert_eq!(backend.name(), "kdusb");
        assert_eq!(backend.default_endpoint(), None);
    }

    #[test]
    fn kdusb_target_requires_explicit_target_name() {
        let missing = TargetSpec::Live {
            backend: Backend::KdUsb,
            connect: None,
            kdnet_key: None,
            memory_source: KdMemorySource::Auto,
        };
        let error = missing.validate().expect_err("missing target name must fail");
        assert!(
            error.to_string().contains("requires a target name"),
            "{error}"
        );

        let empty = TargetSpec::Live {
            backend: Backend::KdUsb,
            connect: Some(String::new()),
            kdnet_key: None,
            memory_source: KdMemorySource::Auto,
        };
        assert!(empty.validate().is_err());
    }

    #[test]
    fn kdusb_target_accepts_kd_memory_source_but_rejects_kdnet_key() {
        let valid = TargetSpec::Live {
            backend: Backend::KdUsb,
            connect: Some("CLSA0102_USB".into()),
            kdnet_key: None,
            memory_source: KdMemorySource::Kd,
        };
        assert!(valid.validate().is_ok());
        assert_eq!(valid.endpoint(), Some("CLSA0102_USB"));

        let keyed = TargetSpec::Live {
            backend: Backend::KdUsb,
            connect: Some("CLSA0102_USB".into()),
            kdnet_key: Some("1.2.3.4".into()),
            memory_source: KdMemorySource::Auto,
        };
        let error = keyed.validate().expect_err("KDNET key must be rejected");
        assert!(
            error.to_string().contains("only valid for the kdnet backend"),
            "{error}"
        );
    }
}
