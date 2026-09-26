use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use super::kdnet::KdNetStream;
#[cfg(target_os = "linux")]
use super::kdusb::KdUsbStream;

pub enum KdTransport {
    Serial(UnixStream),
    Network(KdNetStream),
    #[cfg(target_os = "linux")]
    Usb(KdUsbStream),
}

impl KdTransport {
    pub fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Serial(stream) => stream.try_clone().map(Self::Serial),
            Self::Network(stream) => stream.try_clone().map(Self::Network),
            #[cfg(target_os = "linux")]
            Self::Usb(stream) => stream.try_clone().map(Self::Usb),
        }
    }

    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Serial(stream) => stream.set_read_timeout(timeout),
            Self::Network(stream) => stream.set_read_timeout(timeout),
            #[cfg(target_os = "linux")]
            Self::Usb(stream) => {
                stream.set_read_timeout(timeout);
                Ok(())
            }
        }
    }

    /// KDNET session generation handle, bumped whenever the transport
    /// renegotiates with a restarted target.
    pub fn network_session_generation(&self) -> Option<Arc<AtomicU64>> {
        match self {
            Self::Network(stream) => Some(stream.session_generation()),
            Self::Serial(_) => None,
            #[cfg(target_os = "linux")]
            Self::Usb(_) => None,
        }
    }

    pub fn network_datagrams_received(&self) -> Option<u64> {
        match self {
            Self::Network(stream) => Some(stream.received_datagrams()),
            Self::Serial(_) => None,
            #[cfg(target_os = "linux")]
            Self::Usb(_) => None,
        }
    }
}

impl From<UnixStream> for KdTransport {
    fn from(stream: UnixStream) -> Self {
        Self::Serial(stream)
    }
}

impl From<KdNetStream> for KdTransport {
    fn from(stream: KdNetStream) -> Self {
        Self::Network(stream)
    }
}

#[cfg(target_os = "linux")]
impl From<KdUsbStream> for KdTransport {
    fn from(stream: KdUsbStream) -> Self {
        Self::Usb(stream)
    }
}

impl Read for KdTransport {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Serial(stream) => stream.read(output),
            Self::Network(stream) => stream.read(output),
            #[cfg(target_os = "linux")]
            Self::Usb(stream) => stream.read(output),
        }
    }
}

impl Write for KdTransport {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        match self {
            Self::Serial(stream) => stream.write(input),
            Self::Network(stream) => stream.write(input),
            #[cfg(target_os = "linux")]
            Self::Usb(stream) => stream.write(input),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Serial(stream) => stream.flush(),
            Self::Network(stream) => stream.flush(),
            #[cfg(target_os = "linux")]
            Self::Usb(stream) => stream.flush(),
        }
    }
}
