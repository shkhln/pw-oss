use std::ffi::CString;
use libc::sysctlbyname;
use nix::errno::Errno;

pub enum SysctlName {
  CString(CString)
}

impl From<&str> for SysctlName {

  fn from(str: &str) -> Self {
    SysctlName::CString(CString::new(str).unwrap())
  }
}

impl From<String> for SysctlName {

  fn from(str: String) -> Self {
    SysctlName::CString(CString::new(str).unwrap())
  }
}

pub struct SysctlReader {
  scratch_buffer: Vec<u8>
}

impl SysctlReader {

  pub fn new() -> Self {
    Self {
      scratch_buffer: Vec::with_capacity(32)
    }
  }

  pub fn read_string<T: Into<SysctlName>>(&mut self, name: T, max_len: usize) -> Result<String, Errno> {

    let SysctlName::CString(name) = name.into();

    let mut len = 0;
    if unsafe { sysctlbyname(name.as_ptr(), std::ptr::null_mut(), &mut len, std::ptr::null(), 0) } == -1 {
      return Err(Errno::last())
    }

    if len > max_len {
      return Err(Errno::ENOMEM);
    }

    if len == 0 {
      return Ok("".to_string());
    }

    self.scratch_buffer.resize(len, 0);
    if unsafe { sysctlbyname(name.as_ptr(), self.scratch_buffer.as_mut_ptr().cast(), &mut len, std::ptr::null(), 0) } == -1 {
      return Err(Errno::last());
    }

    Ok(String::from_utf8_lossy(&self.scratch_buffer[0..len]).to_string())
  }
}

use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use uds::UnixSeqpacketConn;

pub struct DevdSocket {
  socket: UnixSeqpacketConn,
  buffer: Vec<u8>
}

impl DevdSocket {

  pub fn open() -> Result<Self, std::io::Error> {
    let socket = UnixSeqpacketConn::connect("/var/run/devd.seqpacket.pipe")?;
    let buffer = [0; 8192 /* DEVCTL_MAXBUF */].to_vec();
    Ok(Self {
      socket,
      buffer
    })
  }

  pub fn fd(&self) -> RawFd {
    self.socket.as_raw_fd()
  }

  pub fn read_event(&mut self, mut apply: impl FnMut(&str)) {
    if let Ok(len) = self.socket.recv(&mut self.buffer) {
      assert!(len <= self.buffer.len());
      apply(std::str::from_utf8(&self.buffer[..len]).unwrap());
    }
  }
}

pub unsafe fn build_enum_format_info(b: &mut libspa::pod::builder::Builder, mono: bool) -> Result<(), Errno> {

  use libspa::sys::*;

  let mut outer = std::mem::MaybeUninit::<spa_pod_frame>::uninit();
  let mut inner = std::mem::MaybeUninit::<spa_pod_frame>::uninit();

  b.push_object(&mut outer, SPA_TYPE_OBJECT_Format, SPA_PARAM_EnumFormat)?;

  b.add_prop(SPA_FORMAT_mediaType, 0)?;
  b.add_id(libspa::utils::Id(SPA_MEDIA_TYPE_audio))?;

  b.add_prop(SPA_FORMAT_mediaSubtype, 0)?;
  b.add_id(libspa::utils::Id(SPA_MEDIA_SUBTYPE_raw))?;

  b.add_prop(SPA_FORMAT_AUDIO_format, 0)?;
  b.push_choice(&mut inner, SPA_CHOICE_Enum, 0)?;
  for fmt in [
    SPA_AUDIO_FORMAT_S32,
    SPA_AUDIO_FORMAT_S32_OE,
    SPA_AUDIO_FORMAT_S16,
    SPA_AUDIO_FORMAT_S16_OE
  ] {
    b.add_id(libspa::utils::Id(fmt))?;
  }
  b.pop(inner.assume_init_mut());

  b.add_prop(SPA_FORMAT_AUDIO_rate, 0)?;
  b.push_choice(&mut inner, SPA_CHOICE_Range, 0)?;
  b.add_int( 48000)?;
  b.add_int(     1)?;
  b.add_int(192000)?;
  b.pop(inner.assume_init_mut());

  if !mono {
    b.add_prop(SPA_FORMAT_AUDIO_channels, 0)?;
    b.push_choice(&mut inner, SPA_CHOICE_Range, 0)?;
    b.add_int(2)?;
    b.add_int(1)?;
    b.add_int(SPA_AUDIO_MAX_CHANNELS as i32)?;
    b.pop(inner.assume_init_mut());

    b.add_prop(SPA_FORMAT_AUDIO_position, 0)?;
    b.add_array(std::mem::size_of_val(&SPA_AUDIO_CHANNEL_FL) as u32, SPA_TYPE_Id, 2,
      [SPA_AUDIO_CHANNEL_FL, SPA_AUDIO_CHANNEL_FR].as_ptr().cast())?;
  } else {
    b.add_prop(SPA_FORMAT_AUDIO_channels, 0)?;
    b.add_int(1)?;
  }

  b.pop(outer.assume_init_mut());

  Ok(())
}

pub fn now_ns(system: &crate::spa::System) -> u64 {
  let mut now = libspa::sys::timespec { tv_sec: 0, tv_nsec: 0 };
  let err = unsafe { system.clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
  assert!(err != -1);
  (now.tv_sec * libspa::sys::SPA_NSEC_PER_SEC as i64 + now.tv_nsec) as u64
}

#[cfg(debug_assertions)]
pub fn now_ns_libc() -> u64 {
  let mut now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
  let err = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
  assert!(err != -1);
  (now.tv_sec * libspa::sys::SPA_NSEC_PER_SEC as i64 + now.tv_nsec) as u64
}
