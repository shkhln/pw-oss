use std::ffi::CString;
use std::os::raw::{c_int, c_ulong, c_void};
use libc::{size_t, ssize_t};
use nix::errno::Errno;

pub const AFMT_S16_LE: u32 = 0x00000010;
pub const AFMT_S16_BE: u32 = 0x00000020;
pub const AFMT_S32_LE: u32 = 0x00001000;
pub const AFMT_S32_BE: u32 = 0x00002000;

const SNDCTL_DSP_SPEED:      c_ulong = nix::request_code_readwrite!(b'P',  2, std::mem::size_of::<c_int>());
const SNDCTL_DSP_SETFMT:     c_ulong = nix::request_code_readwrite!(b'P',  5, std::mem::size_of::<c_int>());
const SNDCTL_DSP_CHANNELS:   c_ulong = nix::request_code_readwrite!(b'P',  6, std::mem::size_of::<c_int>());
const SNDCTL_DSP_GETISPACE:  c_ulong = nix::request_code_read!     (b'P', 13, std::mem::size_of::<audio_buf_info>());
//const SNDCTL_DSP_GETPLAYVOL: c_ulong = nix::request_code_read!     (b'P', 24, std::mem::size_of::<c_int>());
//const SNDCTL_DSP_SETPLAYVOL: c_ulong = nix::request_code_readwrite!(b'P', 24, std::mem::size_of::<c_int>());

#[repr(C)]
struct audio_buf_info {
  fragments:  c_int,
  fragstotal: c_int,
  fragsize:   c_int,
  bytes:      c_int
}

#[derive(Debug, PartialEq)]
enum DspState {
  Closed,
  Setup,
  Running
}

pub struct Dsp {
  path:  CString,
  fd:    c_int,
  state: DspState
}

impl Dsp {

  pub fn new(path: &str) -> Self {
    Self { path: CString::new(path).unwrap(), fd: -1, state: DspState::Closed }
  }

  pub fn is_closed(&self) -> bool {
    self.state == DspState::Closed
  }

  pub fn open(&mut self) -> Result<(), Errno> {
    let fd = unsafe { libc::open(self.path.as_ptr(), libc::O_RDWR) };
    if fd == -1 {
      return Err(Errno::last());
    }

    self.fd    = fd;
    self.state = DspState::Setup;

    Ok(())
  }

  pub fn close(&mut self) {
    assert_ne!(self.state, DspState::Closed);
    unsafe { libc::close(self.fd) };
    self.fd    = -1;
    self.state = DspState::Closed;
  }

  pub fn set_format(&mut self, format: u32) {
    assert_eq!(self.state, DspState::Setup);
    let mut f = format as c_int;
    let err = unsafe { libc::ioctl(self.fd, SNDCTL_DSP_SETFMT, &mut f) };
    assert_ne!(err, -1);
    assert_eq!(f, format as c_int);
  }

  pub fn set_channels(&mut self, channels: u32) {
    assert_eq!(self.state, DspState::Setup);
    let mut n = channels as c_int;
    let err = unsafe { libc::ioctl(self.fd, SNDCTL_DSP_CHANNELS, &mut n) };
    assert_ne!(err, -1);
    assert_eq!(n, channels as c_int);
  }

  pub fn set_rate(&mut self, rate: u32) {
    assert_eq!(self.state, DspState::Setup);
    let mut n = rate as c_int;
    let err = unsafe { libc::ioctl(self.fd, SNDCTL_DSP_SPEED, &mut n) };
    assert_ne!(err, -1);
    assert_eq!(n, rate as c_int);
  }

  pub unsafe fn read(&mut self, buf: *mut c_void, count: size_t) -> ssize_t {
    if self.state == DspState::Setup {
      self.state = DspState::Running;
    }
    assert_eq!(self.state, DspState::Running);
    libc::read(self.fd, buf, count)
  }

  pub unsafe fn write(&mut self, buf: *const c_void, count: size_t) -> ssize_t {
    if self.state == DspState::Setup {
      self.state = DspState::Running;
    }
    assert_eq!(self.state, DspState::Running);
    libc::write(self.fd, buf, count)
  }

  pub fn ready_for_reading(&mut self, timeout_ms: usize) -> bool {

    if self.state == DspState::Setup {
      self.state = DspState::Running;
    }

    assert_eq!(self.state, DspState::Running);

    let mut read_fds = std::mem::MaybeUninit::<libc::fd_set>::uninit();
    unsafe {
      libc::FD_ZERO(read_fds.as_mut_ptr());
      libc::FD_SET(self.fd, read_fds.as_mut_ptr());
    }

    let mut timeout = libc::timeval { tv_sec: 0, tv_usec: timeout_ms as i64 * 1000 };

    let ndesc = unsafe { libc::select(self.fd + 1, read_fds.assume_init_mut(), std::ptr::null_mut(), std::ptr::null_mut(), &mut timeout) };
    ndesc != -1 && ndesc > 0
  }

  pub fn ispace_in_bytes(&mut self) -> c_int {
    assert_eq!(self.state, DspState::Running);
    let mut info = std::mem::MaybeUninit::<audio_buf_info>::uninit();
    let err = unsafe { libc::ioctl(self.fd, SNDCTL_DSP_GETISPACE, info.as_mut_ptr()) };
    assert_ne!(err, -1);
    unsafe { info.assume_init().bytes }
  }
}

impl Drop for Dsp {

  fn drop(&mut self) {
    if self.fd != -1 {
      unsafe { libc::close(self.fd); }
    }
  }
}

use std::fs::read_to_string;

pub fn read_sndstat() -> Result<Vec<u32>, Errno> {
  let mut result = vec![];
  match read_to_string("/dev/sndstat") {
    Ok(str) =>
      for line in str.lines() {
        if line.starts_with("pcm") {
          if let Some(separator_index) = line.find(':') {
            if let Ok(index) = line[3..separator_index].parse::<u32>() {
              result.push(index);
            }
          }
        }
      },
    Err(err) => {
      return Err(Errno::from_i32(err.raw_os_error().unwrap_or(libc::EINVAL)));
    }
  }
  Ok(result)
}

#[derive(Debug)]
pub struct PcmDevice {
  pub index:    u32,
  pub desc:     String,
  pub location: String,
  pub play:     bool,
  pub rec:      bool
}

pub fn read_pcm_device_description(sysctl: &mut crate::utils::SysctlReader, index: u32) -> Option<String> {

  let parent = sysctl.read_string(format!("dev.pcm.{}.%parent", index), 1024).unwrap();
  if let Some(str) = parent.strip_prefix("uaudio") {
    if let Ok(idx) = str.parse::<u32>() {
      if let Ok(desc) = sysctl.read_string(format!("dev.uaudio.{}.%desc", idx), 1024) {
        // let's get rid of ", class %d/%d, rev %x.%02x/%x.%02x, addr %d" suffix
        let re = regex::Regex::new(r"^(.*?), class \d+/\d+, rev [^\s]+, addr \d$").unwrap();
        if let Some(groups) = re.captures(&desc) {
          if let Some(str) = groups.get(1) {
            return Some(str.as_str().to_string());
          }
        } else {
          return Some(desc);
        }
      }
    }
  }

  sysctl.read_string(format!("dev.pcm.{}.%desc", index), 1024).ok()
}

pub fn list_pcm_devices(indexes: &[u32]) -> Vec<PcmDevice> {

  let mut result = Vec::with_capacity(indexes.len());
  let mut sysctl = crate::utils::SysctlReader::new();

  for index in indexes {
    if let Some(desc) = read_pcm_device_description(&mut sysctl, *index) {
      if let Ok(location) = sysctl.read_string(format!("dev.pcm.{}.%location", index), 1024) {
        let play = sysctl.read_string(format!("dev.pcm.{}.play.vchanformat", index), 1024).is_ok();
        let rec  = sysctl.read_string(format!("dev.pcm.{}.rec.vchanformat",  index), 1024).is_ok();
        result.push(PcmDevice { index: *index, desc, location, play, rec });
      }
    }
  }

  result
}
