use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::raw::{c_int, c_long, c_uint, c_ulong, c_void};
use libc::{size_t, ssize_t};
use nix::errno::Errno;

pub const AFMT_S16_LE: u32 = 0x00000010;
pub const AFMT_S16_BE: u32 = 0x00000020;
pub const AFMT_S32_LE: u32 = 0x00001000;
pub const AFMT_S32_BE: u32 = 0x00002000;

const SNDCTL_DSP_SPEED:       c_ulong = nix::request_code_readwrite!(b'P',  2, std::mem::size_of::<c_int>());
const SNDCTL_DSP_SETFMT:      c_ulong = nix::request_code_readwrite!(b'P',  5, std::mem::size_of::<c_int>());
const SNDCTL_DSP_CHANNELS:    c_ulong = nix::request_code_readwrite!(b'P',  6, std::mem::size_of::<c_int>());
const SNDCTL_DSP_SETFRAGMENT: c_ulong = nix::request_code_readwrite!(b'P', 10, std::mem::size_of::<c_int>());
const SNDCTL_DSP_GETOSPACE:   c_ulong = nix::request_code_read!     (b'P', 12, std::mem::size_of::<audio_buf_info>());
const SNDCTL_DSP_GETISPACE:   c_ulong = nix::request_code_read!     (b'P', 13, std::mem::size_of::<audio_buf_info>());
//const SNDCTL_DSP_SETTRIGGER:  c_ulong = nix::request_code_write!    (b'P', 16, std::mem::size_of::<c_int>());
//const SNDCTL_DSP_GETPLAYVOL:  c_ulong = nix::request_code_read!     (b'P', 24, std::mem::size_of::<c_int>());
//const SNDCTL_DSP_SETPLAYVOL:  c_ulong = nix::request_code_readwrite!(b'P', 24, std::mem::size_of::<c_int>());
const SNDCTL_DSP_GETODELAY:   c_ulong = nix::request_code_read!     (b'P', 23, std::mem::size_of::<c_int>());
const SNDCTL_DSP_GETERROR:    c_ulong = nix::request_code_read!     (b'P', 25, std::mem::size_of::<audio_errinfo>());

const PCM_ENABLE_INPUT:  c_int = 0x00000001;
const PCM_ENABLE_OUTPUT: c_int = 0x00000002;

#[repr(C)]
struct audio_buf_info {
  fragments:  c_int,
  fragstotal: c_int,
  fragsize:   c_int,
  bytes:      c_int
}

#[repr(C)]
struct audio_errinfo {
  play_underruns:  c_int,
  rec_overruns:    c_int,
  play_ptradjust:  c_uint,
  rec_ptradjust:   c_uint,
  play_errorcount: c_int,
  rec_errorcount:  c_int,
  play_lasterror:  c_int,
  rec_lasterror:   c_int,
  play_errorparm:  c_long,
  rec_errorparm:   c_long,
  filler:          [c_int; 16]
}

#[derive(Debug, PartialEq)]
enum DspState {
  Closed,
  Setup,
  Running
}

fn set_format(fd: c_int, format: u32) {
  let mut f = format as c_int;
  let err = unsafe { libc::ioctl(fd, SNDCTL_DSP_SETFMT, &mut f) };
  assert_ne!(err, -1);
  assert_eq!(f, format as c_int);
}

fn set_channels(fd: c_int, channels: u32) {
  let mut n = channels as c_int;
  let err = unsafe { libc::ioctl(fd, SNDCTL_DSP_CHANNELS, &mut n) };
  assert_ne!(err, -1);
  assert_eq!(n, channels as c_int);
}

fn set_rate(fd: c_int, rate: u32) {
  let mut n = rate as c_int;
  let err = unsafe { libc::ioctl(fd, SNDCTL_DSP_SPEED, &mut n) };
  assert_ne!(err, -1);
  assert_eq!(n, rate as c_int);
}

fn ospace_in_bytes(fd: c_int) -> c_int {
  let mut info = std::mem::MaybeUninit::<audio_buf_info>::uninit();
  unsafe {
    let err = libc::ioctl(fd, SNDCTL_DSP_GETOSPACE, info.as_mut_ptr());
    assert_ne!(err, -1);
    info.assume_init().bytes
  }
}

fn set_fragment(fd: c_int, n_frags: u16, frag_size_selector: u16) {
  let mut s = ((n_frags as u32) << 16) | frag_size_selector as u32;
  let err = unsafe { libc::ioctl(fd, SNDCTL_DSP_SETFRAGMENT, &mut s) };
  assert_ne!(err, -1);
  let out_len = ((s & 0xFFFF0000) >> 16) * (2u32 << (s & 0x0000FFFF));
  assert!(out_len >= n_frags as u32 * (2u32 << frag_size_selector));
}

/*fn set_trigger(fd: c_int, mask: c_int) {
  let mut m = mask as c_int;
  let err = unsafe { libc::ioctl(fd, SNDCTL_DSP_SETTRIGGER, &mut m) };
  assert_ne!(err, -1);
  assert_eq!(m, mask as c_int);
}*/

fn odelay(fd: c_int) -> c_int {
  let mut delay: c_int = -1;
  let err = unsafe { libc::ioctl(fd, SNDCTL_DSP_GETODELAY, &mut delay) };
  assert_ne!(err, -1);
  delay
}

fn get_error(fd: c_int) -> audio_errinfo {
  let mut info = std::mem::MaybeUninit::<audio_errinfo>::uninit();
  unsafe {
    let err = libc::ioctl(fd, SNDCTL_DSP_GETERROR, info.as_mut_ptr());
    assert_ne!(err, -1);
    info.assume_init()
  }
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
    set_format(self.fd, format);
  }

  pub fn set_channels(&mut self, channels: u32) {
    assert_eq!(self.state, DspState::Setup);
    set_channels(self.fd, channels);
  }

  pub fn set_rate(&mut self, rate: u32) {
    assert_eq!(self.state, DspState::Setup);
    set_rate(self.fd, rate);
  }

  pub unsafe fn read(&mut self, buf: *mut c_void, count: size_t) -> ssize_t {
    if self.state == DspState::Setup {
      self.state = DspState::Running;
    }
    assert_eq!(self.state, DspState::Running);
    libc::read(self.fd, buf, count)
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
    if err != -1 {
      unsafe { info.assume_init().bytes }
    } else {
      0
    }
  }
}

pub struct DspWriter {
  pub path: String,
  fd:      c_int,
  state:   DspState,
  #[cfg(debug_assertions)]
  prev_ns: u64
}

const ZEROES: [u8; 131072] = [0u8; 131072];

impl DspWriter {

  pub fn new(path: &str) -> Self {
    Self {
      path:    path.to_string(),
      fd:      -1,
      state:   DspState::Closed,
      #[cfg(debug_assertions)]
      prev_ns: 0
    }
  }

  pub fn is_closed(&self) -> bool {
    self.state == DspState::Closed
  }

  pub fn is_running(&self) -> bool {
    self.state == DspState::Running
  }

  pub fn open(&mut self) -> Result<(), Errno> {
    let path = CString::new(self.path.clone()).unwrap();
    let fd   = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
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
    set_format(self.fd, format);
  }

  pub fn set_channels(&mut self, channels: u32) {
    assert_eq!(self.state, DspState::Setup);
    set_channels(self.fd, channels);
  }

  pub fn set_rate(&mut self, rate: u32) {
    assert_eq!(self.state, DspState::Setup);
    set_rate(self.fd, rate);
  }

  pub fn set_buffer_size(&mut self, len: usize) {
    assert_eq!(self.state, DspState::Setup);
    set_fragment(self.fd, (len as f32 / 1024.0).ceil() as u16, 10);
  }

  pub unsafe fn write(&mut self, buf: *const c_void, count: size_t) -> ssize_t {
    if self.state == DspState::Setup {
      self.state = DspState::Running;
    }
    assert_eq!(self.state, DspState::Running);

    #[cfg(debug_assertions)]
    let space = ospace_in_bytes(self.fd) as usize;
    #[cfg(debug_assertions)]
    let delay = odelay(self.fd);

    let nbytes = libc::write(self.fd, buf, count);

    #[cfg(debug_assertions)]
    {
      let now         = crate::utils::now_ns_libc();
      let space_after = ospace_in_bytes(self.fd) as usize;
      let delay_after = odelay(self.fd);
      eprintln!("{}: {:9} @ {}, count = {:5}, ospace = {:5} -> {:5}, odelay = {:5} -> {:5}",
        self.path, now - self.prev_ns, now, count, space, space_after, delay, delay_after);
      self.prev_ns = now;
    }

    nbytes
  }

  pub fn write_zeroes(&mut self, count: usize) {
    assert!(count <= ZEROES.len());
    let nbytes = unsafe { self.write(ZEROES.as_ptr().cast(), count) };
    assert_eq!(nbytes, count as isize);
  }

  pub fn underruns(&self) -> u32 {
    assert_eq!(self.state, DspState::Running);
    let uruns = get_error(self.fd).play_underruns;
    assert!(uruns >= 0);
    uruns as u32
  }

  /*pub fn pause(&self) {
    assert_eq!(self.state, DspState::Running);
    set_trigger(self.fd, 0);
  }*/

  /*pub fn resume(&self) {
    assert_eq!(self.state, DspState::Running);
    set_trigger(self.fd, PCM_ENABLE_OUTPUT);
  }*/
}

impl Drop for DspWriter {

  fn drop(&mut self) {
    if !self.is_closed() {
      self.close();
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

pub fn group_pcm_devices_by_parent(indexes: &[u32]) -> BTreeMap<String, Vec<u32>> {
  let mut sysctl = crate::utils::SysctlReader::new();
  let mut indexes_by_parent: BTreeMap<String, Vec<u32>> = BTreeMap::new();
  for index in indexes {
    if let Ok(parent) = sysctl.read_string(format!("dev.pcm.{}.%parent", index), 1024) {
      let values = indexes_by_parent.entry(parent).or_default();
      values.push(*index);
    }
  }
  indexes_by_parent
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
