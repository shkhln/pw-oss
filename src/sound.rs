use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::raw::{c_int, c_long, c_uint, c_ulong, c_void};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use bbqueue::{BBBuffer, Consumer, Producer};
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
const SNDCTL_DSP_GETOSPACE:  c_ulong = nix::request_code_read!     (b'P', 12, std::mem::size_of::<audio_buf_info>());
//const SNDCTL_DSP_GETPLAYVOL: c_ulong = nix::request_code_read!     (b'P', 24, std::mem::size_of::<c_int>());
//const SNDCTL_DSP_SETPLAYVOL: c_ulong = nix::request_code_readwrite!(b'P', 24, std::mem::size_of::<c_int>());
const SNDCTL_DSP_GETODELAY:  c_ulong = nix::request_code_read!     (b'P', 23, std::mem::size_of::<c_int>());
const SNDCTL_DSP_GETERROR:   c_ulong = nix::request_code_read!     (b'P', 25, std::mem::size_of::<audio_errinfo>());

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
  let err = unsafe { libc::ioctl(fd, SNDCTL_DSP_GETOSPACE, info.as_mut_ptr()) };
  if err != -1 {
    unsafe { info.assume_init().bytes }
  } else {
    0
  }
}

fn odelay(fd: c_int) -> c_int {
  let mut delay: c_int = 4242;
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

const BUFFER_SIZE: usize = 131072;
const MAX_BUFFERS: usize = 8;

static BUFFERS: [BBBuffer<BUFFER_SIZE>; MAX_BUFFERS] = [const { BBBuffer::new() }; MAX_BUFFERS];
static USED_BUFFERS: Mutex<[bool; MAX_BUFFERS]> = Mutex::new([false; 8]);

fn grab_buffer() -> Option<usize> {
  let mut used = USED_BUFFERS.lock().unwrap();
  for i in 0..MAX_BUFFERS {
    if !used[i] {
      used[i] = true;
      return Some(i);
    }
  }
  None
}

fn return_buffer(index: usize) {
  let mut used = USED_BUFFERS.lock().unwrap();
  used[index] = false;
}

pub struct DspWriter {
  path:    CString,
  fd:      c_int,
  buf_idx: Option<usize>,
  prod:    Option<Producer<'static, BUFFER_SIZE>>,
  io_thr:  Option<std::thread::JoinHandle<Consumer<'static, BUFFER_SIZE>>>,
  closing: Arc<AtomicBool>,
  state:   DspState
}

impl DspWriter {

  pub fn new(path: &str) -> Self {
    Self {
      path:    CString::new(path).unwrap(),
      fd:      -1,
      buf_idx: None,
      prod:    None,
      io_thr:  None,
      closing: Arc::new(AtomicBool::new(false)),
      state:   DspState::Closed
    }
  }

  pub fn is_closed(&self) -> bool {
    self.state == DspState::Closed
  }

  pub fn is_running(&self) -> bool {
    self.state == DspState::Running
  }

  pub fn open(&mut self) -> Result<(), Errno> {
    let fd = unsafe { libc::open(self.path.as_ptr(), libc::O_WRONLY) };
    if fd == -1 {
      return Err(Errno::last());
    }

    self.fd    = fd;
    self.state = DspState::Setup;

    self.buf_idx = grab_buffer();
    let (mut prod, mut cons) = BUFFERS[self.buf_idx.unwrap()].try_split().unwrap();

    if self.io_thr.is_none() {
      let closing = self.closing.clone();
      self.io_thr = Some(std::thread::spawn(move || {
        loop {
          if closing.load(Ordering::Relaxed) {
            break;
          }
          match cons.read() {
            Ok(rgr) => {
              let len = rgr.buf().len();

              let ospace = ospace_in_bytes(fd) as usize;
              let odelay = odelay(fd);
              eprintln!("count: {:5}, ospace: {:5}, odelay: {:5}", len, ospace, odelay);

              let nbytes = unsafe { libc::write(fd, rgr.buf().as_ptr().cast(), len) };
              rgr.release(usize::MAX);
              if nbytes == -1 /*nbytes != len as isize*/ {
                break;
              }
            },
            Err(_) => {
              std::thread::sleep(std::time::Duration::from_millis(1));
            }
          }
        }
        cons
      }));
    }

    self.prod = Some(prod);

    Ok(())
  }

  pub fn close(&mut self) {
    assert_ne!(self.state, DspState::Closed);

    self.closing.store(true, Ordering::Relaxed);
    if let Some(prod) = self.prod.take() {
      if let Some(thr) = self.io_thr.take() {
        let cons = thr.join().unwrap();
        assert!(BUFFERS[self.buf_idx.unwrap()].try_release(prod, cons).is_ok());
      }
    }
    self.closing.store(false, Ordering::Relaxed);

    if let Some(index) = self.buf_idx.take() {
      return_buffer(index);
    }

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

  unsafe fn write_async(&mut self, buf: *const c_void, count: size_t) {

    if self.state == DspState::Setup {
      self.state = DspState::Running;
    }

    assert_eq!(self.state, DspState::Running);

    if let Some(prod) = &mut self.prod {
      let mut wgr = prod.grant_exact(count).unwrap();
      std::ptr::copy_nonoverlapping(buf as *mut u8, wgr.buf().as_ptr() as *mut u8, count);
      wgr.commit(count);
    }
  }

  unsafe fn write_sync(&mut self, buf: *const c_void, count: size_t) {
    if self.state == DspState::Setup {
      self.state = DspState::Running;
    }
    assert_eq!(self.state, DspState::Running);

    let ospace = ospace_in_bytes(self.fd) as usize;
    let odelay = odelay(self.fd);
    eprintln!("count: {:5}, ospace: {:5}, odelay: {:5}", count, ospace, odelay);

    let nbytes = libc::write(self.fd, buf, count);
    assert_eq!(nbytes, count as isize);
  }

  pub unsafe fn write(&mut self, buf: *const c_void, count: size_t) {
    self.write_async(buf, count);
  }

  pub fn underruns(&self) -> c_int {
    assert_eq!(self.state, DspState::Running);
    let info = get_error(self.fd);
    info.play_underruns
  }
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
