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
