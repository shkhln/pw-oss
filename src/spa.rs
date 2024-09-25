use core::ffi::CStr;
use std::ffi::CString;
use std::os::raw::{c_int, c_void};
use libspa::sys::*;

pub const SPA_DEVICE_CHANGE_MASK_ALL: u32 =
  SPA_DEVICE_CHANGE_MASK_FLAGS  |
  SPA_DEVICE_CHANGE_MASK_PARAMS |
  SPA_DEVICE_CHANGE_MASK_PROPS;

pub const SPA_DEVICE_OBJECT_CHANGE_MASK_ALL: u32 =
  SPA_DEVICE_OBJECT_CHANGE_MASK_FLAGS |
  SPA_DEVICE_OBJECT_CHANGE_MASK_PROPS;

pub const SPA_NODE_CHANGE_MASK_ALL: u32 =
  SPA_NODE_CHANGE_MASK_FLAGS  |
  SPA_NODE_CHANGE_MASK_PARAMS |
  SPA_NODE_CHANGE_MASK_PROPS;

pub const SPA_PORT_CHANGE_MASK_ALL: u32 =
  SPA_PORT_CHANGE_MASK_FLAGS  |
  SPA_PORT_CHANGE_MASK_PARAMS |
  SPA_PORT_CHANGE_MASK_PROPS  |
  SPA_PORT_CHANGE_MASK_RATE;

pub unsafe fn for_each_hook(head: *mut spa_hook_list, mut apply: impl FnMut(&spa_hook)) {
  let mut entry = (*head).list.next as *mut spa_hook;
  while (*entry).link != (*head).list {
    apply(entry.as_ref().expect("broken spa_hook_list"));
    entry = (*entry).link.next as *mut spa_hook;
  }
}

pub unsafe fn dev_emit_result(hooks: &mut spa_hook_list, seq: c_int, res: c_int, type_: u32, result: &spa_result_device_params) {
  for_each_hook(hooks, |entry| {
    let f = entry.cb.funcs.cast::<spa_device_events>().as_ref().expect("hook should be initialized");
    assert!(f.version >= SPA_VERSION_DEVICE_EVENTS);
    if let Some(result_fun) = f.result {
      result_fun(entry.cb.data, seq, res, type_, result as *const _ as *const c_void);
    }
  });
}

pub unsafe fn node_emit_result(hooks: &mut spa_hook_list, seq: c_int, res: c_int, type_: u32, result: &spa_result_node_params) {
  for_each_hook(hooks, |entry| {
    let f = entry.cb.funcs.cast::<spa_node_events>().as_ref().expect("hook should be initialized");
    assert!(f.version >= SPA_VERSION_NODE_EVENTS);
    if let Some(result_fun) = f.result {
      result_fun(entry.cb.data, seq, res, type_, result as *const _ as *const c_void);
    }
  });
}

pub unsafe fn spa_loop_invoke(loop_: *const spa_loop, func: spa_invoke_func_t,
  seq: u32, data: *const c_void, size: usize, block: bool, user_data: *mut c_void) -> c_int
{
  let loop_methods = (*loop_).iface.cb.funcs.cast::<spa_loop_methods>().as_ref()
    .expect("loop should be initialized");
  assert!(loop_methods.version >= SPA_VERSION_LOOP_METHODS);
  let spa_loop_invoke = loop_methods.invoke.expect("invoke should be initialized");
  spa_loop_invoke((*loop_).iface.cb.data, func, seq, data, size, block, user_data)
}

pub unsafe fn for_each_dict_item(dict: &spa_dict, mut apply: impl FnMut(&str, &str)) {
  for item in std::slice::from_raw_parts(dict.items, dict.n_items as usize) {
    let key   = CStr::from_ptr(item.key)  .to_str().unwrap();
    let value = CStr::from_ptr(item.value).to_str().unwrap();
    apply(key, value);
  }
}

#[cfg(debug_assertions)]
pub unsafe fn dump_spa_dict(dict: &spa_dict) {
  for_each_dict_item(dict, |key, value| {
    eprintln!("dict item: key = {:?}, value = {:?}", key, value);
  });
}

pub enum DictionaryString {
  CString(CString),
  Ptr(*const i8)
}

impl From<&str> for DictionaryString {

  fn from(str: &str) -> Self {
    DictionaryString::CString(CString::new(str).unwrap())
  }
}

impl From<String> for DictionaryString {

  fn from(str: String) -> Self {
    DictionaryString::CString(CString::new(str).unwrap())
  }
}

impl From<*const u8> for DictionaryString {

  fn from(p: *const u8) -> Self {
    DictionaryString::Ptr(p.cast())
  }
}

const MAX_ITEMS: u32 = 1024;

pub struct Dictionary {
  dict:    spa_dict,
  items:   Vec<spa_dict_item>,
  strings: Vec<CString>
}

impl Dictionary {

  pub fn new() -> Self {
    Self {
      dict: spa_dict {
        flags:   0,
        n_items: 0,
        items:   std::ptr::null(),
      },
      items:   vec![],
      strings: vec![]
    }
  }

  pub fn fix_pointers(&mut self) {
    self.dict.items = self.items.as_ptr();
  }

  pub unsafe fn raw(&self) -> *const spa_dict {
    &self.dict as *const spa_dict
  }

  unsafe fn raw_mut(&mut self) -> *mut spa_dict {
    &mut self.dict as *mut spa_dict
  }

  pub fn len(&self) -> u32 {
    self.items.len() as u32
  }

  pub fn add_item<K: Into<DictionaryString>, V: Into<DictionaryString>>(&mut self, key: K, value: V) {

    assert!(self.items.len() < MAX_ITEMS as usize);

    match (key.into(), value.into()) {
      (DictionaryString::CString(key), DictionaryString::CString(value)) => {
        self.items.push(spa_dict_item { key: key.as_ptr(), value: value.as_ptr() });
        self.strings.push(key);
        self.strings.push(value);
      },
      (DictionaryString::CString(key), DictionaryString::Ptr(value)) => {
        self.items.push(spa_dict_item { key: key.as_ptr(), value });
        self.strings.push(key);
      },
      (DictionaryString::Ptr(key), DictionaryString::CString(value)) => {
        self.items.push(spa_dict_item { key, value: value.as_ptr() });
        self.strings.push(value);
      },
      (DictionaryString::Ptr(key), DictionaryString::Ptr(value)) => {
        self.items.push(spa_dict_item { key, value });
      }
    };

    self.dict.n_items = self.items.len() as u32;
    self.fix_pointers();
  }
}

const MAX_PARAMS: u32 = 16;

pub struct DeviceInfo {
  info:    spa_device_info,
  props:   Dictionary,
  params:  [spa_param_info; MAX_PARAMS as usize]
}

impl DeviceInfo {

  pub fn new() -> Self {
    Self {
      info: spa_device_info {
        version:     SPA_VERSION_DEVICE_INFO,
        change_mask: 0,
        flags:       0,
        props:       std::ptr::null(),
        params:      std::ptr::null_mut(),
        n_params:    0
      },
      props:  Dictionary::new(),
      params: [spa_param_info { id: 0, flags: 0, user: 0, seq: 0, padding: [0, 0, 0, 0] }; MAX_PARAMS as usize]
    }
  }

  pub fn fix_pointers(&mut self) {
    self.info.props  = unsafe { self.props.raw() };
    self.info.params = self.params.as_mut_ptr();
  }

  pub unsafe fn raw(&self) -> *const spa_device_info {
    &self.info as *const spa_device_info
  }

  pub fn add_prop<K: Into<DictionaryString>, V: Into<DictionaryString>>(&mut self, key: K, value: V) {
    self.props.add_item(key, value);
    self.info.change_mask |= SPA_DEVICE_CHANGE_MASK_PROPS as u64;
  }

  pub fn add_param(&mut self, id: u32, flags: u32) {
    assert!(self.info.n_params < MAX_PARAMS);
    self.params[self.info.n_params as usize] = spa_param_info {
      id, flags, user: 0, seq: 0, padding: [0, 0, 0, 0]
    };
    self.info.change_mask |= SPA_DEVICE_CHANGE_MASK_PARAMS as u64;
    self.info.n_params += 1;
  }

  pub fn replace_change_mask(&mut self, new_mask: u64) -> u64 {
    let old = self.info.change_mask;
    self.info.change_mask = new_mask;
    old
  }
}

pub struct NodeInfo {
  info:   spa_node_info,
  props:  Dictionary,
  params: [spa_param_info; MAX_PARAMS as usize],
}

impl NodeInfo {

  pub fn new() -> Self {
    Self {
      info: spa_node_info {
        max_input_ports:  0,
        max_output_ports: 0,
        change_mask:      0,
        flags:            0,
        props:            std::ptr::null_mut(),
        params:           std::ptr::null_mut(),
        n_params:         0
      },
      props:  Dictionary::new(),
      params: [spa_param_info { id: 0, flags: 0, user: 0, seq: 0, padding: [0, 0, 0, 0] }; MAX_PARAMS as usize],
    }
  }

  pub fn fix_pointers(&mut self) {
    self.info.props  = unsafe { self.props.raw_mut() };
    self.info.params = self.params.as_mut_ptr();
  }

  pub unsafe fn raw(&self) -> *const spa_node_info {
    &self.info as *const spa_node_info
  }

  pub fn set_max_input_ports(&mut self, max_ports: u32) {
    self.info.max_input_ports = max_ports;
    self.info.change_mask |= SPA_NODE_CHANGE_MASK_FLAGS as u64; // does this field count as a flag?
  }

  pub fn set_flags(&mut self, flags: u64) {
    self.info.flags = flags;
    self.info.change_mask |= SPA_NODE_CHANGE_MASK_FLAGS as u64;
  }

  pub fn add_prop<K: Into<DictionaryString>, V: Into<DictionaryString>>(&mut self, key: K, value: V) {
    self.props.add_item(key, value);
    self.info.change_mask |= SPA_NODE_CHANGE_MASK_PROPS as u64;
  }

  pub fn add_param(&mut self, id: u32, flags: u32) {
    assert!(self.info.n_params < MAX_PARAMS);
    self.params[self.info.n_params as usize] = spa_param_info {
      id, flags, user: 0, seq: 0, padding: [0, 0, 0, 0]
    };
    self.info.change_mask |= SPA_NODE_CHANGE_MASK_PARAMS as u64;
    self.info.n_params += 1;
  }

  pub fn replace_change_mask(&mut self, new_mask: u64) -> u64 {
    let old = self.info.change_mask;
    self.info.change_mask = new_mask;
    old
  }
}

pub struct PortInfo {
  info:    spa_port_info,
  props:   Dictionary,
  params:  [spa_param_info; MAX_PARAMS as usize]
}

impl PortInfo {

  pub fn new() -> Self {
    Self {
      info: spa_port_info {
        change_mask:      0,
        flags:            0,
        rate:             spa_fraction { num: 0, denom: 0 },
        props:            std::ptr::null_mut(),
        params:           std::ptr::null_mut(),
        n_params:         0
      },
      props:  Dictionary::new(),
      params: [spa_param_info { id: 0, flags: 0, user: 0, seq: 0, padding: [0, 0, 0, 0] }; MAX_PARAMS as usize],
    }
  }

  pub fn fix_pointers(&mut self) {
    self.info.props  = unsafe { self.props.raw_mut() };
    self.info.params = self.params.as_mut_ptr();
  }

  pub unsafe fn raw(&self) -> *const spa_port_info {
    &self.info as *const spa_port_info
  }

  pub fn set_flags(&mut self, flags: u64) {
    self.info.flags = flags;
    self.info.change_mask |= SPA_PORT_CHANGE_MASK_FLAGS as u64;
  }

  pub fn set_rate(&mut self, rate: spa_fraction) {
    self.info.rate = rate;
    self.info.change_mask |= SPA_PORT_CHANGE_MASK_RATE as u64;
  }

  pub fn add_prop<K: Into<DictionaryString>, V: Into<DictionaryString>>(&mut self, key: K, value: V) {
    self.props.add_item(key, value);
    self.info.change_mask |= SPA_PORT_CHANGE_MASK_PROPS as u64;
  }

  pub fn add_param(&mut self, id: u32, flags: u32) {
    assert!(self.info.n_params < MAX_PARAMS);
    self.params[self.info.n_params as usize] = spa_param_info {
      id, flags, user: 0, seq: 0, padding: [0, 0, 0, 0]
    };
    self.info.change_mask |= SPA_PORT_CHANGE_MASK_PARAMS as u64;
    self.info.n_params += 1;
  }

  pub fn replace_change_mask(&mut self, new_mask: u64) -> u64 {
    let old = self.info.change_mask;
    self.info.change_mask = new_mask;
    old
  }
}
