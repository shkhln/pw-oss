use std::collections::BTreeMap;
use std::mem::MaybeUninit;
use std::os::raw::{c_char, c_int, c_void};
use std::string::String;
use std::vec::Vec;
use libspa::sys::*;

#[repr(C)]
struct State {
  handle:   spa_handle,
  device:   spa_device,
  dev_info: spa_device_info,
  hooks:    spa_hook_list
}

unsafe extern "C" fn add_listener(object: *mut c_void, listener: *mut spa_hook, events: *const spa_device_events, data: *mut c_void) -> c_int {

  let state = object.cast::<State>().as_mut()
    .expect("object is not supposed to be null");

  let pcm_device_indexes = match crate::sound::read_sndstat() {
    Ok(indexes) => indexes,
    Err(err)    => {
      eprintln!("Can't open /dev/sndstat: {}", err);
      return -(err as c_int);
    }
  };

  let mut indexes_by_parent: BTreeMap<String, Vec<u32>> = BTreeMap::new();
  let mut sysctl = crate::utils::SysctlReader::new();

  for index in pcm_device_indexes {
    if let Ok(parent) = sysctl.read_string(format!("dev.pcm.{}.%parent", index), 1024) {
      let values = indexes_by_parent.entry(parent).or_default();
      values.push(index);
    }
  }

  let mut save = MaybeUninit::<spa_hook_list>::uninit();
  spa_hook_list_isolate(&mut state.hooks, save.as_mut_ptr(), listener, events.cast(), data);

  crate::spa::for_each_hook(&mut state.hooks, |entry| {

    let f = entry.cb.funcs.cast::<spa_device_events>().as_ref()
      .expect("we just assigned events to this very hook by calling spa_hook_list_isolate");

    assert!(f.version >= SPA_VERSION_DEVICE_EVENTS);

    state.dev_info.change_mask = crate::spa::SPA_DEVICE_CHANGE_MASK_ALL as u64;

    if let Some(dev_info_fun) = f.info {
      dev_info_fun(entry.cb.data, &state.dev_info);
    }

    for (parent, indexes) in &indexes_by_parent {

      let indexes_str = indexes.iter().map(|i| format!("{}", i)).collect::<Vec<_>>().join(",");

      let mut dict = crate::spa::Dictionary::new();
      dict.add_item(crate::keys::PCM_PARENT_DEVICE,  parent.as_str());
      dict.add_item(crate::keys::PCM_DEVICE_INDEXES, indexes_str);

      let obj_info = spa_device_object_info {
        version:      SPA_VERSION_DEVICE_OBJECT_INFO,
        type_:        SPA_TYPE_INTERFACE_Device.as_ptr().cast(),
        factory_name: c"freebsd-oss.device".as_ptr(),
        change_mask:  crate::spa::SPA_DEVICE_OBJECT_CHANGE_MASK_ALL as u64,
        flags:        0,
        props:        dict.raw()
      };

      if let Some(obj_info_fun) = f.object_info {
        obj_info_fun(entry.cb.data, indexes[0], &obj_info);
      }
    }
  });

  spa_hook_list_join(&mut state.hooks, save.assume_init_mut());
  0
}

const DEVICE_IMPL: spa_device_methods = spa_device_methods {
  version:      SPA_VERSION_DEVICE_METHODS,
  add_listener: Some(add_listener),
  sync:         None,
  enum_params:  None,
  set_param:    None
};

unsafe extern "C" fn get_interface(handle: *mut spa_handle, type_: *const c_char, interface: *mut *mut c_void) -> c_int {

  let state = handle.cast::<State>().as_mut()
    .expect("handle is not supposed to be null");

  assert!(!interface.is_null());

  if spa_streq(type_, SPA_TYPE_INTERFACE_Device.as_ptr().cast()) {
    *interface = &mut state.device as *mut _ as *mut c_void;
  } else {
    unimplemented!()
  }

  0
}

unsafe extern "C" fn clear(handle: *mut spa_handle) -> c_int {
  let state = handle.cast::<State>().as_mut()
    .expect("handle is not supposed to be null");
  std::ptr::drop_in_place(state);
  0
}

unsafe extern "C" fn get_size(_factory: *const spa_handle_factory, _params: *const spa_dict) -> usize {
  std::mem::size_of::<State>()
}

const DEV_INFO_PROPS: spa_dict = spa_dict {
  flags:   0,
  n_items: 0,
  items:   std::ptr::null()
};

unsafe extern "C" fn init(
  _factory:   *const spa_handle_factory,
  handle:     *mut   spa_handle,
  _info:      *const spa_dict,
  _support:   *const spa_support,
  _n_support: u32
) -> c_int
{
  let state = handle.cast::<State>().as_mut()
    .expect("handle is not supposed to be null");

  std::ptr::write(state, State {

    handle: spa_handle {
      version:       SPA_VERSION_HANDLE,
      get_interface: Some(get_interface),
      clear:         Some(clear)
    },

    device: spa_device {
      iface: spa_interface {
        type_:   SPA_TYPE_INTERFACE_Device.as_ptr().cast(),
        version: SPA_VERSION_DEVICE,
        cb: spa_callbacks {
          funcs: &DEVICE_IMPL as *const _ as *const c_void,
          data:  state as *mut _ as *mut c_void
        }
      }
    },

    dev_info: spa_device_info {
      version:     SPA_VERSION_DEVICE_INFO,
      change_mask: 0,
      flags:       0,
      props:       &DEV_INFO_PROPS,
      params:      std::ptr::null_mut(),
      n_params:    0
    },

    hooks: spa_hook_list {
      list: spa_list {
        next: std::ptr::null_mut(),
        prev: std::ptr::null_mut()
      }
    }
  });

  spa_hook_list_init(&mut state.hooks);

  0
}

const INTERFACE_INFO: [spa_interface_info; 1] = [
  spa_interface_info {
    type_: SPA_TYPE_INTERFACE_Device.as_ptr().cast()
  }
];

unsafe extern "C" fn enum_interface_info(_factory: *const spa_handle_factory, info: *mut *const spa_interface_info, index: *mut u32) -> c_int {
  assert!(!info .is_null());
  assert!(!index.is_null());
  match *index {
    0 => { *info = &INTERFACE_INFO[0]; *index += 1; 1 }
    _ => 0
  }
}

pub const OSS_MONITOR_FACTORY: spa_handle_factory = spa_handle_factory {
  version:             SPA_VERSION_HANDLE_FACTORY,
  name:                c"freebsd-oss.monitor".as_ptr(),
  info:                std::ptr::null(),
  get_size:            Some(get_size),
  init:                Some(init),
  enum_interface_info: Some(enum_interface_info)
};
