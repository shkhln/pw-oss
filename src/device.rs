use std::mem::MaybeUninit;
use std::os::raw::{c_char, c_int, c_void};
use libspa::sys::*;

#[repr(C)]
struct State {
  handle:      spa_handle,
  device:      spa_device,
  dev_info:    crate::spa::DeviceInfo,
  hooks:       spa_hook_list,
  pcm_devices: Vec<crate::sound::PcmDevice>,
  description: String
}

unsafe extern "C" fn add_listener(object: *mut c_void, listener: *mut spa_hook, events: *const spa_device_events, data: *mut c_void) -> c_int {

  let state = object.cast::<State>().as_mut()
    .expect("object is not supposed to be null");

  let mut save = MaybeUninit::<spa_hook_list>::uninit();
  spa_hook_list_isolate(&mut state.hooks, save.as_mut_ptr(), listener, events.cast(), data);

  crate::spa::for_each_hook(&mut state.hooks, |entry| {

    let f = entry.cb.funcs.cast::<spa_device_events>().as_ref()
      .expect("we just assigned events to this very hook by calling spa_hook_list_isolate");

    assert!(f.version >= SPA_VERSION_DEVICE_EVENTS);

    if let Some(dev_info_fun) = f.info {
      let old_mask = state.dev_info.replace_change_mask(crate::spa::SPA_DEVICE_CHANGE_MASK_ALL as u64);
      dev_info_fun(entry.cb.data, state.dev_info.raw());
      let _ = state.dev_info.replace_change_mask(old_mask);
    }

    for device in &state.pcm_devices {

      let mut dict = crate::spa::Dictionary::new();

      dict.add_item(SPA_KEY_NODE_NAME.as_ptr(), format!("pcm{}", device.index));

      if device.desc == state.description && !device.location.is_empty() {
        dict.add_item(SPA_KEY_NODE_DESCRIPTION.as_ptr(), format!("{} @ {}", device.desc, device.location));
      } else {
        dict.add_item(SPA_KEY_NODE_DESCRIPTION.as_ptr(), device.desc.as_str());
      }

      dict.add_item(crate::keys::OSS_DSP_PATH, format!("/dev/dsp{}", device.index));

      if device.play {
        let obj_info = spa_device_object_info {
          version:      SPA_VERSION_DEVICE_OBJECT_INFO,
          type_:        SPA_TYPE_INTERFACE_Node.as_ptr().cast(),
          factory_name: c"freebsd-oss.sink".as_ptr(),
          change_mask:  crate::spa::SPA_DEVICE_OBJECT_CHANGE_MASK_ALL as u64,
          flags:        0,
          props:        dict.raw()
        };

        if let Some(obj_info_fun) = f.object_info {
          obj_info_fun(entry.cb.data, device.index * 2, &obj_info);
        }
      }

      if device.rec {
        let obj_info = spa_device_object_info {
          version:      SPA_VERSION_DEVICE_OBJECT_INFO,
          type_:        SPA_TYPE_INTERFACE_Node.as_ptr().cast(),
          factory_name: c"freebsd-oss.source".as_ptr(),
          change_mask:  crate::spa::SPA_DEVICE_OBJECT_CHANGE_MASK_ALL as u64,
          flags:        0,
          props:        dict.raw()
        };

        if let Some(obj_info_fun) = f.object_info {
          obj_info_fun(entry.cb.data, device.index * 2 + 1, &obj_info);
        }
      }
    }
  });

  spa_hook_list_join(&mut state.hooks, save.assume_init_mut());
  0
}

unsafe extern "C" fn sync(object: *mut c_void, seq: c_int) -> c_int {

  let state = object.cast::<State>().as_mut()
    .expect("object is not supposed to be null");

  crate::spa::for_each_hook(&mut state.hooks, |entry| {
    let f = entry.cb.funcs.cast::<spa_device_events>().as_ref().expect("hook should be initialized");
    assert!(f.version >= SPA_VERSION_DEVICE_EVENTS);
    if let Some(result_fun) = f.result {
      result_fun(entry.cb.data, seq, 0, 0, std::ptr::null());
    }
  });

  0
}

/*unsafe extern "C" fn enum_params(object: *mut c_void, seq: c_int, id: u32, start: u32, max: u32, filter: *const spa_pod) -> c_int {

  let state = object.cast::<State>().as_mut()
    .expect("object is not supposed to be null");

  assert_ne!(max, 0);

  let mut buffer = vec![];

  let mut index = start;
  let mut count = 0;

  while count < max {

    use libspa::pod::builder::Builder;
    use libspa::pod::builder::builder_add;

    let mut builder = Builder::new(&mut buffer);

    #[allow(non_upper_case_globals)]
    match (id, index) {
      (SPA_PARAM_EnumProfile, _) => return 0,
      (SPA_PARAM_Profile, _)     => return 0,
      (SPA_PARAM_EnumRoute, _)   => return 0,
      (SPA_PARAM_Route, _)       => return 0,
      _ => unimplemented!()
    };

    let mut result = spa_result_device_params { id, index, next: index + 1, param: std::ptr::null_mut() };

    if spa_pod_filter(builder.as_raw_ptr(), &mut result.param, buffer.as_mut_ptr() as *mut spa_pod, filter) >= 0 {
      crate::spa::dev_emit_result(&mut state.hooks, seq, 0, SPA_RESULT_TYPE_DEVICE_PARAMS, &result);
      count += 1;
    }

    index += 1;
  }

  0
}*/

#[allow(unused_variables)]
unsafe extern "C" fn set_param(object: *mut c_void, id: u32, flags: u32, param: *const spa_pod) -> c_int {
  unimplemented!()
}

const DEVICE_IMPL: spa_device_methods = spa_device_methods {
  version:           SPA_VERSION_DEVICE_METHODS,
  add_listener:      Some(add_listener),
  sync:              Some(sync),
  enum_params:       None, //Some(enum_params),
  set_param:         Some(set_param),
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

unsafe extern "C" fn init(
  _factory:  *const spa_handle_factory,
  handle:    *mut   spa_handle,
  info:      *const spa_dict,
  support:   *const spa_support,
  n_support: u32
) -> c_int
{
  let log = spa_support_find(support, n_support, SPA_TYPE_INTERFACE_Log.as_ptr().cast()) as *mut spa_log;
  let log = crate::spa::Log::wrap(log);

  let state = handle.cast::<State>().as_mut()
    .expect("handle is not supposed to be null");

  let mut pcm_parent_device  = None;
  let mut pcm_device_indexes = vec![];

  if let Some(info) = info.as_ref() {
    #[cfg(debug_assertions)]
    crate::spa::dump_spa_dict(info);

    crate::spa::for_each_dict_item(info, |key, value| {
      match key {
        crate::keys::PCM_PARENT_DEVICE => {
          pcm_parent_device = Some(value.to_string());
        },
        crate::keys::PCM_DEVICE_INDEXES =>
          for part in value.split(',') {
            if let Ok(index) = part.parse::<u32>() {
              pcm_device_indexes.push(index);
            }
          },
        _ => ()
      }
    });
  }

  if pcm_device_indexes.is_empty() {
    crate::error!(log, "{} should contain pcm device indexes", crate::keys::PCM_DEVICE_INDEXES);
    return -libc::EINVAL;
  }

  let pcm_devices = crate::sound::list_pcm_devices(&pcm_device_indexes);

  if pcm_devices.is_empty() {
    crate::error!(log, "can't retrieve pcm device information");
    return -libc::EINVAL;
  }

  let mut common_desc = pcm_devices[0].desc.clone();
  for pcm_device in &pcm_devices[1..] {

    let mut count = 0;

    for (a, b) in common_desc.bytes().zip(pcm_device.desc.bytes()) {
      if a == b {
        count += 1;
      } else {
        break;
      }
    }

    common_desc.truncate(count);
  }

  while common_desc.ends_with(' ') || common_desc.ends_with('(') {
    common_desc.truncate(common_desc.len() - 1);
  }

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

    dev_info: crate::spa::DeviceInfo::new(),

    hooks: spa_hook_list {
      list: spa_list {
        next: std::ptr::null_mut(),
        prev: std::ptr::null_mut()
      }
    },

    pcm_devices,
    description: common_desc
  });

  state.dev_info.fix_pointers();
  state.dev_info.add_prop(SPA_KEY_DEVICE_API .as_ptr(), "freebsd-oss");
  state.dev_info.add_prop(SPA_KEY_MEDIA_CLASS.as_ptr(), "Audio/Device");
  if let Some(pcm_parent_device) = pcm_parent_device {
    state.dev_info.add_prop(SPA_KEY_DEVICE_NAME.as_ptr(), pcm_parent_device);
  }
  state.dev_info.add_prop(SPA_KEY_DEVICE_DESCRIPTION.as_ptr(), state.description.as_str());
  state.dev_info.add_param(SPA_PARAM_EnumProfile, SPA_PARAM_INFO_READ);
  state.dev_info.add_param(SPA_PARAM_Profile,     SPA_PARAM_INFO_READWRITE);
  state.dev_info.add_param(SPA_PARAM_EnumRoute,   SPA_PARAM_INFO_READ);
  state.dev_info.add_param(SPA_PARAM_Route,       SPA_PARAM_INFO_READWRITE);

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

const OSS_DEVICE_FACTORY_INFO: spa_dict = spa_dict {
  flags:   0,
  n_items: 0,
  items:   std::ptr::null()
};

pub const OSS_DEVICE_FACTORY: spa_handle_factory = spa_handle_factory {
  version:             SPA_VERSION_HANDLE_FACTORY,
  name:                c"freebsd-oss.device".as_ptr(),
  info:                &OSS_DEVICE_FACTORY_INFO,
  get_size:            Some(get_size),
  init:                Some(init),
  enum_interface_info: Some(enum_interface_info)
};
