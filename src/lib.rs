use std::os::raw::c_int;
use libspa::sys::spa_handle_factory;

#[allow(clippy::absurd_extreme_comparisons)]
mod device;
#[allow(clippy::absurd_extreme_comparisons)]
mod monitor;
#[allow(clippy::absurd_extreme_comparisons)]
mod sink;
#[allow(clippy::absurd_extreme_comparisons)]
mod source;
#[allow(clippy::absurd_extreme_comparisons)]
mod spa;

mod keys;
mod sound;
mod utils;

use device::OSS_DEVICE_FACTORY;
use monitor::OSS_MONITOR_FACTORY;
use sink::OSS_SINK_FACTORY;
use source::OSS_SOURCE_FACTORY;

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn spa_handle_factory_enum(factory: *mut *const spa_handle_factory, index: *mut u32) -> c_int {
  assert!(!factory.is_null());
  assert!(!index  .is_null());
  match *index {
    0 => { *factory = &OSS_MONITOR_FACTORY; *index += 1; 1 },
    1 => { *factory = &OSS_DEVICE_FACTORY;  *index += 1; 1 },
    2 => { *factory = &OSS_SINK_FACTORY;    *index += 1; 1 },
    3 => { *factory = &OSS_SOURCE_FACTORY;  *index += 1; 1 },
    _ => 0
  }
}
