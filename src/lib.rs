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

mod dll;

mod keys;
mod sound;
mod utils;

use device ::OSS_DEVICE_FACTORY;
use monitor::OSS_MONITOR_FACTORY;
use sink   ::OSS_SINK_FACTORY;
use source ::OSS_SOURCE_FACTORY;

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

use libspa::sys::{spa_log_topic, spa_log_topic_enum, SPA_VERSION_LOG_TOPIC_ENUM};

#[allow(dead_code)]
#[cfg(target_pointer_width = "64")]
#[repr(align(8))]
struct AlignedTopicPointer(*mut spa_log_topic);

#[link_section = "spa_log_topic"]
#[no_mangle]
#[used]
static mut spa_log_topic_export_oss_device:  AlignedTopicPointer =
  AlignedTopicPointer(&raw mut device::OSS_DEVICE_TOPIC);

#[link_section = "spa_log_topic"]
#[no_mangle]
#[used]
static mut spa_log_topic_export_oss_sink:    AlignedTopicPointer =
  AlignedTopicPointer(&raw mut sink::OSS_SINK_TOPIC);

#[link_section = "spa_log_topic"]
#[no_mangle]
#[used]
static mut spa_log_topic_export_oss_source:  AlignedTopicPointer =
  AlignedTopicPointer(&raw mut source::OSS_SOURCE_TOPIC);

#[link_section = "spa_log_topic"]
#[no_mangle]
#[used]
static mut spa_log_topic_export_oss_monitor: AlignedTopicPointer =
  AlignedTopicPointer(&raw mut monitor::OSS_MONITOR_TOPIC);

extern "C" {
  static __start_spa_log_topic: *mut spa_log_topic;
  static __stop_spa_log_topic:  *mut spa_log_topic;
}

#[no_mangle]
#[used]
static mut spa_log_topic_enum: spa_log_topic_enum = libspa::sys::spa_log_topic_enum {
  version: SPA_VERSION_LOG_TOPIC_ENUM,
  topics:     &raw const __start_spa_log_topic,
  topics_end: &raw const __stop_spa_log_topic,
};
