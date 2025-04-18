use std::mem::MaybeUninit;
use std::os::raw::{c_char, c_int, c_void};

use libspa::sys::*;

const MAX_PORTS: usize = 1;

#[repr(C)]
struct State {
  handle:        spa_handle,
  node:          spa_node,
  node_info:     crate::spa::NodeInfo,
  port_info:     crate::spa::PortInfo,
  data_loop:     crate::spa::Loop,
  data_system:   crate::spa::System,
  log:           crate::spa::Log,
  clock:         *mut spa_io_clock,
  position:      *mut spa_io_position,
  rate_match:    *mut spa_io_rate_match,
  timer_source:  spa_source,
  next_time:     u64,
  hooks:         spa_hook_list,
  callbacks:     spa_callbacks,
  ports:         [Port; MAX_PORTS],
  started:       bool,
  following:     bool,
  cur_timestamp: u64,  // method invocation timestamp for `process`
  old_timestamp: u64,
  oss_delay:     u32 // additional delay in 1/8ths of period
}

impl State {

  fn node_is_follower(&self) -> bool {
    !self.clock.is_null() && !self.position.is_null() && unsafe { (*self.position).clock.id != (*self.clock).id }
  }
}

struct Port {
  config:         Option<PortConfig>,
  buffers:        Vec<*mut spa_buffer>,
  io:             *mut spa_io_buffers,
  dsp:            crate::sound::DspWriter,
  xrun_timestamp: u64, // the moment we noticed an underrun (which is a bit later than the start of it)
  dll:            crate::dll::SpaDLL
}

pub struct PortConfig {
  pub format:    libspa::param::audio::AudioFormat,
  pub rate:      u32,
  pub channels:  u32,
  pub positions: Vec<u32>
}

impl PortConfig {

  fn bytes_per_sample(&self) -> u32 {
    match self.format {
      libspa::param::audio::AudioFormat::S32LE => 4,
      libspa::param::audio::AudioFormat::S32BE => 4,
      libspa::param::audio::AudioFormat::S16LE => 2,
      libspa::param::audio::AudioFormat::S16BE => 2,
      _ => unreachable!()
    }
  }

  fn stride(&self) -> u32 {
    self.bytes_per_sample() * self.channels
  }
}

unsafe extern "C" fn add_listener(object: *mut c_void, listener: *mut spa_hook, events: *const spa_node_events, data: *mut c_void) -> c_int {

  let state = object.cast::<State>().as_mut()
    .expect("object is not supposed to be null");

  let mut save = MaybeUninit::<spa_hook_list>::uninit();
  spa_hook_list_isolate(&mut state.hooks, save.as_mut_ptr(), listener, events.cast(), data);

  // note that this only iterates over the newly added listener
  crate::spa::for_each_hook(&mut state.hooks, |entry| {

    let f = entry.cb.funcs.cast::<spa_node_events>().as_ref()
      .expect("we just assigned events to this very hook by calling spa_hook_list_isolate");

    assert!(f.version >= SPA_VERSION_NODE_EVENTS);

    if let Some(node_info_fun) = f.info {
      let old_mask = state.node_info.replace_change_mask(crate::spa::SPA_NODE_CHANGE_MASK_ALL as u64);
      node_info_fun(entry.cb.data, state.node_info.raw());
      let _ = state.node_info.replace_change_mask(old_mask);
    }

    if let Some(port_info_fun) = f.port_info {
      let old_mask = state.port_info.replace_change_mask(crate::spa::SPA_PORT_CHANGE_MASK_ALL as u64);
      port_info_fun(entry.cb.data, SPA_DIRECTION_INPUT, 0, state.port_info.raw());
      let _ = state.port_info.replace_change_mask(old_mask);
    }
  });

  spa_hook_list_join(&mut state.hooks, save.assume_init_mut());

  0
}

unsafe extern "C" fn set_callbacks(object: *mut c_void, callbacks: *const spa_node_callbacks, data: *mut c_void) -> c_int {
  let state = object.cast::<State>().as_mut()
    .expect("object is not supposed to be null");
  state.callbacks.funcs = callbacks as *const c_void;
  state.callbacks.data  = data;
  0
}

#[allow(unused_variables)]
unsafe extern "C" fn sync(object: *mut c_void, seq: c_int) -> c_int {
  unimplemented!()
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
      //TODO: ?
      _ => unimplemented!()
    };

    let mut result = spa_result_node_params { id, index, next: index + 1, param: std::ptr::null_mut() };

    if spa_pod_filter(builder.as_raw_ptr(), &mut result.param, buffer.as_mut_ptr() as *mut spa_pod, filter) >= 0 {
      crate::spa::node_emit_result(&mut state.hooks, seq, 0, SPA_RESULT_TYPE_NODE_PARAMS, &result);
      count += 1;
    }

    index += 1;
  }

  0
}*/

unsafe extern "C" fn set_param(object: *mut c_void, id: u32, _flags: u32, param: *const spa_pod) -> c_int {

  let state = object.cast::<State>().as_mut()
    .expect("object is not supposed to be null");

  use libspa::pod::{Value, Object, Pod};
  use libspa::pod::deserialize::PodDeserializer;

  #[allow(non_upper_case_globals)]
  match id {
    SPA_PARAM_Props => {
      assert!(!param.is_null());
      match PodDeserializer::deserialize_any_from(Pod::from_raw(param).as_bytes()) {
        Ok((_, Value::Object(Object { type_, properties, .. }))) if type_ == SPA_TYPE_OBJECT_Props => {
          for property in properties {
            match property.key {
              // there is no way adapter is actually supposed to pass all those properties (or parameters?) to us,
              // it's probably a bug
              SPA_PROP_volume         => (), // fuck it
              SPA_PROP_mute           => (), // ditto
              SPA_PROP_channelVolumes => (), // ditto
              SPA_PROP_channelMap     => (), // ditto
              SPA_PROP_monitorMute    => (), // ditto
              SPA_PROP_monitorVolumes => (), // ditto
              SPA_PROP_softMute       => (), // ditto
              SPA_PROP_softVolumes    => (), // ditto
              SPA_PROP_params         => {
                match property.value {
                  Value::Struct(values) if values.len() % 2 == 0 => {
                    for kv in values.chunks(2) {
                      match (&kv[0], &kv[1]) {
                        // pw-cli set-param <object-id> Props '{ "params": ["oss.delay", 8]}'
                        (Value::String(s), Value::Int(x)) if s == "oss.delay" && *x >= 0 => {
                          state.oss_delay = *x as u32;
                        },
                        _ => ()
                      }
                    }
                  }
                  _ => ()
                }
              },
              _ => unimplemented!()
            }
          }
        },
        _ => return -libc::EINVAL
      }
      0
    },
    _ => unimplemented!()
  }
}

unsafe extern "C" fn on_timeout(source: *mut spa_source) {

  let state = (*source).data.cast::<State>().as_mut()
    .expect("(*source).data is not supposed to be null");

  #[cfg(debug_assertions)]
  crate::trace!(state.log, "on_timeout");

  let mut expirations = 0;
  let err = state.data_system.timerfd_read(state.timer_source.fd, &mut expirations);
  assert_ne!(err, -1);

  let nsec = state.next_time;

  assert!(!state.position.is_null());

  #[cfg(debug_assertions)]
  {
    let now   = crate::utils::now_ns(&state.data_system);
    let delay = now - nsec;
    eprintln!("cycle: {}, delay: {} ms @ {}", (*state.position).clock.cycle, delay as f64 / 1000000.0, now);
  }

  let duration = (*state.position).clock.target_duration;
  let rate     = (*state.position).clock.target_rate.denom;

  state.next_time = nsec + duration * SPA_NSEC_PER_SEC as u64 / rate as u64;

  assert!(!state.clock.is_null());

  (*state.clock).nsec      = nsec;
  (*state.clock).rate      = (*state.clock).target_rate; // ?
  (*state.clock).position += (*state.clock).duration;
  (*state.clock).duration  = duration;
  (*state.clock).delay     = 0;
  (*state.clock).rate_diff = 1.0;
  (*state.clock).next_nsec = state.next_time;

  let node_callbacks = state.callbacks.funcs.cast::<spa_node_callbacks>().as_ref()
    .expect("callbacks should be initialized");
  assert!(node_callbacks.version >= SPA_VERSION_NODE_CALLBACKS);
  if let Some(ready_fun) = node_callbacks.ready {
    let err = ready_fun(state.callbacks.data, SPA_STATUS_NEED_DATA as i32);
    #[cfg(debug_assertions)]
    crate::trace!(state.log, "ready -> {}", err);
    #[cfg(not(debug_assertions))]
    let _ = err;
  }

  set_timeout(state, state.next_time);
}

unsafe fn set_timeout(state: &mut State, next_time: u64) {

  #[cfg(debug_assertions)]
  crate::trace!(state.log, "set_timeout {}", next_time);

  let timerspec = itimerspec {
    it_value: timespec {
      tv_sec:  (next_time / SPA_NSEC_PER_SEC as u64) as i64,
      tv_nsec: (next_time % SPA_NSEC_PER_SEC as u64) as i64
    },
    it_interval: timespec { tv_sec: 0, tv_nsec: 0 }
  };

  state.data_system.timerfd_settime(state.timer_source.fd, SPA_FD_TIMER_ABSTIME as i32, &timerspec, std::ptr::null_mut());
}

#[allow(unused_variables)]
unsafe extern "C" fn set_timers(loop_: *mut spa_loop, async_: bool, seq: u32, data: *const c_void, size: usize, user_data: *mut c_void) -> c_int {

  let state = user_data.cast::<State>().as_mut()
    .expect("user_data is not supposed to be null");

  #[cfg(debug_assertions)]
  crate::trace!(state.log, "set_timers");

  if state.started && !state.following {
    state.next_time = crate::utils::now_ns(&state.data_system);
    #[cfg(debug_assertions)]
    crate::trace!(state.log, "next time {}", state.next_time);
    set_timeout(state, state.next_time);
  } else {
    #[cfg(debug_assertions)]
    crate::trace!(state.log, "next time {}", 0);
    set_timeout(state, 0);
  }

  0
}

unsafe extern "C" fn set_io(object: *mut c_void, id: u32, data: *mut c_void, size: usize) -> c_int {

  let state = object.cast::<State>().as_mut()
    .expect("object is not supposed to be null");

  #[allow(non_upper_case_globals)]
  match id {
    SPA_IO_Clock    => {
      assert_eq!(size, std::mem::size_of::<spa_io_clock>());
      state.clock = data.cast();
    },
    SPA_IO_Position => {
      assert_eq!(size, std::mem::size_of::<spa_io_position>());
      state.position = data.cast();
    },
    _ => unimplemented!()
  };

  if state.started {
    let following = state.node_is_follower();
    if state.following != following {
      state.following = following;
      //TODO: do we just ignore the result of this function?
      let user_data = state as *mut _ as *mut c_void;
      let _ = state.data_loop.invoke(Some(set_timers), 0, std::ptr::null(), 0, true, user_data);

      // there are some weird PipeWire xruns on clock changes that are messing up our OSS buffer delay,
      // we'll just preemptively treat them as OSS underruns for now
      for port in &mut state.ports {
        port.xrun_timestamp = crate::utils::now_ns(&state.data_system);
        #[cfg(debug_assertions)]
        crate::warn!(state.log, "{}: clock change @ {}", port.dsp.path, port.xrun_timestamp);
      }
    }
  }

  0
}

unsafe extern "C" fn send_command(object: *mut c_void, command: *const spa_command) -> c_int {

  let state = object.cast::<State>().as_mut()
    .expect("object is not supposed to be null");

  assert!(!command.is_null());
  let body = (*command).body.body;

  #[allow(non_upper_case_globals)]
  match (body.type_, body.id) {
    (SPA_TYPE_COMMAND_Node, SPA_NODE_COMMAND_Start) => {
      for port in &mut state.ports {
        if let Some(config) = &port.config {

          port.dsp.open().unwrap();

          let format = match config.format {
            libspa::param::audio::AudioFormat::S32LE => crate::sound::AFMT_S32_LE,
            libspa::param::audio::AudioFormat::S32BE => crate::sound::AFMT_S32_BE,
            libspa::param::audio::AudioFormat::S16LE => crate::sound::AFMT_S16_LE,
            libspa::param::audio::AudioFormat::S16BE => crate::sound::AFMT_S16_BE,
            _ => unreachable!()
          };

          port.dsp.set_format(format);
          port.dsp.set_channels(config.channels);
          port.dsp.set_rate(config.rate);

          port.xrun_timestamp = 0;
        }
      }

      state.started   = true;
      state.following = state.node_is_follower();

      state.cur_timestamp = 0;
      state.old_timestamp = 0;

      let user_data = state as *mut _ as *mut c_void;
      let _ = state.data_loop.invoke(Some(set_timers), 0, std::ptr::null(), 0, true, user_data);
      0
    },
    (SPA_TYPE_COMMAND_Node, SPA_NODE_COMMAND_Suspend | SPA_NODE_COMMAND_Pause) => {
      for port in &mut state.ports {
        if !port.dsp.is_closed() {
          port.dsp.close();
        }
      }
      state.started = false;
      let user_data = state as *mut _ as *mut c_void;
      let _ = state.data_loop.invoke(Some(set_timers), 0, std::ptr::null(), 0, true, user_data);
      0
    },
    (SPA_TYPE_COMMAND_Node, SPA_NODE_COMMAND_ParamBegin | SPA_NODE_COMMAND_ParamEnd) => 0, // we don't care
    (cmd_type, cmd_id) => {
      crate::warn!(state.log, "unknown command: {}, {}", cmd_type, cmd_id);
      -libc::ENOTSUP
    }
  }
}

#[allow(unused_variables)]
unsafe extern "C" fn add_port(object: *mut c_void, direction: spa_direction, port_id: u32, props: *const spa_dict) -> c_int {
  unimplemented!()
}

#[allow(unused_variables)]
unsafe extern "C" fn remove_port(object: *mut c_void, direction: spa_direction, port_id: u32) -> c_int {
  unimplemented!()
}

//TODO: SPA_PARAM_PORT_CONFIG_MODE_none vs SPA_PARAM_PORT_CONFIG_MODE_passthrough vs SPA_PARAM_PORT_CONFIG_MODE_convert
/*unsafe fn build_port_config_info(builder: &mut libspa::pod::builder::Builder, config: &PortConfig, id: u32) -> Result<(), Errno> {

  let mut frame = MaybeUninit::<spa_pod_frame>::uninit();

  builder.push_object(&mut frame, SPA_TYPE_OBJECT_ParamPortConfig, SPA_PARAM_PortConfig)?;

  builder.add_prop(SPA_PARAM_PORT_CONFIG_direction, 0)?;
  builder.add_id(libspa::utils::Id(SPA_DIRECTION_INPUT))?;

  builder.add_prop(SPA_PARAM_PORT_CONFIG_mode, 0)?;
  builder.add_id(libspa::utils::Id(SPA_PARAM_PORT_CONFIG_MODE_none))?;

  builder.add_prop(SPA_PARAM_PORT_CONFIG_monitor, 0)?;
  builder.add_bool(false)?;

  builder.add_prop(SPA_PARAM_PORT_CONFIG_control, 0)?;
  builder.add_bool(false)?;

  builder.add_prop(SPA_PARAM_PORT_CONFIG_format, 0)?;
  build_port_format_info(builder, config, id);

  builder.pop(frame.assume_init_mut());

  Ok(())
}*/

/*unsafe fn build_port_format_info(builder: &mut libspa::pod::builder::Builder, config: &PortConfig, id: u32) {

  assert!(config.positions.len() <= 64);

  let mut position = [0u32; 64];
  for i in 0..config.positions.len() {
    position[i] = config.positions[i];
  }

  let mut raw = spa_audio_info_raw {
    format:   config.format.as_raw(),
    flags:    0,
    rate:     config.rate,
    channels: config.channels,
    position
  };

  spa_format_audio_raw_build(builder.as_raw_ptr(), id, &mut raw);
}*/

unsafe extern "C" fn port_enum_params(
  object:    *mut c_void,
  seq:       c_int,
  direction: spa_direction,
  port_id:   u32,
  id:        u32,
  start:     u32,
  max:       u32,
  filter:    *const spa_pod
) -> c_int
{
  let state = object.cast::<State>().as_mut()
    .expect("object is not supposed to be null");

  assert_eq!(direction, SPA_DIRECTION_INPUT);
  assert!((port_id as usize) < MAX_PORTS);
  assert_ne!(max, 0);

  let mut buffer = vec![];

  let mut index = start;
  let mut count = 0;

  while count < max {

    use libspa::pod::builder::Builder;

    let mut builder = Builder::new(&mut buffer);

    #[allow(non_upper_case_globals)]
    match (id, index) {
      (SPA_PARAM_EnumFormat, 0) => crate::utils::build_enum_format_info(&mut builder, false).unwrap(),
      (SPA_PARAM_EnumFormat, _) => return 0,
      (SPA_PARAM_Buffers, _)    => return 0,
      _ => return -libc::EINVAL
    };

    let mut result = spa_result_node_params { id, index, next: index + 1, param: std::ptr::null_mut() };

    if spa_pod_filter(builder.as_raw_ptr(), &mut result.param, buffer.as_mut_ptr() as *mut spa_pod, filter) >= 0 {
      crate::spa::node_emit_result(&mut state.hooks, seq, 0, SPA_RESULT_TYPE_NODE_PARAMS, &result);
      count += 1;
    }

    index += 1;
  }

  0
}

unsafe extern "C" fn port_set_param(object: *mut c_void, direction: spa_direction, port_id: u32, id: u32, _flags: u32, param: *const spa_pod) -> c_int {

  let state = object.cast::<State>().as_mut()
    .expect("object is not supposed to be null");

  assert_eq!(direction, SPA_DIRECTION_INPUT);
  assert!((port_id as usize) < MAX_PORTS);
  //assert_eq!(flags, 0);

  #[allow(non_upper_case_globals)]
  match id {
    SPA_PARAM_Format => {
      if !param.is_null() {
        use libspa::param::format::{MediaType, MediaSubtype};
        use libspa::param::format_utils::parse_format;

        match parse_format(libspa::pod::Pod::from_raw(param)) {
          Ok((MediaType::Audio, MediaSubtype::Raw)) => {
            let mut raw = MaybeUninit::<spa_audio_info_raw>::uninit();
            if spa_format_audio_raw_parse(param, raw.as_mut_ptr()) < 0 {
              crate::warn!(state.log, "spa_format_audio_raw_parse failed");
              return -libc::EINVAL;
            }

            let raw = raw.assume_init();

            //TODO: check whether format is supported by OSS
            //TODO: what should we do with flags?

            assert!(raw.rate > 0);
            assert!(raw.channels > 0 && raw.channels <= SPA_AUDIO_MAX_CHANNELS);
            assert_eq!(raw.flags, 0);

            let format    = libspa::param::audio::AudioFormat(raw.format);
            let positions = raw.position.iter().take(raw.channels as usize).copied().collect::<Vec<_>>();

            crate::info!(state.log, "requested format: {:?} (planar = {}), flags = {}, rate = {}, channels = {}, position = {:?}",
              format, format.is_planar(), raw.flags, raw.rate, raw.channels, positions);

            let config = PortConfig {
              format,
              rate:     raw.rate,
              channels: raw.channels,
              positions
            };

            state.ports[port_id as usize].config = Some(config);
          },
          Ok((t, st)) => {
            crate::warn!(state.log, "unknown media type combination: {:?}, {:?}", t, st);
            return -libc::ENOENT;
          },
          Err(err) => {
            crate::warn!(state.log, "parse_format failed: {}", err);
            return -libc::EINVAL
          }
        };
      } else {
        state.ports[port_id as usize].config = None;
      }

      //TODO: emit port info

      0
    },
    SPA_PARAM_Latency => 0,
    SPA_PARAM_Tag     => 0,
    _ => unimplemented!()
  }
}

unsafe extern "C" fn process(object: *mut c_void) -> c_int {

  let state = object.cast::<State>().as_mut()
    .expect("object is not supposed to be null");

  assert!(state.started);

  state.old_timestamp = state.cur_timestamp;
  state.cur_timestamp = crate::utils::now_ns(&state.data_system);

  let mut result = SPA_STATUS_OK as i32;

  for port in &mut state.ports {

    if port.config.is_none() {
      continue;
    }

    let port_config = port.config.as_ref().unwrap();

    assert!(!port.buffers.is_empty());
    assert!(!port.io.is_null());

    if (*port.io).status != SPA_STATUS_HAVE_DATA as i32 {
      return (*port.io).status; //TODO: or continue?
    }

    let buffer_id = (*port.io).buffer_id;
    let buffer = port.buffers.get(buffer_id as usize).unwrap().as_ref().unwrap();

    // no, I'm not the person that decided to pluralize "data" that way; it's completely savage
    assert_eq!(buffer.n_datas, 1);

    let data_0 = buffer.datas.offset(0).as_ref().unwrap();
    assert_eq!(data_0.type_, SPA_DATA_MemPtr);

    let offset = (*data_0.chunk).offset % data_0.maxsize; //TODO: should this be `(*data_0.chunk).offset.min(data_0.maxsize)` instead?
    let size   = (*data_0.chunk).size.min(data_0.maxsize - offset);

    debug_assert_eq!((*data_0.chunk).stride, port_config.stride() as i32);

    #[cfg(debug_assertions)]
    if (*state.position).clock.flags & SPA_IO_CLOCK_FLAG_XRUN_RECOVER != 0 {
      crate::warn!(state.log, "{}: SPA_IO_CLOCK_FLAG_XRUN_RECOVER @ {}", port.dsp.path, state.cur_timestamp);
    }

    #[cfg(debug_assertions)]
    if state.log.log_level() >= SPA_LOG_LEVEL_TRACE {
      crate::trace!(state.log, "offset: {}, chunk size: {}", offset, size);
      spa_debug_mem(0, data_0.data.offset(offset as isize), 16.min(size) as usize);
    }

    let driver_clock = (*state.position).clock;

    if !port.dsp.is_running() {

      let period_in_bytes       = driver_clock.target_duration as u32 * port_config.stride();
      let target_delay_in_bytes = period_in_bytes / 8 * state.oss_delay;

      port.dll.init();
      port.dll.set_bw(crate::dll::SPA_DLL_BW_MIN, period_in_bytes as u32, driver_clock.target_rate.denom * port_config.stride());

      port.dsp.set_buffer_size(period_in_bytes * 2 /* enough space to not overrun the buffer */ + target_delay_in_bytes);

      #[cfg(debug_assertions)]
      crate::warn!(state.log, "{}: writing initial {} zeroes", port.dsp.path, target_delay_in_bytes);

      // there might be a slight delay on playback start,
      // making the overall buffer delay a bit higher than expected
      port.dsp.write_zeroes(target_delay_in_bytes);
    } else {
      let underrun_count = port.dsp.underruns();
      if underrun_count > 0 {
        //TODO: spa_node_call_xrun?
        crate::warn!(state.log, "{}: OSS reported {} underruns @ {}", port.dsp.path, underrun_count, state.cur_timestamp);
        if port.xrun_timestamp == 0 {
          port.xrun_timestamp = state.cur_timestamp;
        }
      }
    }

    let nbytes = if port.xrun_timestamp != 0 {

      let period = driver_clock.target_duration * SPA_NSEC_PER_SEC as u64 / driver_clock.target_rate.denom as u64;
      let diff   = state.cur_timestamp - state.old_timestamp;

      // not sure if that does anything of value
      /*if !state.clock.is_null() {
        (*state.clock).xrun += diff;
      }*/

      // we are going to wait for the appropriate conditions to continue normal playback
      if driver_clock.nsec > port.xrun_timestamp && driver_clock.flags & SPA_IO_CLOCK_FLAG_XRUN_RECOVER == 0 &&
        diff >= period && diff < period + 1_000_000 /* ? */
      {
        port.xrun_timestamp = 0;

        let period_in_bytes       = driver_clock.target_duration as u32 * port_config.stride();
        let target_delay_in_bytes = period_in_bytes / 8 * state.oss_delay;

        port.dll.init();
        port.dll.set_bw(crate::dll::SPA_DLL_BW_MIN, period_in_bytes, driver_clock.target_rate.denom * port_config.stride());

        #[cfg(debug_assertions)]
        crate::warn!(state.log, "{}: writing {} zeroes", port.dsp.path, target_delay_in_bytes);

        port.dsp.write_zeroes(target_delay_in_bytes);
        port.dsp.write(data_0.data.offset(offset as isize), period_in_bytes)
      } else {
        #[cfg(debug_assertions)]
        crate::warn!(state.log, "{}: skipping buffer @ {}", port.dsp.path, driver_clock.nsec);

        size as isize
      }
    } else {
      // PipeWire's ALSA DLL usage is quite a bit more elaborate than this. Should we do something about it?
      if !state.rate_match.is_null() {

        let period_in_bytes       = driver_clock.target_duration as u32 * port_config.stride();
        let target_delay_in_bytes = period_in_bytes / 8 * state.oss_delay;

        let err  = (port.dsp.odelay() as isize - target_delay_in_bytes as isize) as f64;
        let corr = port.dll.update(err /*.clamp(-((period_in_bytes / 8) as f64), (period_in_bytes / 8) as f64)*/);

        #[cfg(debug_assertions)]
        eprintln!("{}: corr = {}, err = {}", port.dsp.path, corr, err);

        (*state.rate_match).rate = corr.clamp(0.99, 1.01);

        //TODO: assign state.clock.delay and state.clock.rate_diff?
      }

      port.dsp.write(data_0.data.offset(offset as isize), size)
    };

    if nbytes < size as isize {
      crate::warn!(state.log, "{}: dropped {} bytes", port.dsp.path, if nbytes > 0 { size - nbytes as u32 } else { size });
    }

    (*port.io).status = SPA_STATUS_NEED_DATA as i32;

    result |= SPA_STATUS_HAVE_DATA as i32; // those codes don't make any sense
  }

  result
}

unsafe extern "C" fn port_use_buffers(object: *mut c_void, direction: spa_direction, port_id: u32, flags: u32, buffers: *mut *mut spa_buffer, n_buffers: u32) -> c_int {

  let state = object.cast::<State>().as_mut()
    .expect("object is not supposed to be null");

  assert_eq!(direction, SPA_DIRECTION_INPUT);
  assert!((port_id as usize) < MAX_PORTS);
  assert_eq!(flags, 0);

  if !buffers.is_null() {
    assert!(n_buffers > 0);
    state.ports[port_id as usize].buffers = std::slice::from_raw_parts(buffers, n_buffers as usize).to_vec();
  } else {
    state.ports[port_id as usize].buffers = vec![];
  }

  0
}

unsafe extern "C" fn port_set_io(object: *mut c_void, direction: spa_direction, port_id: u32, id: u32, data: *mut c_void, _size: usize) -> c_int {

  assert_eq!(direction, SPA_DIRECTION_INPUT);
  assert!((port_id as usize) < MAX_PORTS);

  let state = object.cast::<State>().as_mut()
    .expect("object is not supposed to be null");

  #[allow(non_upper_case_globals)]
  match id {
    SPA_IO_Buffers => {
      state.ports[port_id as usize].io = data.cast();
      0
    },
    // you'd think that would be a node parameter instead
    SPA_IO_RateMatch => {
      let rate_match = data as *mut spa_io_rate_match;
      if !rate_match.is_null() {
        assert_eq!(MAX_PORTS, 1); // the code assumes a single port
        (*rate_match).flags |= SPA_IO_RATE_MATCH_FLAG_ACTIVE;
      }
      state.rate_match = rate_match;
      0
    },
    _ => unimplemented!()
  }
}

#[allow(unused_variables)]
unsafe extern "C" fn port_reuse_buffer(object: *mut c_void, port_id: u32, buffer_id: u32) -> c_int {
  unimplemented!()
}

const NODE_IMPL: spa_node_methods = spa_node_methods {
  version:           SPA_VERSION_NODE_METHODS,
  add_listener:      Some(add_listener),
  set_callbacks:     Some(set_callbacks),
  sync:              Some(sync),
  enum_params:       None, // Some(enum_params),
  set_param:         Some(set_param),
  set_io:            Some(set_io),
  send_command:      Some(send_command),
  add_port:          Some(add_port),
  remove_port:       Some(remove_port),
  port_enum_params:  Some(port_enum_params),
  port_set_param:    Some(port_set_param),
  port_use_buffers:  Some(port_use_buffers),
  port_set_io:       Some(port_set_io),
  port_reuse_buffer: Some(port_reuse_buffer),
  process:           Some(process),
};

unsafe extern "C" fn get_interface(handle: *mut spa_handle, type_: *const c_char, interface: *mut *mut c_void) -> c_int {
  let state = handle.cast::<State>().as_mut()
    .expect("handle is not supposed to be null");
  assert!(!interface.is_null());
  if spa_streq(type_, SPA_TYPE_INTERFACE_Node.as_ptr().cast()) {
    *interface = &mut state.node as *mut _ as *mut c_void;
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

  let data_loop   = spa_support_find(support, n_support, SPA_TYPE_INTERFACE_DataLoop  .as_ptr().cast()) as *mut spa_loop;
  let data_system = spa_support_find(support, n_support, SPA_TYPE_INTERFACE_DataSystem.as_ptr().cast()) as *mut spa_system;

  if data_loop.is_null() || data_system.is_null() {
    return -libc::EINVAL;
  }

  let data_loop   = crate::spa::Loop  ::wrap(data_loop);
  let data_system = crate::spa::System::wrap(data_system);

  let timer_fd = data_system.timerfd_create(libc::CLOCK_MONOTONIC, (SPA_FD_CLOEXEC | SPA_FD_NONBLOCK) as i32);
  assert!(timer_fd >= 0);

  let mut dsp_path = None;

  if let Some(info) = info.as_ref() {
    #[cfg(debug_assertions)]
    crate::spa::dump_spa_dict(info);

    //TODO: would be better with an iterator
    crate::spa::for_each_dict_item(info, |key, value| {
      if key == crate::keys::OSS_DSP_PATH {
        dsp_path = Some(value.to_string());
      }
    });
  }

  let dsp_path = dsp_path.unwrap();

  let state = handle.cast::<State>().as_mut()
    .expect("handle is not supposed to be null");

  std::ptr::write(state, State {

    handle: spa_handle {
      version:       SPA_VERSION_HANDLE,
      get_interface: Some(get_interface),
      clear:         Some(clear)
    },

    node: spa_node {
      iface: spa_interface {
        type_:   SPA_TYPE_INTERFACE_Node.as_ptr().cast(),
        version: SPA_VERSION_NODE,
        cb: spa_callbacks {
          funcs: &NODE_IMPL as *const _ as *const c_void,
          data:  state as *mut _ as *mut c_void
        }
      }
    },

    node_info: crate::spa::NodeInfo::new(),
    port_info: crate::spa::PortInfo::new(),

    data_loop,
    data_system,
    log,

    clock:      std::ptr::null_mut(),
    position:   std::ptr::null_mut(),
    rate_match: std::ptr::null_mut(),

    timer_source: spa_source {
      loop_: std::ptr::null_mut(),
      func:  Some(on_timeout),
      data:  state as *mut _ as *mut c_void,
      fd:    timer_fd,
      mask:  SPA_IO_IN,
      rmask: 0,
      priv_: std::ptr::null_mut()
    },

    next_time: 0,

    hooks: spa_hook_list {
      list: spa_list {
        next: std::ptr::null_mut(),
        prev: std::ptr::null_mut()
      }
    },

    callbacks: spa_callbacks {
      funcs: std::ptr::null(),
      data:  std::ptr::null_mut()
    },

    ports: [
      Port {
        config:         None,
        buffers:        vec![],
        io:             std::ptr::null_mut(),
        dsp:            crate::sound::DspWriter::new(&dsp_path),
        xrun_timestamp: 0,
        dll:            std::default::Default::default()
      };
      MAX_PORTS
    ],

    started:   false,
    following: false,

    cur_timestamp: 0,
    old_timestamp: 0,

    oss_delay: 10 // eh, whatever
  });

  state.node_info.fix_pointers();

  state.node_info.set_max_input_ports(1);
  state.node_info.set_flags(SPA_NODE_FLAG_RT as u64); // ?

  state.node_info.add_prop(SPA_KEY_MEDIA_CLASS.as_ptr(), "Audio/Sink");
  state.node_info.add_prop(SPA_KEY_NODE_DRIVER.as_ptr(), "true");

  //state.node_info.add_param(SPA_PARAM_IO,             SPA_PARAM_INFO_READ);
  //state.node_info.add_param(SPA_PARAM_EnumFormat,     SPA_PARAM_INFO_READ);
  //state.node_info.add_param(SPA_PARAM_EnumPortConfig, SPA_PARAM_INFO_READ);
  //state.node_info.add_param(SPA_PARAM_PortConfig,     SPA_PARAM_INFO_READ);
  //state.node_info.add_param(SPA_PARAM_Props,          SPA_PARAM_INFO_READWRITE);
  //state.node_info.add_param(SPA_PARAM_PropInfo,       SPA_PARAM_INFO_READ);

  state.port_info.fix_pointers();

  state.port_info.set_flags((SPA_PORT_FLAG_PHYSICAL | SPA_PORT_FLAG_TERMINAL) as u64);
  state.port_info.set_rate(spa_fraction { num: 1, denom: 48000 }); // ?

  //state.port_info.add_param(SPA_PARAM_EnumFormat, SPA_PARAM_INFO_READ);
  //state.port_info.add_param(SPA_PARAM_Format,     SPA_PARAM_INFO_READWRITE);
  //state.port_info.add_param(SPA_PARAM_PortConfig, SPA_PARAM_INFO_READWRITE);
  //state.port_info.add_param(SPA_PARAM_IO,         SPA_PARAM_INFO_READ);
  //state.port_info.add_param(SPA_PARAM_Buffers,    SPA_PARAM_INFO_WRITE); // ?

  spa_hook_list_init(&mut state.hooks);

  let err = state.data_loop.add_source(&mut state.timer_source);
  assert!(err >= 0);

  0
}

const INTERFACE_INFO: [spa_interface_info; 1] = [
  spa_interface_info {
    type_: SPA_TYPE_INTERFACE_Node.as_ptr().cast()
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

const OSS_SINK_FACTORY_INFO: spa_dict = spa_dict {
  flags:   0,
  n_items: 0,
  items:   std::ptr::null()
};

pub const OSS_SINK_FACTORY: spa_handle_factory = spa_handle_factory {
  version:             SPA_VERSION_HANDLE_FACTORY,
  name:                c"freebsd-oss.sink".as_ptr(),
  info:                &OSS_SINK_FACTORY_INFO,
  get_size:            Some(get_size),
  init:                Some(init),
  enum_interface_info: Some(enum_interface_info)
};
