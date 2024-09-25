log = Log.open_topic("s-monitors")

function createNode(parent, id, obj_type, factory, properties)
  -- supposedly mandatory props
  properties["device.id"]    = parent["bound-id"]
  properties["factory.name"] = factory
  -- monitors/alsa.lua does this, so...
  properties["node.pause-on-idle"] = false

  local node = Node("adapter", properties)
  node:activate(Feature.Proxy.BOUND | Feature.PipewireObject.PARAM_FORMAT | Feature.PipewireObject.PARAM_PORT_CONFIG)
  parent:store_managed_object(id, node)
end

function createDevice(parent, id, obj_type, factory, properties)
  local device = SpaDevice(factory, properties)
  if device then
    device:connect("create-object", createNode)
    device:activate(Feature.SpaDevice.ENABLED | Feature.Proxy.BOUND)
    parent:store_managed_object(id, device)
  else
    log:warning("Failed to create " .. factory)
  end
end

function createMonitor()
  local monitor = SpaDevice("freebsd-oss.monitor", {})
  if monitor then
    monitor:connect("create-object", createDevice)
    monitor:activate(Feature.SpaDevice.ENABLED)
  else
    log:notice("No sound for you")
  end
  return monitor
end

monitor = createMonitor()
