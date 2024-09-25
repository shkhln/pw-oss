#!/bin/sh
export PIPEWIRE_RUNTIME_DIR=/var/run/user/`id -u`
export XDG_RUNTIME_DIR=/var/run/user/`id -u`
exec "$@"
