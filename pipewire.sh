#!/bin/sh
script_dir="$(dirname $(realpath "$0"))"
export SPA_PLUGIN_DIR="$script_dir/target/debug:/usr/local/lib/spa-0.2"
export XDG_CONFIG_HOME="$script_dir/conf"
export XDG_DATA_HOME="$script_dir/share"
$script_dir/run.sh pipewire "$@"
