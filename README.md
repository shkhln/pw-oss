This repo contains a very basic FreeBSD sound input/output plugin for PipeWire.
No other operating systems are supported.

## Limitations

1. The plugin is only sufficiently complete to be used with the
`node.features.audio.no-dsp=false` Wireplumber setting (which is the default).
1. There is no multichannel support (for now).
1. The author is yet to figure out how buffering works,
which means there are occassional crackling sounds.
1. No fancy features are planned at all. No bitperfect audio, etc.

## Usage

To build and run the project locally:
1. `sudo pkg install rust`
1. `git clone <this repo>`
1. `cd pw-oss`
1. `cargo build`
1. Start PipeWire with`./pipewire.sh`.
1. Start client apps with run.sh, e.g. `./run.sh pw-play whatever.wav`.

## Installation

TBD

## License

This code is *by necessity* derived and closely follows PipeWire's SPA
plugin code, which is covered by the MIT license.

There is no way to actually implement plugins independently
(in the copyright terms), while attributing each line would be
completely obnoxious, so hopefully this notice is enough.

Anything original is also subject to the MIT license.
