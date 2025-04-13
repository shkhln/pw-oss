// This code was borrowed from PipeWire's spa/include/spa/utils/dll.h that has the following header:

/* Simple DLL */
/* SPDX-FileCopyrightText: Copyright © 2019 Wim Taymans */
/* SPDX-License-Identifier: MIT */

pub const SPA_DLL_BW_MAX: f64 = 0.128;
pub const SPA_DLL_BW_MIN: f64 = 0.016;

#[derive(Default)]
pub struct SpaDLL {
  bw: f64,
  z1: f64,
  z2: f64,
  z3: f64,
  w0: f64,
  w1: f64,
  w2: f64
}

impl SpaDLL {

  #[inline(always)]
  pub fn init(&mut self) {
    self.bw = 0.0;
    self.z1 = 0.0;
    self.z2 = 0.0;
    self.z3 = 0.0;
  }

  #[inline(always)]
  pub fn set_bw(&mut self, bw: f64, period: u32, rate: u32) {
    let w = 2.0 * std::f64::consts::PI * bw * period as f64 / rate as f64;
    self.w0 = 1.0 - (-20.0 * w).exp();
    self.w1 = w * 1.5 / period as f64;
    self.w2 = w / 1.5;
    self.bw = bw;
  }

  #[inline(always)]
  pub fn update(&mut self, err: f64) -> f64 {
    self.z1 += self.w0 * (self.w1 * err - self.z1);
    self.z2 += self.w0 * (self.z1 - self.z2);
    self.z3 += self.w2 * self.z2;
    1.0 - (self.z2 + self.z3)
  }
}
