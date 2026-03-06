// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Force feedback (FF) input device subsystem.
//!
//! Implements the Linux-compatible force feedback API for input devices
//! that have rumble motors, periodic actuators, or other haptic outputs.
//!
//! # Effect types
//!
//! | Type | Description |
//! |------|-------------|
//! | Rumble | Left/right motor magnitudes |
//! | Periodic | Waveform (sine, square, etc.) with frequency/amplitude |
//! | Constant | Constant force in a direction |
//! | Spring | Restoring force proportional to offset |
//! | Friction | Resistance proportional to velocity |
//! | Damper | Velocity-dampening force |
//! | Inertia | Acceleration-opposing force |

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of simultaneously active FF effects per device.
const MAX_EFFECTS: usize = 16;

/// Default gain (full scale).
const DEFAULT_GAIN: u16 = 0xFFFF;

// ── FfEffectType ─────────────────────────────────────────────────────────────

/// Force feedback effect type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfEffectType {
    /// Dual-motor rumble (left/right motors).
    Rumble,
    /// Periodic waveform (sine, square, triangle, sawtooth).
    Periodic,
    /// Constant force in one direction.
    Constant,
    /// Restoring spring force (toward centre).
    Spring,
    /// Friction (velocity-proportional resistance).
    Friction,
    /// Damper (velocity-opposing force).
    Damper,
    /// Inertia (acceleration-opposing force).
    Inertia,
}

// ── FfReplay ─────────────────────────────────────────────────────────────────

/// Playback timing for an FF effect.
#[derive(Debug, Clone, Copy, Default)]
pub struct FfReplay {
    /// Effect duration in milliseconds (0 = forever).
    pub length_ms: u16,
    /// Delay before playback starts (milliseconds).
    pub delay_ms: u16,
}

// ── FfRumble ─────────────────────────────────────────────────────────────────

/// Rumble effect parameters.
#[derive(Debug, Clone, Copy, Default)]
pub struct FfRumble {
    /// Left (strong) motor magnitude (0–0xFFFF).
    pub strong_magnitude: u16,
    /// Right (weak) motor magnitude (0–0xFFFF).
    pub weak_magnitude: u16,
}

// ── FfWaveform ───────────────────────────────────────────────────────────────

/// Waveform shape for periodic effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfWaveform {
    /// Sine wave.
    Sine,
    /// Square wave.
    Square,
    /// Triangle wave.
    Triangle,
    /// Sawtooth up.
    SawUp,
    /// Sawtooth down.
    SawDown,
    /// Custom waveform (device-specific).
    Custom,
}

// ── FfPeriodic ───────────────────────────────────────────────────────────────

/// Periodic effect parameters.
#[derive(Debug, Clone, Copy, Default)]
pub struct FfPeriodic {
    /// Waveform type.
    pub waveform: Option<FfWaveform>,
    /// Period in milliseconds.
    pub period_ms: u16,
    /// Peak magnitude (0–0x7FFF).
    pub magnitude: i16,
    /// Mean offset (signed, shifts the waveform).
    pub offset: i16,
    /// Phase offset in degrees (0–359).
    pub phase: u16,
    /// Attack time in ms.
    pub attack_length_ms: u16,
    /// Attack level.
    pub attack_level: u16,
    /// Fade time in ms.
    pub fade_length_ms: u16,
    /// Fade level.
    pub fade_level: u16,
}

// ── FfConstant ───────────────────────────────────────────────────────────────

/// Constant force effect.
#[derive(Debug, Clone, Copy, Default)]
pub struct FfConstant {
    /// Force level (signed, -0x7FFF – 0x7FFF).
    pub level: i16,
    /// Attack/fade envelope timing.
    pub attack_length_ms: u16,
    /// Attack level.
    pub attack_level: u16,
    /// Fade length in ms.
    pub fade_length_ms: u16,
    /// Fade level.
    pub fade_level: u16,
}

// ── FfCondition ──────────────────────────────────────────────────────────────

/// Condition-based effect (spring/friction/damper/inertia).
#[derive(Debug, Clone, Copy, Default)]
pub struct FfCondition {
    /// Right saturation.
    pub right_saturation: u16,
    /// Left saturation.
    pub left_saturation: u16,
    /// Right coefficient.
    pub right_coeff: i16,
    /// Left coefficient.
    pub left_coeff: i16,
    /// Dead band around centre.
    pub deadband: u16,
    /// Centre point offset.
    pub centre: i16,
}

// ── FfEffectData ─────────────────────────────────────────────────────────────

/// Effect-type-specific parameters.
#[derive(Debug, Clone, Copy)]
pub enum FfEffectData {
    /// Rumble motor parameters.
    Rumble(FfRumble),
    /// Periodic waveform parameters.
    Periodic(FfPeriodic),
    /// Constant force parameters.
    Constant(FfConstant),
    /// Condition (spring/friction/damper/inertia) parameters.
    Condition(FfCondition),
}

// ── FfEffect ─────────────────────────────────────────────────────────────────

/// A complete force feedback effect.
#[derive(Debug, Clone, Copy)]
pub struct FfEffect {
    /// Effect type.
    pub effect_type: FfEffectType,
    /// Assigned effect ID (–1 = unassigned).
    pub id: i16,
    /// Playback timing.
    pub replay: FfReplay,
    /// Effect-specific data.
    pub data: FfEffectData,
    /// Whether this effect is currently playing.
    pub playing: bool,
    /// Remaining play count (0 = play once, 0xFFFF = infinite).
    pub play_count: u16,
}

impl FfEffect {
    /// Create a new rumble effect.
    pub const fn new_rumble(strong: u16, weak: u16, length_ms: u16) -> Self {
        Self {
            effect_type: FfEffectType::Rumble,
            id: -1,
            replay: FfReplay {
                length_ms,
                delay_ms: 0,
            },
            data: FfEffectData::Rumble(FfRumble {
                strong_magnitude: strong,
                weak_magnitude: weak,
            }),
            playing: false,
            play_count: 1,
        }
    }
}

// ── FfDevice ─────────────────────────────────────────────────────────────────

/// Force feedback device.
pub struct FfDevice {
    /// Maximum number of effects supported by the hardware.
    pub max_effects: usize,
    /// Global gain (0–0xFFFF); scales all effect outputs.
    pub gain: u16,
    /// Autocenter strength (0 = disabled).
    pub autocenter: u16,
    /// Effect slots.
    effects: [Option<FfEffect>; MAX_EFFECTS],
    /// Effect upload callback (called when an effect is uploaded).
    pub upload_cb: Option<fn(effect: &FfEffect) -> Result<()>>,
    /// Effect erase callback.
    pub erase_cb: Option<fn(effect_id: i16) -> Result<()>>,
    /// Effect start/stop callback.
    pub playback_cb: Option<fn(effect_id: i16, playing: bool) -> Result<()>>,
    /// Gain change callback.
    pub set_gain_cb: Option<fn(gain: u16)>,
    /// Autocenter change callback.
    pub set_autocenter_cb: Option<fn(strength: u16)>,
}

impl FfDevice {
    /// Create a new force feedback device.
    pub const fn new(max_effects: usize) -> Self {
        Self {
            max_effects,
            gain: DEFAULT_GAIN,
            autocenter: 0,
            effects: [const { None }; MAX_EFFECTS],
            upload_cb: None,
            erase_cb: None,
            playback_cb: None,
            set_gain_cb: None,
            set_autocenter_cb: None,
        }
    }

    /// Upload a new effect.
    ///
    /// Allocates an effect slot, assigns an ID, and calls `upload_cb`.
    /// Returns the assigned effect ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no slots remain.
    pub fn upload(&mut self, mut effect: FfEffect) -> Result<i16> {
        let slot = self.find_free_slot().ok_or(Error::OutOfMemory)?;
        let id = slot as i16;
        effect.id = id;

        if let Some(cb) = self.upload_cb {
            cb(&effect)?;
        }

        self.effects[slot] = Some(effect);
        Ok(id)
    }

    /// Erase (remove) an effect by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no effect with that ID exists.
    pub fn erase(&mut self, effect_id: i16) -> Result<()> {
        let slot = self.find_slot(effect_id).ok_or(Error::NotFound)?;

        if let Some(Some(eff)) = self.effects.get(slot) {
            if eff.playing {
                // Stop before erasing.
                if let Some(cb) = self.playback_cb {
                    let _ = cb(effect_id, false);
                }
            }
        }

        if let Some(cb) = self.erase_cb {
            cb(effect_id)?;
        }

        self.effects[slot] = None;
        Ok(())
    }

    /// Start or stop playback of an effect.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the effect ID is unknown.
    pub fn playback(&mut self, effect_id: i16, playing: bool) -> Result<()> {
        let slot = self.find_slot(effect_id).ok_or(Error::NotFound)?;
        if let Some(cb) = self.playback_cb {
            cb(effect_id, playing)?;
        }
        if let Some(Some(eff)) = self.effects.get_mut(slot) {
            eff.playing = playing;
        }
        Ok(())
    }

    /// Set the global gain.
    pub fn set_gain(&mut self, gain: u16) {
        self.gain = gain;
        if let Some(cb) = self.set_gain_cb {
            cb(gain);
        }
    }

    /// Set the autocenter strength.
    pub fn set_autocenter(&mut self, strength: u16) {
        self.autocenter = strength;
        if let Some(cb) = self.set_autocenter_cb {
            cb(strength);
        }
    }

    /// Return a reference to an effect by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not found.
    pub fn get_effect(&self, effect_id: i16) -> Result<&FfEffect> {
        let slot = self.find_slot(effect_id).ok_or(Error::NotFound)?;
        self.effects[slot].as_ref().ok_or(Error::NotFound)
    }

    /// Return the number of effects currently uploaded.
    pub fn effect_count(&self) -> usize {
        self.effects.iter().filter(|e| e.is_some()).count()
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn find_free_slot(&self) -> Option<usize> {
        self.effects.iter().position(|e| e.is_none())
    }

    fn find_slot(&self, id: i16) -> Option<usize> {
        self.effects
            .iter()
            .position(|e| e.as_ref().map_or(false, |eff| eff.id == id))
    }
}
