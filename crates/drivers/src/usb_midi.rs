// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! USB MIDI (Musical Instrument Digital Interface) class driver.
//!
//! Implements the USB Audio Class 1.0 MIDI Streaming interface:
//!
//! - USB-MIDI Event Packet parsing and construction
//! - MIDI 1.0 status byte interpretation
//! - Virtual cable multiplexing (up to 16 virtual cables)
//! - Note On/Off, Control Change, Program Change, SysEx handling
//!
//! Reference: Universal Serial Bus Device Class Definition for MIDI Devices,
//! Release 1.0 (USB MIDI 1.0 spec); MIDI 1.0 Detailed Specification.

use oncrix_lib::{Error, Result};

// ── USB-MIDI Constants ─────────────────────────────────────────────────────

/// USB-MIDI event packet size (always 4 bytes).
pub const MIDI_PACKET_SIZE: usize = 4;
/// Maximum virtual cables per device.
pub const MAX_CABLES: usize = 16;
/// Maximum MIDI ports per driver instance.
pub const MAX_PORTS: usize = 8;
/// Maximum SysEx message length.
pub const MAX_SYSEX_LEN: usize = 256;
/// MIDI SysEx start byte.
pub const SYSEX_START: u8 = 0xF0;
/// MIDI SysEx end byte.
pub const SYSEX_END: u8 = 0xF7;

// ── MIDI Status Bytes ──────────────────────────────────────────────────────

/// MIDI channel message status bytes (high nibble).
pub mod midi_status {
    /// Note Off (channel message).
    pub const NOTE_OFF: u8 = 0x80;
    /// Note On.
    pub const NOTE_ON: u8 = 0x90;
    /// Polyphonic Key Pressure (aftertouch).
    pub const POLY_PRESSURE: u8 = 0xA0;
    /// Control Change.
    pub const CONTROL_CHANGE: u8 = 0xB0;
    /// Program Change.
    pub const PROGRAM_CHANGE: u8 = 0xC0;
    /// Channel Pressure.
    pub const CHANNEL_PRESSURE: u8 = 0xD0;
    /// Pitch Bend Change.
    pub const PITCH_BEND: u8 = 0xE0;
    /// System Exclusive start.
    pub const SYSEX: u8 = 0xF0;
    /// MIDI Time Code Quarter Frame.
    pub const TIME_CODE: u8 = 0xF1;
    /// Song Position Pointer.
    pub const SONG_POSITION: u8 = 0xF2;
    /// Song Select.
    pub const SONG_SELECT: u8 = 0xF3;
    /// Tune Request.
    pub const TUNE_REQUEST: u8 = 0xF6;
    /// SysEx End.
    pub const SYSEX_END: u8 = 0xF7;
    /// Timing Clock.
    pub const TIMING_CLOCK: u8 = 0xF8;
    /// Start.
    pub const START: u8 = 0xFA;
    /// Continue.
    pub const CONTINUE: u8 = 0xFB;
    /// Stop.
    pub const STOP: u8 = 0xFC;
    /// Active Sensing.
    pub const ACTIVE_SENSING: u8 = 0xFE;
    /// System Reset.
    pub const RESET: u8 = 0xFF;
}

// ── USB-MIDI Code Index Numbers (CIN) ─────────────────────────────────────

/// USB-MIDI Code Index Number (CIN) — identifies the packet type.
pub mod cin {
    /// Miscellaneous function codes (reserved).
    pub const MISC: u8 = 0x00;
    /// Cable events (reserved).
    pub const CABLE: u8 = 0x01;
    /// Two-byte system common.
    pub const TWO_BYTE_SYS: u8 = 0x02;
    /// Three-byte system common.
    pub const THREE_BYTE_SYS: u8 = 0x03;
    /// SysEx starts or continues.
    pub const SYSEX_START: u8 = 0x04;
    /// Single-byte system common or SysEx ends with 1 byte.
    pub const SYSEX_END_1: u8 = 0x05;
    /// SysEx ends with 2 bytes.
    pub const SYSEX_END_2: u8 = 0x06;
    /// SysEx ends with 3 bytes.
    pub const SYSEX_END_3: u8 = 0x07;
    /// Note Off.
    pub const NOTE_OFF: u8 = 0x08;
    /// Note On.
    pub const NOTE_ON: u8 = 0x09;
    /// Poly-key pressure.
    pub const POLY_KEYPRESS: u8 = 0x0A;
    /// Control Change.
    pub const CONTROL_CHANGE: u8 = 0x0B;
    /// Program Change.
    pub const PROGRAM_CHANGE: u8 = 0x0C;
    /// Channel Pressure.
    pub const CHANNEL_PRESSURE: u8 = 0x0D;
    /// Pitch Bend.
    pub const PITCH_BEND: u8 = 0x0E;
    /// Single byte.
    pub const SINGLE_BYTE: u8 = 0x0F;
}

// ── USB-MIDI Event Packet ──────────────────────────────────────────────────

/// A 4-byte USB-MIDI event packet.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MidiPacket {
    /// Byte 0: Cable number (bits 7:4) | Code Index Number (bits 3:0).
    pub header: u8,
    /// MIDI bytes 1-3 (may be padded with 0).
    pub midi: [u8; 3],
}

impl MidiPacket {
    /// Create a packet from raw bytes.
    pub fn from_bytes(b: [u8; 4]) -> Self {
        Self {
            header: b[0],
            midi: [b[1], b[2], b[3]],
        }
    }

    /// Return the Cable Number (virtual cable 0-15).
    pub fn cable(&self) -> u8 {
        self.header >> 4
    }

    /// Return the Code Index Number.
    pub fn cin(&self) -> u8 {
        self.header & 0x0F
    }

    /// Return the raw 4-byte packet.
    pub fn as_bytes(&self) -> [u8; 4] {
        [self.header, self.midi[0], self.midi[1], self.midi[2]]
    }

    /// Build a Note On packet.
    pub fn note_on(cable: u8, channel: u8, note: u8, velocity: u8) -> Self {
        Self {
            header: (cable << 4) | cin::NOTE_ON,
            midi: [
                midi_status::NOTE_ON | (channel & 0x0F),
                note & 0x7F,
                velocity & 0x7F,
            ],
        }
    }

    /// Build a Note Off packet.
    pub fn note_off(cable: u8, channel: u8, note: u8, velocity: u8) -> Self {
        Self {
            header: (cable << 4) | cin::NOTE_OFF,
            midi: [
                midi_status::NOTE_OFF | (channel & 0x0F),
                note & 0x7F,
                velocity & 0x7F,
            ],
        }
    }

    /// Build a Control Change packet.
    pub fn control_change(cable: u8, channel: u8, controller: u8, value: u8) -> Self {
        Self {
            header: (cable << 4) | cin::CONTROL_CHANGE,
            midi: [
                midi_status::CONTROL_CHANGE | (channel & 0x0F),
                controller & 0x7F,
                value & 0x7F,
            ],
        }
    }

    /// Build a Program Change packet.
    pub fn program_change(cable: u8, channel: u8, program: u8) -> Self {
        Self {
            header: (cable << 4) | cin::PROGRAM_CHANGE,
            midi: [
                midi_status::PROGRAM_CHANGE | (channel & 0x0F),
                program & 0x7F,
                0,
            ],
        }
    }

    /// Build a Pitch Bend packet (value: 0-16383, center = 8192).
    pub fn pitch_bend(cable: u8, channel: u8, value: u16) -> Self {
        let lsb = (value & 0x7F) as u8;
        let msb = ((value >> 7) & 0x7F) as u8;
        Self {
            header: (cable << 4) | cin::PITCH_BEND,
            midi: [midi_status::PITCH_BEND | (channel & 0x0F), lsb, msb],
        }
    }
}

// ── MIDI Event ─────────────────────────────────────────────────────────────

/// Parsed MIDI event (channel message).
#[derive(Clone, Copy, Debug)]
pub enum MidiEvent {
    NoteOff {
        channel: u8,
        note: u8,
        velocity: u8,
    },
    NoteOn {
        channel: u8,
        note: u8,
        velocity: u8,
    },
    ControlChange {
        channel: u8,
        controller: u8,
        value: u8,
    },
    ProgramChange {
        channel: u8,
        program: u8,
    },
    PitchBend {
        channel: u8,
        value: u16,
    },
    ChannelPressure {
        channel: u8,
        pressure: u8,
    },
    SysEx {
        len: usize,
    },
    TimingClock,
    Start,
    Stop,
    Continue,
    ActiveSensing,
    Reset,
    Other {
        status: u8,
    },
}

impl MidiEvent {
    /// Parse a MIDI packet into a typed event.
    pub fn from_packet(pkt: &MidiPacket) -> Option<Self> {
        let status = pkt.midi[0];
        let channel = status & 0x0F;
        let b1 = pkt.midi[1];
        let b2 = pkt.midi[2];
        match pkt.cin() {
            cin::NOTE_OFF => Some(Self::NoteOff {
                channel,
                note: b1,
                velocity: b2,
            }),
            cin::NOTE_ON if b2 == 0 => {
                // Note On with velocity 0 = Note Off.
                Some(Self::NoteOff {
                    channel,
                    note: b1,
                    velocity: 0,
                })
            }
            cin::NOTE_ON => Some(Self::NoteOn {
                channel,
                note: b1,
                velocity: b2,
            }),
            cin::CONTROL_CHANGE => Some(Self::ControlChange {
                channel,
                controller: b1,
                value: b2,
            }),
            cin::PROGRAM_CHANGE => Some(Self::ProgramChange {
                channel,
                program: b1,
            }),
            cin::PITCH_BEND => {
                let val = b1 as u16 | ((b2 as u16) << 7);
                Some(Self::PitchBend {
                    channel,
                    value: val,
                })
            }
            cin::CHANNEL_PRESSURE => Some(Self::ChannelPressure {
                channel,
                pressure: b1,
            }),
            cin::SINGLE_BYTE => match status {
                0xF8 => Some(Self::TimingClock),
                0xFA => Some(Self::Start),
                0xFB => Some(Self::Continue),
                0xFC => Some(Self::Stop),
                0xFE => Some(Self::ActiveSensing),
                0xFF => Some(Self::Reset),
                _ => Some(Self::Other { status }),
            },
            _ => None,
        }
    }
}

// ── Virtual Cable ──────────────────────────────────────────────────────────

/// Per-cable receive buffer.
struct CableBuffer {
    buf: [u8; MAX_SYSEX_LEN],
    len: usize,
    active: bool,
}

impl CableBuffer {
    const fn new() -> Self {
        Self {
            buf: [0u8; MAX_SYSEX_LEN],
            len: 0,
            active: false,
        }
    }
}

// ── USB MIDI Driver ────────────────────────────────────────────────────────

/// USB MIDI class driver.
pub struct UsbMidi {
    /// USB device address.
    addr: u8,
    /// Bulk IN endpoint address.
    ep_in: u8,
    /// Bulk OUT endpoint address.
    ep_out: u8,
    /// Per-cable receive buffers (for SysEx reassembly).
    cables: [CableBuffer; MAX_CABLES],
    /// Total packets received.
    rx_count: u64,
    /// Total packets transmitted.
    tx_count: u64,
}

impl UsbMidi {
    /// Create a new USB MIDI driver instance.
    pub fn new(addr: u8, ep_in: u8, ep_out: u8) -> Self {
        Self {
            addr,
            ep_in,
            ep_out,
            cables: [const { CableBuffer::new() }; MAX_CABLES],
            rx_count: 0,
            tx_count: 0,
        }
    }

    /// Process a received USB-MIDI packet.
    ///
    /// Returns a parsed event if this packet completes a MIDI message.
    pub fn receive_packet(&mut self, raw: [u8; 4]) -> Option<MidiEvent> {
        let pkt = MidiPacket::from_bytes(raw);
        let cable = pkt.cable() as usize;
        if cable >= MAX_CABLES {
            return None;
        }
        self.rx_count += 1;
        // Handle SysEx reassembly.
        match pkt.cin() {
            cin::SYSEX_START => {
                let cb = &mut self.cables[cable];
                if cb.len + 3 <= MAX_SYSEX_LEN {
                    for &b in &pkt.midi {
                        if b != 0 {
                            cb.buf[cb.len] = b;
                            cb.len += 1;
                        }
                    }
                }
                cb.active = true;
                None
            }
            cin::SYSEX_END_1 | cin::SYSEX_END_2 | cin::SYSEX_END_3 => {
                let bytes = match pkt.cin() {
                    cin::SYSEX_END_1 => 1,
                    cin::SYSEX_END_2 => 2,
                    _ => 3,
                };
                let cb = &mut self.cables[cable];
                for i in 0..bytes {
                    if cb.len < MAX_SYSEX_LEN {
                        cb.buf[cb.len] = pkt.midi[i];
                        cb.len += 1;
                    }
                }
                let len = cb.len;
                cb.len = 0;
                cb.active = false;
                Some(MidiEvent::SysEx { len })
            }
            _ => MidiEvent::from_packet(&pkt),
        }
    }

    /// Build and return a 4-byte USB-MIDI packet for transmission.
    pub fn build_packet(&mut self, event: MidiEvent) -> Result<[u8; 4]> {
        let pkt = match event {
            MidiEvent::NoteOn {
                channel,
                note,
                velocity,
            } => MidiPacket::note_on(0, channel, note, velocity),
            MidiEvent::NoteOff {
                channel,
                note,
                velocity,
            } => MidiPacket::note_off(0, channel, note, velocity),
            MidiEvent::ControlChange {
                channel,
                controller,
                value,
            } => MidiPacket::control_change(0, channel, controller, value),
            MidiEvent::ProgramChange { channel, program } => {
                MidiPacket::program_change(0, channel, program)
            }
            MidiEvent::PitchBend { channel, value } => MidiPacket::pitch_bend(0, channel, value),
            _ => return Err(Error::NotImplemented),
        };
        self.tx_count += 1;
        Ok(pkt.as_bytes())
    }

    /// Return the USB device address.
    pub fn addr(&self) -> u8 {
        self.addr
    }

    /// Return the bulk IN endpoint address.
    pub fn ep_in(&self) -> u8 {
        self.ep_in
    }

    /// Return the bulk OUT endpoint address.
    pub fn ep_out(&self) -> u8 {
        self.ep_out
    }

    /// Return total received packet count.
    pub fn rx_count(&self) -> u64 {
        self.rx_count
    }

    /// Return total transmitted packet count.
    pub fn tx_count(&self) -> u64 {
        self.tx_count
    }
}
