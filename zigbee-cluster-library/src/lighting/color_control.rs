use crate::cluster_server::ClusterServer;
use crate::cluster_server::ClusterTick;
use crate::cluster_server::CommandResult;
use crate::cluster_server::DispatchContext;
use crate::frame::Status;
use crate::reporting::LatestReportingTable;
use crate::types::bitmaps::Bitmap8;
use crate::types::bitmaps::Bitmap16;
use crate::types::descriptors::AttrInfo;
use crate::types::descriptors::encode_attr;
use crate::types::enums::ColorMode;
use crate::types::enums::Enum8;
use crate::types::enums::ZclEnum8;
use crate::types::error::AttrError;
use crate::types::error::ZclError;
use crate::types::ids::AttributeId;
use crate::types::ids::ClusterId;
use crate::types::ids::CommandId;
use crate::types::ids::TypeId;

/// Active hue transition (set when a `MoveToHue` / `MoveHue` / `StepHue`
/// command initiates movement). `take()` pattern used in `tick` avoids borrow
/// conflicts.
struct HueTransition {
    start_hue: u8,
    target_hue: u8,
    /// true = increasing hue (wrapping through 255), false = decreasing
    direction_up: bool,
    /// arc length — total hue steps to travel (0..255)
    arc: u32,
    start_ms: u32,
    duration_ms: u32,
}

/// Active saturation transition. Saturation is linear, 0–254, no wrap.
struct SatTransition {
    start_sat: u8,
    target_sat: u8,
    start_ms: u32,
    duration_ms: u32,
}

/// ZCL Color Control cluster (0x0300) — hue/saturation mode.
///
/// Transitions use absolute monotonic time. `ClusterServer::tick(now_ms)`
/// advances both axes and returns the exact next-change time (adaptive cadence,
/// never a fixed polling interval).
///
/// ZCL hue is 0x00–0xFE (modulo 255). Saturation is 0x00–0xFE, linear.
/// `Options` (0x000F) is the only writable attribute; all others are read-only.
pub struct ColorControlServer {
    /// Attribute 0x0000 — `CurrentHue` (Uint8, R|REPORTABLE, 0x00–0xFE).
    pub current_hue: u8,
    /// Attribute 0x0001 — `CurrentSaturation` (Uint8, R|REPORTABLE, 0x00–0xFE).
    pub current_saturation: u8,
    /// Attribute 0x0002 — `RemainingTime` (Uint16, R, tenths of seconds).
    remaining_time: u16,
    /// Attribute 0x0008 — `ColorMode` (Enum8, R).
    pub color_mode: ColorMode,
    /// Attribute 0x000F — `Options` (Bitmap8, R/W).
    pub options: u8,
    hue_tx: Option<HueTransition>,
    sat_tx: Option<SatTransition>,
    reporting: LatestReportingTable<2, 1>,
}

impl ColorControlServer {
    pub const fn new(hue: u8, saturation: u8) -> Self {
        Self {
            current_hue: hue,
            current_saturation: saturation,
            remaining_time: 0,
            color_mode: ColorMode::HueSaturation,
            options: 0,
            hue_tx: None,
            sat_tx: None,
            reporting: LatestReportingTable::new(),
        }
    }

    /// Returns `true` while any axis is actively transitioning.
    pub fn is_moving(&self) -> bool {
        self.hue_tx.is_some() || self.sat_tx.is_some()
    }

    fn recompute_remaining_time(&mut self, now_ms: u32) {
        let rem_hue = self.hue_tx.as_ref().map_or(0u32, |tx| {
            let elapsed = now_ms.wrapping_sub(tx.start_ms);
            tx.duration_ms.saturating_sub(elapsed) / 100
        });
        let rem_sat = self.sat_tx.as_ref().map_or(0u32, |tx| {
            let elapsed = now_ms.wrapping_sub(tx.start_ms);
            tx.duration_ms.saturating_sub(elapsed) / 100
        });
        self.remaining_time =
            u16::try_from(rem_hue.max(rem_sat).min(u32::from(u16::MAX))).unwrap_or(u16::MAX);
    }

    fn start_hue_transition(
        &mut self,
        now_ms: u32,
        target_hue: u8,
        direction: u8,
        duration_ms: u32,
    ) {
        if duration_ms == 0 {
            self.current_hue = target_hue;
            self.hue_tx = None;
            self.reporting.note_value_update(AttributeId::new(0x0000));
            self.recompute_remaining_time(now_ms);
            return;
        }
        let (direction_up, arc) = hue_direction(self.current_hue, target_hue, direction);
        self.hue_tx = Some(HueTransition {
            start_hue: self.current_hue,
            target_hue,
            direction_up,
            arc,
            start_ms: now_ms,
            duration_ms,
        });
        self.recompute_remaining_time(now_ms);
    }

    fn start_sat_transition(&mut self, now_ms: u32, target_sat: u8, duration_ms: u32) {
        if duration_ms == 0 {
            self.current_saturation = target_sat;
            self.sat_tx = None;
            self.reporting.note_value_update(AttributeId::new(0x0001));
            self.recompute_remaining_time(now_ms);
            return;
        }
        self.sat_tx = Some(SatTransition {
            start_sat: self.current_saturation,
            target_sat,
            start_ms: now_ms,
            duration_ms,
        });
        self.recompute_remaining_time(now_ms);
    }
}

impl Default for ColorControlServer {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

/// Compute (`direction_up`, `arc_length`) from start/target and ZCL direction
/// code.
///
/// ZCL direction: 0 = shortest, 1 = longest, 2 = up, 3 = down.
/// Hue wraps at 255 (valid range 0–254).
fn hue_direction(start: u8, target: u8, direction: u8) -> (bool, u32) {
    let dist_up = (u32::from(target) + 255).wrapping_sub(u32::from(start)) % 255;
    let dist_down = (u32::from(start) + 255).wrapping_sub(u32::from(target)) % 255;
    match direction {
        0x01 => {
            // longest
            if dist_up >= dist_down {
                (true, dist_up)
            } else {
                (false, dist_down)
            }
        }
        0x02 => (true, dist_up),    // up
        0x03 => (false, dist_down), // down
        _ => {
            // 0x00 shortest (default)
            if dist_up <= dist_down {
                (true, dist_up)
            } else {
                (false, dist_down)
            }
        }
    }
}

/// Interpolate hue with wrap-around. `arc` = total steps to travel (0..255).
#[allow(clippy::cast_possible_truncation)]
fn interpolate_hue(start: u8, direction_up: bool, arc: u32, elapsed: u32, duration: u32) -> u8 {
    let step = arc * elapsed / duration;
    if direction_up {
        ((u32::from(start) + step) % 255) as u8
    } else {
        ((u32::from(start) + 255 - step % 255) % 255) as u8
    }
}

/// Interpolate saturation linearly, clamped to 0–254.
#[allow(clippy::cast_possible_truncation)]
fn interpolate_linear(start: u8, target: u8, elapsed: u32, duration: u32) -> u8 {
    if target >= start {
        let delta = u32::from(target - start);
        (u32::from(start) + delta * elapsed / duration).min(254) as u8
    } else {
        let delta = u32::from(start - target);
        u32::from(start).saturating_sub(delta * elapsed / duration) as u8
    }
}

/// Return the tighter of two optional absolute timestamps.
fn tighter_deadline(a: Option<u32>, b: Option<u32>) -> Option<u32> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

impl ClusterServer for ColorControlServer {
    const CLUSTER_ID: ClusterId = ClusterId::new(0x0300);

    fn read_attribute(
        &self,
        id: AttributeId,
        buf: &mut [u8],
    ) -> Result<(TypeId, usize), AttrError> {
        match id.0 {
            0x0000 => Ok(encode_attr::<u8>(self.current_hue, buf)?),
            0x0001 => Ok(encode_attr::<u8>(self.current_saturation, buf)?),
            0x0002 => Ok(encode_attr::<u16>(self.remaining_time, buf)?),
            0x0008 => Ok(encode_attr::<Enum8<ColorMode>>(self.color_mode, buf)?),
            0x000F => Ok(encode_attr::<Bitmap8<u8>>(self.options, buf)?),
            0x400A => Ok(encode_attr::<Bitmap16<u16>>(0x0001u16, buf)?),
            0xFFFD => Ok(encode_attr::<u16>(3, buf)?),
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }

    fn check_write_attribute(
        &self,
        id: AttributeId,
        type_id: TypeId,
        data: &[u8],
    ) -> Result<(), AttrError> {
        match id.0 {
            0x000F => {
                if type_id != TypeId::Bitmap8 {
                    return Err(AttrError::InvalidDataType);
                }
                if data.len() != 1 {
                    return Err(AttrError::InvalidValue);
                }
                Ok(())
            }
            0x0000 | 0x0001 | 0x0002 | 0x0008 | 0x400A | 0xFFFD => Err(AttrError::ReadOnly),
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }

    fn write_attribute(
        &mut self,
        id: AttributeId,
        type_id: TypeId,
        data: &[u8],
    ) -> Result<(), AttrError> {
        match id.0 {
            0x000F => {
                if type_id != TypeId::Bitmap8 {
                    return Err(AttrError::InvalidDataType);
                }
                if data.len() != 1 {
                    return Err(AttrError::InvalidValue);
                }
                self.options = data[0];
                Ok(())
            }
            0x0000 | 0x0001 | 0x0002 | 0x0008 | 0x400A | 0xFFFD => Err(AttrError::ReadOnly),
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }

    #[allow(clippy::cast_possible_truncation, clippy::too_many_lines)]
    fn handle_command(
        &mut self,
        id: CommandId,
        payload: &[u8],
        ctx: DispatchContext,
        _buf: &mut [u8],
    ) -> Result<CommandResult, ZclError> {
        match id.0 {
            // MoveToHue: Hue(u8) + Direction(u8) + TransitionTime(u16 in 1/10 s)
            0x00 => {
                if payload.len() < 4 {
                    return Err(ZclError::InsufficientBytes);
                }
                let hue = payload[0].min(254);
                let direction = payload[1];
                let raw_time = u16::from_le_bytes([payload[2], payload[3]]);
                if direction > 0x03 {
                    return Ok(CommandResult::DefaultResponse(Status::InvalidField));
                }
                let duration_ms = if raw_time == 0xFFFF {
                    0
                } else {
                    u32::from(raw_time) * 100
                };
                self.color_mode = ColorMode::HueSaturation;
                self.start_hue_transition(ctx.now_ms, hue, direction, duration_ms);
                Ok(CommandResult::DefaultResponse(Status::Success))
            }
            // MoveHue: MoveMode(u8) + Rate(u8 hue/s)
            0x01 => {
                if payload.len() < 2 {
                    return Err(ZclError::InsufficientBytes);
                }
                let mode = payload[0];
                let rate = payload[1];
                if mode > 0x02 {
                    return Ok(CommandResult::DefaultResponse(Status::InvalidField));
                }
                self.color_mode = ColorMode::HueSaturation;
                if mode == 0x00 || rate == 0 {
                    // Stop
                    self.hue_tx = None;
                    self.recompute_remaining_time(ctx.now_ms);
                    return Ok(CommandResult::DefaultResponse(Status::Success));
                }
                let direction_up = mode == 0x01;
                let start = self.current_hue;
                // Model as one full revolution at the given rate.
                // duration = 254 steps / rate (steps/s) * 1000 ms/s
                let duration_ms = 254_u32 * 1000 / u32::from(rate);
                let arc = 254_u32;
                let target = if direction_up {
                    ((u32::from(start) + 254) % 255) as u8
                } else {
                    ((u32::from(start) + 1) % 255) as u8
                };
                self.hue_tx = Some(HueTransition {
                    start_hue: start,
                    target_hue: target,
                    direction_up,
                    arc,
                    start_ms: ctx.now_ms,
                    duration_ms,
                });
                self.recompute_remaining_time(ctx.now_ms);
                Ok(CommandResult::DefaultResponse(Status::Success))
            }
            // StepHue: StepMode(u8) + StepSize(u8) + TransitionTime(u8 in 1/10 s)
            0x02 => {
                if payload.len() < 3 {
                    return Err(ZclError::InsufficientBytes);
                }
                let mode = payload[0];
                let step_size = payload[1];
                let raw_time = payload[2];
                if !matches!(mode, 0x01 | 0x02) {
                    return Ok(CommandResult::DefaultResponse(Status::InvalidField));
                }
                let duration_ms = u32::from(raw_time) * 100;
                self.color_mode = ColorMode::HueSaturation;
                let direction_up = mode == 0x01;
                let target = if direction_up {
                    ((u32::from(self.current_hue) + u32::from(step_size)) % 255) as u8
                } else {
                    ((u32::from(self.current_hue) + 255 - u32::from(step_size) % 255) % 255) as u8
                };
                self.start_hue_transition(
                    ctx.now_ms,
                    target,
                    if direction_up { 0x02 } else { 0x03 },
                    duration_ms,
                );
                Ok(CommandResult::DefaultResponse(Status::Success))
            }
            // MoveToSaturation: Saturation(u8) + TransitionTime(u16 in 1/10 s)
            0x03 => {
                if payload.len() < 3 {
                    return Err(ZclError::InsufficientBytes);
                }
                let sat = payload[0].min(254);
                let raw_time = u16::from_le_bytes([payload[1], payload[2]]);
                let duration_ms = if raw_time == 0xFFFF {
                    0
                } else {
                    u32::from(raw_time) * 100
                };
                self.color_mode = ColorMode::HueSaturation;
                self.start_sat_transition(ctx.now_ms, sat, duration_ms);
                Ok(CommandResult::DefaultResponse(Status::Success))
            }
            // MoveSaturation: MoveMode(u8) + Rate(u8 sat/s)
            0x04 => {
                if payload.len() < 2 {
                    return Err(ZclError::InsufficientBytes);
                }
                let mode = payload[0];
                let rate = payload[1];
                if mode > 0x02 {
                    return Ok(CommandResult::DefaultResponse(Status::InvalidField));
                }
                self.color_mode = ColorMode::HueSaturation;
                if mode == 0x00 || rate == 0 {
                    self.sat_tx = None;
                    self.recompute_remaining_time(ctx.now_ms);
                    return Ok(CommandResult::DefaultResponse(Status::Success));
                }
                let go_up = mode == 0x01;
                let start = self.current_saturation;
                let (target, steps) = if go_up {
                    let t = 254u8;
                    (t, u32::from(254 - start))
                } else {
                    let t = 0u8;
                    (t, u32::from(start))
                };
                if steps == 0 {
                    return Ok(CommandResult::DefaultResponse(Status::Success));
                }
                let duration_ms = steps * 1000 / u32::from(rate);
                self.sat_tx = Some(SatTransition {
                    start_sat: start,
                    target_sat: target,
                    start_ms: ctx.now_ms,
                    duration_ms,
                });
                self.recompute_remaining_time(ctx.now_ms);
                Ok(CommandResult::DefaultResponse(Status::Success))
            }
            // StepSaturation: StepMode(u8) + StepSize(u8) + TransitionTime(u8 in 1/10 s)
            0x05 => {
                if payload.len() < 3 {
                    return Err(ZclError::InsufficientBytes);
                }
                let mode = payload[0];
                let step_size = payload[1];
                let raw_time = payload[2];
                if !matches!(mode, 0x01 | 0x02) {
                    return Ok(CommandResult::DefaultResponse(Status::InvalidField));
                }
                let duration_ms = u32::from(raw_time) * 100;
                self.color_mode = ColorMode::HueSaturation;
                let go_up = mode == 0x01;
                let target = if go_up {
                    (u32::from(self.current_saturation) + u32::from(step_size)).min(254) as u8
                } else {
                    u32::from(self.current_saturation).saturating_sub(u32::from(step_size)) as u8
                };
                self.start_sat_transition(ctx.now_ms, target, duration_ms);
                Ok(CommandResult::DefaultResponse(Status::Success))
            }
            // MoveToHueAndSaturation: Hue(u8) + Saturation(u8) + TransitionTime(u16 in 1/10 s)
            0x06 => {
                if payload.len() < 4 {
                    return Err(ZclError::InsufficientBytes);
                }
                let hue = payload[0].min(254);
                let sat = payload[1].min(254);
                let raw_time = u16::from_le_bytes([payload[2], payload[3]]);
                let duration_ms = if raw_time == 0xFFFF {
                    0
                } else {
                    u32::from(raw_time) * 100
                };
                self.color_mode = ColorMode::HueSaturation;
                self.start_hue_transition(ctx.now_ms, hue, 0x00, duration_ms);
                self.start_sat_transition(ctx.now_ms, sat, duration_ms);
                Ok(CommandResult::DefaultResponse(Status::Success))
            }
            _ => Ok(CommandResult::DefaultResponse(Status::UnsupCommand)),
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    fn tick(&mut self, now_ms: u32) -> ClusterTick {
        let mut changed = false;
        let mut next_ms: Option<u32> = None;

        // --- hue axis ---
        if let Some(tx) = self.hue_tx.take() {
            let elapsed = now_ms.wrapping_sub(tx.start_ms);
            if elapsed >= tx.duration_ms {
                let old = self.current_hue;
                self.current_hue = tx.target_hue;
                if self.current_hue != old {
                    changed = true;
                    self.reporting.note_value_update(AttributeId::new(0x0000));
                }
                // hue_tx remains None (taken above, not put back)
            } else {
                let new_hue = interpolate_hue(
                    tx.start_hue,
                    tx.direction_up,
                    tx.arc,
                    elapsed,
                    tx.duration_ms,
                );
                if new_hue != self.current_hue {
                    self.current_hue = new_hue;
                    changed = true;
                    self.reporting.note_value_update(AttributeId::new(0x0000));
                }
                // Adaptive cadence: exact time of next integer hue step.
                let next_hue_ms = if tx.arc == 0 {
                    tx.start_ms.wrapping_add(tx.duration_ms)
                } else {
                    let step = tx.arc * elapsed / tx.duration_ms;
                    let wake_elapsed = (step + 1) * tx.duration_ms / tx.arc + 1;
                    tx.start_ms.wrapping_add(wake_elapsed)
                };
                next_ms = tighter_deadline(next_ms, Some(next_hue_ms));
                self.hue_tx = Some(tx);
            }
        }

        // --- saturation axis ---
        if let Some(tx) = self.sat_tx.take() {
            let elapsed = now_ms.wrapping_sub(tx.start_ms);
            if elapsed >= tx.duration_ms {
                let old = self.current_saturation;
                self.current_saturation = tx.target_sat;
                if self.current_saturation != old {
                    changed = true;
                    self.reporting.note_value_update(AttributeId::new(0x0001));
                }
                // sat_tx remains None
            } else {
                let new_sat =
                    interpolate_linear(tx.start_sat, tx.target_sat, elapsed, tx.duration_ms);
                if new_sat != self.current_saturation {
                    self.current_saturation = new_sat;
                    changed = true;
                    self.reporting.note_value_update(AttributeId::new(0x0001));
                }
                // Adaptive cadence: exact time of next integer saturation step.
                let delta_abs = u32::from(tx.target_sat).abs_diff(u32::from(tx.start_sat));
                let next_sat_ms = if delta_abs == 0 {
                    tx.start_ms.wrapping_add(tx.duration_ms)
                } else {
                    let step = delta_abs * elapsed / tx.duration_ms;
                    let wake_elapsed = (step + 1) * tx.duration_ms / delta_abs + 1;
                    tx.start_ms.wrapping_add(wake_elapsed)
                };
                next_ms = tighter_deadline(next_ms, Some(next_sat_ms));
                self.sat_tx = Some(tx);
            }
        }

        self.recompute_remaining_time(now_ms);

        ClusterTick {
            changed,
            next_tick_ms: next_ms,
        }
    }

    impl_reporting!(reporting, 1);

    fn attribute_list() -> &'static [AttrInfo] {
        attr_list![
            (0x0000, Uint8, READ | REPORTABLE),
            (0x0001, Uint8, READ | REPORTABLE),
            (0x0002, Uint16, READ),
            (0x0008, Enum8, READ),
            (0x000F, Bitmap8, READ | WRITE),
            (0x400A, Bitmap16, READ),
            (0xFFFD, Uint16, READ),
        ]
    }

    fn snapshot(&self, buf: &mut [u8]) -> usize {
        if buf.len() < 4 {
            return 0;
        }
        buf[0] = self.current_hue;
        buf[1] = self.current_saturation;
        buf[2] = self.color_mode.into_raw();
        buf[3] = self.options;
        4
    }

    fn restore_snapshot(&mut self, buf: &[u8]) {
        if buf.len() < 4 {
            return;
        }
        self.current_hue = buf[0];
        self.current_saturation = buf[1];
        if let Ok(cm) = ColorMode::from_raw(buf[2]) {
            self.color_mode = cm;
        }
        self.options = buf[3];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_server::ApsPeer;
    use crate::cluster_server::ConfigureReportingRecord;
    use crate::cluster_server::DeliveryMode;
    use crate::cluster_server::DispatchContext;
    use crate::cluster_server::ReportDeliveryResult;
    use crate::cluster_server::zcl_cluster_dispatch;
    use crate::frame::IncomingZclFrame;
    use crate::frame::Status;
    use crate::reporting::ReportPayloadWriter;
    use crate::types::enums::ZclEnum8;

    fn unicast_at(now_ms: u32) -> DispatchContext {
        DispatchContext::unicast(now_ms, None)
    }

    fn unicast() -> DispatchContext {
        unicast_at(0)
    }

    fn unicast_with_source() -> DispatchContext {
        DispatchContext {
            delivery: DeliveryMode::Unicast,
            now_ms: 0,
            source: Some(ApsPeer {
                short_addr: 0x1234,
                endpoint: 1,
            }),
        }
    }

    fn send_record(
        attr_id: u16,
        attr_type: u8,
        min: u16,
        max: u16,
    ) -> ConfigureReportingRecord<'static> {
        ConfigureReportingRecord {
            direction: 0,
            attr_id: AttributeId::new(attr_id),
            attr_type,
            min_interval: min,
            max_interval: max,
            reportable_change: &[],
            timeout_period: 0,
        }
    }

    fn read_remaining(server: &ColorControlServer) -> u16 {
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0002), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint16);
        assert_eq!(n, 2);
        u16::from_le_bytes([buf[0], buf[1]])
    }

    // --- attribute reads ---

    #[test]
    fn initial_hue_and_saturation_readable() {
        let server = ColorControlServer::new(128, 200);
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint8);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 128);

        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0001), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint8);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 200);
    }

    #[test]
    fn color_mode_encodes_as_enum8() {
        let server = ColorControlServer::default();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0008), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Enum8);
        assert_eq!(n, 1);
        assert_eq!(buf[0], ColorMode::HueSaturation.into_raw());
    }

    #[test]
    fn options_encodes_as_bitmap8() {
        let server = ColorControlServer {
            options: 0x03,
            ..ColorControlServer::default()
        };
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x000F), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Bitmap8);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x03);
    }

    #[test]
    fn write_options_succeeds() {
        let mut server = ColorControlServer::default();
        assert!(
            server
                .write_attribute(AttributeId::new(0x000F), TypeId::Bitmap8, &[0x01])
                .is_ok()
        );
        assert_eq!(server.options, 0x01);
    }

    #[test]
    fn options_write_validates_type_and_exact_length() {
        let mut server = ColorControlServer::default();
        assert_eq!(
            server.check_write_attribute(AttributeId::new(0x000F), TypeId::Uint8, &[0x01]),
            Err(AttrError::InvalidDataType)
        );
        assert_eq!(
            server.write_attribute(AttributeId::new(0x000F), TypeId::Uint8, &[0x01]),
            Err(AttrError::InvalidDataType)
        );
        assert_eq!(
            server.check_write_attribute(AttributeId::new(0x000F), TypeId::Bitmap8, &[]),
            Err(AttrError::InvalidValue)
        );
        assert_eq!(
            server.write_attribute(AttributeId::new(0x000F), TypeId::Bitmap8, &[0x01, 0x02]),
            Err(AttrError::InvalidValue)
        );
        assert_eq!(server.options, 0);
    }

    #[test]
    fn write_readonly_attrs_returns_error() {
        let mut server = ColorControlServer::default();
        for attr in [0x0000u16, 0x0001, 0x0002, 0x0008, 0x400A, 0xFFFD] {
            assert_eq!(
                server.write_attribute(AttributeId::new(attr), TypeId::Uint8, &[0x00]),
                Err(AttrError::ReadOnly)
            );
        }
    }

    #[test]
    fn write_unknown_attr_returns_unsupported() {
        let mut server = ColorControlServer::default();
        assert_eq!(
            server.write_attribute(AttributeId::new(0xFFFF), TypeId::Uint8, &[0x00]),
            Err(AttrError::UnsupportedAttribute)
        );
    }

    #[test]
    fn attribute_list_has_correct_entries() {
        let attrs = ColorControlServer::attribute_list();
        assert_eq!(attrs.len(), 7);
        assert!(attrs[0].access.is_reportable()); // hue
        assert!(attrs[1].access.is_reportable()); // saturation
    }

    #[test]
    fn color_capabilities_reads_hs_only_bit() {
        let server = ColorControlServer::default();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x400A), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Bitmap16);
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 0x0001);
    }

    #[test]
    fn cluster_revision_reads_zcl_rev8_value() {
        let server = ColorControlServer::default();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0xFFFD), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 3);
    }

    // --- tick: no-op when idle ---

    #[test]
    fn tick_noop_when_idle() {
        let mut server = ColorControlServer::new(100, 200);
        let ct = server.tick(1000);
        assert!(!ct.changed);
        assert_eq!(ct.next_tick_ms, None);
        assert_eq!(server.current_hue, 100);
        assert_eq!(server.current_saturation, 200);
    }

    // --- MoveToHue ---

    #[test]
    fn move_to_hue_instant_sets_immediately() {
        let mut server = ColorControlServer::new(0, 0);
        // cmd=0x00, hue=100, direction=0x00 (shortest), time=0x0000 (instant)
        let payload = &[100u8, 0x00, 0x00, 0x00];
        let result = server
            .handle_command(CommandId(0x00), payload, unicast(), &mut [])
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::Success)
        ));
        assert_eq!(server.current_hue, 100);
        assert!(!server.is_moving());
    }

    #[test]
    fn move_to_hue_timed_starts_transition() {
        let mut server = ColorControlServer::new(0, 0);
        // target=100, time=10 tenths = 1000ms
        let payload = &[100u8, 0x00, 10, 0x00];
        server
            .handle_command(CommandId(0x00), payload, unicast_at(0), &mut [])
            .unwrap();
        assert!(server.is_moving());
        assert_eq!(server.current_hue, 0); // not yet moved
    }

    #[test]
    fn tick_advances_hue_midpoint() {
        let mut server = ColorControlServer::new(0, 0);
        // 0 → 100 going up (shortest), 1000ms
        let payload = &[100u8, 0x02, 10, 0x00]; // direction=up
        server
            .handle_command(CommandId(0x00), payload, unicast_at(0), &mut [])
            .unwrap();

        let ct = server.tick(500);
        assert!(ct.changed);
        assert!(server.current_hue > 0 && server.current_hue < 100);
    }

    #[test]
    fn tick_completes_hue_transition() {
        let mut server = ColorControlServer::new(0, 0);
        let payload = &[200u8, 0x02, 10, 0x00]; // up, 1000ms
        server
            .handle_command(CommandId(0x00), payload, unicast_at(0), &mut [])
            .unwrap();

        let ct = server.tick(1000);
        assert_eq!(server.current_hue, 200);
        assert!(!server.is_moving());
        assert_eq!(ct.next_tick_ms, None);
    }

    #[test]
    fn tick_adaptive_cadence_hue_exact_next_change() {
        // delta=2 (0→2), duration=10000ms: exact next change at step=1 → elapsed =
        // 1*10000/2 + 1 = 5001
        let mut server = ColorControlServer::new(0, 0);
        let payload = &[2u8, 0x02, 100, 0x00]; // up, 10000ms
        server
            .handle_command(CommandId(0x00), payload, unicast_at(0), &mut [])
            .unwrap();

        let ct = server.tick(0);
        assert_eq!(ct.next_tick_ms, Some(5001));
    }

    // --- MoveToSaturation ---

    #[test]
    fn move_to_saturation_instant() {
        let mut server = ColorControlServer::new(0, 0);
        let payload = &[200u8, 0x00, 0x00];
        server
            .handle_command(CommandId(0x03), payload, unicast(), &mut [])
            .unwrap();
        assert_eq!(server.current_saturation, 200);
        assert!(!server.is_moving());
    }

    #[test]
    fn tick_advances_saturation() {
        let mut server = ColorControlServer::new(0, 0);
        // 0 → 100, 1000ms
        let payload = &[100u8, 10, 0x00];
        server
            .handle_command(CommandId(0x03), payload, unicast_at(0), &mut [])
            .unwrap();

        server.tick(500);
        assert_eq!(server.current_saturation, 50);
    }

    #[test]
    fn tick_completes_saturation_transition() {
        let mut server = ColorControlServer::new(0, 0);
        let payload = &[200u8, 10, 0x00]; // 1000ms
        server
            .handle_command(CommandId(0x03), payload, unicast_at(0), &mut [])
            .unwrap();

        let ct = server.tick(1000);
        assert_eq!(server.current_saturation, 200);
        assert!(!server.is_moving());
        assert_eq!(ct.next_tick_ms, None);
    }

    #[test]
    fn tick_adaptive_cadence_saturation_exact_next_change() {
        // delta=2 (0→2), duration=10000ms → next change at 5001
        let mut server = ColorControlServer::new(0, 0);
        let payload = &[2u8, 100, 0x00]; // 10000ms
        server
            .handle_command(CommandId(0x03), payload, unicast_at(0), &mut [])
            .unwrap();

        let ct = server.tick(0);
        assert_eq!(ct.next_tick_ms, Some(5001));
    }

    // --- MoveToHueAndSaturation ---

    #[test]
    fn move_to_hue_and_saturation_instant() {
        let mut server = ColorControlServer::new(0, 0);
        // hue=100, sat=200, time=0
        let payload = &[100u8, 200, 0x00, 0x00];
        server
            .handle_command(CommandId(0x06), payload, unicast(), &mut [])
            .unwrap();
        assert_eq!(server.current_hue, 100);
        assert_eq!(server.current_saturation, 200);
        assert!(!server.is_moving());
    }

    #[test]
    fn move_to_hue_and_saturation_timed_both_axes_active() {
        let mut server = ColorControlServer::new(0, 0);
        // hue=100, sat=200, time=10 tenths = 1000ms
        let payload = &[100u8, 200, 10, 0x00];
        server
            .handle_command(CommandId(0x06), payload, unicast_at(0), &mut [])
            .unwrap();
        assert!(server.hue_tx.is_some());
        assert!(server.sat_tx.is_some());
    }

    #[test]
    fn tick_returns_tighter_deadline_for_dual_axis() {
        // hue: delta=100 in 10000ms, sat: delta=200 in 10000ms
        // sat has larger delta → tighter cadence (smaller next_tick gap)
        let mut server = ColorControlServer::new(0, 0);
        let payload = &[100u8, 200, 100, 0x00]; // 10000ms
        server
            .handle_command(CommandId(0x06), payload, unicast_at(0), &mut [])
            .unwrap();

        let ct = server.tick(0);
        assert!(ct.next_tick_ms.is_some());
        // sat cadence = 10000/200 + 1 = 51ms, hue cadence = 10000/100 + 1 = 101ms →
        // tighter = 51
        assert_eq!(ct.next_tick_ms, Some(51));
    }

    // --- remaining_time ---

    #[test]
    fn remaining_time_decreases_as_transition_progresses() {
        let mut server = ColorControlServer::new(0, 0);
        // 1000ms = 10 tenths
        let payload = &[200u8, 0x02, 10, 0x00];
        server
            .handle_command(CommandId(0x00), payload, unicast_at(0), &mut [])
            .unwrap();

        server.tick(500); // 500ms elapsed → 500ms remaining = 5 tenths
        assert_eq!(read_remaining(&server), 5);
    }

    #[test]
    fn remaining_time_is_fresh_immediately_after_start_stop_and_instant() {
        let mut server = ColorControlServer::new(0, 0);
        server
            .handle_command(
                CommandId(0x00),
                &[200, 0x02, 10, 0x00],
                unicast_at(100),
                &mut [],
            )
            .unwrap();
        assert_eq!(read_remaining(&server), 10);

        server
            .handle_command(CommandId(0x01), &[0x00, 0], unicast_at(100), &mut [])
            .unwrap();
        assert_eq!(read_remaining(&server), 0);

        server
            .handle_command(CommandId(0x03), &[100, 10, 0x00], unicast_at(200), &mut [])
            .unwrap();
        assert_eq!(read_remaining(&server), 10);

        server
            .handle_command(CommandId(0x03), &[50, 0, 0], unicast_at(200), &mut [])
            .unwrap();
        assert_eq!(read_remaining(&server), 0);
    }

    // --- MoveHue ---

    #[test]
    fn move_hue_stop_mode_clears_transition() {
        let mut server = ColorControlServer::new(50, 0);
        // First start a move
        server
            .handle_command(CommandId(0x01), &[0x01, 10], unicast_at(0), &mut [])
            .unwrap();
        assert!(server.hue_tx.is_some());
        // Then stop
        server
            .handle_command(CommandId(0x01), &[0x00, 0], unicast(), &mut [])
            .unwrap();
        assert!(server.hue_tx.is_none());
    }

    #[test]
    fn move_hue_up_starts_transition() {
        let mut server = ColorControlServer::new(50, 0);
        server
            .handle_command(CommandId(0x01), &[0x01, 10], unicast_at(0), &mut [])
            .unwrap();
        assert!(server.hue_tx.is_some());
        let tx = server.hue_tx.as_ref().unwrap();
        assert!(tx.direction_up);
    }

    #[test]
    fn invalid_hue_modes_return_invalid_field_without_mutation() {
        let mut server = ColorControlServer::new(50, 100);
        server.color_mode = ColorMode::XY;

        for (id, payload) in [
            (0x00, &[60, 0x04, 10, 0][..]),
            (0x01, &[0x03, 10][..]),
            (0x02, &[0x00, 20, 10][..]),
            (0x02, &[0x03, 20, 10][..]),
        ] {
            let result = server
                .handle_command(CommandId(id), payload, unicast_at(0), &mut [])
                .unwrap();
            assert!(matches!(
                result,
                CommandResult::DefaultResponse(Status::InvalidField)
            ));
            assert_eq!(server.current_hue, 50);
            assert_eq!(server.current_saturation, 100);
            assert_eq!(server.color_mode, ColorMode::XY);
            assert!(!server.is_moving());
            assert_eq!(read_remaining(&server), 0);
        }
    }

    // --- StepHue ---

    #[test]
    fn step_hue_up_moves_toward_target() {
        let mut server = ColorControlServer::new(100, 0);
        // mode=up, step=20, time=10 tenths = 1000ms
        server
            .handle_command(CommandId(0x02), &[0x01, 20, 10], unicast_at(0), &mut [])
            .unwrap();
        assert!(server.hue_tx.is_some());
        let tx = server.hue_tx.as_ref().unwrap();
        assert_eq!(tx.target_hue, 120);
    }

    // --- StepSaturation ---

    #[test]
    fn step_saturation_down_moves_toward_target() {
        let mut server = ColorControlServer::new(0, 200);
        // mode=down, step=50, time=10 tenths = 1000ms
        server
            .handle_command(CommandId(0x05), &[0x02, 50, 10], unicast_at(0), &mut [])
            .unwrap();
        assert!(server.sat_tx.is_some());
        let tx = server.sat_tx.as_ref().unwrap();
        assert_eq!(tx.target_sat, 150); // 200 - 50
    }

    // --- MoveSaturation ---

    #[test]
    fn move_saturation_stop_clears_transition() {
        let mut server = ColorControlServer::new(0, 100);
        server
            .handle_command(CommandId(0x04), &[0x01, 10], unicast_at(0), &mut [])
            .unwrap();
        assert!(server.sat_tx.is_some());
        server
            .handle_command(CommandId(0x04), &[0x00, 0], unicast(), &mut [])
            .unwrap();
        assert!(server.sat_tx.is_none());
    }

    #[test]
    fn invalid_saturation_modes_return_invalid_field_without_mutation() {
        let mut server = ColorControlServer::new(50, 100);
        server.color_mode = ColorMode::XY;

        for (id, payload) in [
            (0x04, &[0x03, 10][..]),
            (0x05, &[0x00, 20, 10][..]),
            (0x05, &[0x03, 20, 10][..]),
        ] {
            let result = server
                .handle_command(CommandId(id), payload, unicast_at(0), &mut [])
                .unwrap();
            assert!(matches!(
                result,
                CommandResult::DefaultResponse(Status::InvalidField)
            ));
            assert_eq!(server.current_hue, 50);
            assert_eq!(server.current_saturation, 100);
            assert_eq!(server.color_mode, ColorMode::XY);
            assert!(!server.is_moving());
            assert_eq!(read_remaining(&server), 0);
        }
    }

    // --- error cases ---

    #[test]
    fn move_to_hue_short_payload_returns_error() {
        let mut server = ColorControlServer::default();
        assert!(
            server
                .handle_command(CommandId(0x00), &[100, 0x00], unicast(), &mut [])
                .is_err()
        );
    }

    #[test]
    fn unknown_command_returns_unsup() {
        let mut server = ColorControlServer::default();
        let result = server
            .handle_command(CommandId(0xFF), &[], unicast(), &mut [])
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::UnsupCommand)
        ));
    }

    // --- dispatch integration ---

    #[test]
    fn dispatch_read_current_hue() {
        let req: &[u8] = &[0x00, 0x01, 0x00, 0x00, 0x00]; // ReadAttributes, seq=1, attr=0x0000
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = ColorControlServer::new(77, 0);
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + attr_id(2) + status(1) + type_id(1) + value(1) = 8
        assert_eq!(n, 8);
        assert_eq!(buf[5], 0x00); // Success
        assert_eq!(buf[6], TypeId::Uint8.as_u8());
        assert_eq!(buf[7], 77);
    }

    // --- reporting ---

    #[test]
    fn configure_reporting_hue_returns_success() {
        let mut server = ColorControlServer::default();
        let record = send_record(0x0000, TypeId::Uint8.as_u8(), 0, 30);
        assert_eq!(
            server.configure_reporting(record, unicast_with_source()),
            Status::Success
        );
    }

    #[test]
    fn configure_reporting_saturation_returns_success() {
        let mut server = ColorControlServer::default();
        let record = send_record(0x0001, TypeId::Uint8.as_u8(), 0, 30);
        assert_eq!(
            server.configure_reporting(record, unicast_with_source()),
            Status::Success
        );
    }

    #[test]
    fn collect_reports_after_instant_move_to_hue() {
        let mut server = ColorControlServer::new(0, 0);
        let record = send_record(0x0000, TypeId::Uint8.as_u8(), 0, 30);
        server.configure_reporting(record, unicast_with_source());

        server
            .handle_command(
                CommandId(0x00),
                &[150, 0x00, 0x00, 0x00],
                unicast(),
                &mut [],
            )
            .unwrap();

        let mut buf = [0u8; 32];
        let mut writer = ReportPayloadWriter::new(&mut buf);
        let ready = server.collect_reports(0, &mut writer).unwrap();
        assert!(ready.is_some());
        // attr_id(2) + type_id(1) + value(1) = 4 bytes
        assert_eq!(writer.len(), 4);
        assert_eq!(buf[3], 150);
    }

    #[test]
    fn report_delivery_result_sent_clears_pending() {
        let mut server = ColorControlServer::new(0, 0);
        let record = send_record(0x0000, TypeId::Uint8.as_u8(), 0, 30);
        server.configure_reporting(record, unicast_with_source());
        server
            .handle_command(
                CommandId(0x00),
                &[100, 0x00, 0x00, 0x00],
                unicast(),
                &mut [],
            )
            .unwrap();

        let mut buf = [0u8; 32];
        let mut writer = ReportPayloadWriter::new(&mut buf);
        let ready = server
            .collect_reports(0, &mut writer)
            .unwrap()
            .expect("pending report");

        server.report_delivery_result(ready.token, ReportDeliveryResult::Sent, 1_000);

        let mut writer = ReportPayloadWriter::new(&mut buf);
        assert!(
            server
                .collect_reports(1_000, &mut writer)
                .unwrap()
                .is_none()
        );
    }

    // --- hue_direction helper ---

    #[test]
    fn hue_direction_shortest_up_when_closer() {
        let (up, arc) = hue_direction(0, 100, 0x00);
        assert!(up);
        assert_eq!(arc, 100);
    }

    #[test]
    fn hue_direction_shortest_down_when_closer() {
        let (up, arc) = hue_direction(100, 0, 0x00);
        assert!(!up);
        assert_eq!(arc, 100);
    }

    #[test]
    fn hue_direction_wrap_up_crossing_zero() {
        // Start=250, target=5, shortest is up: 250→254→0→5 = 10 steps
        let (up, arc) = hue_direction(250, 5, 0x00);
        assert!(up);
        assert_eq!(arc, 10);
    }

    #[test]
    fn hue_direction_wrap_down_when_shorter() {
        // Start=5, target=250, shortest is down: 5→0→254→250 = 10 steps
        let (up, arc) = hue_direction(5, 250, 0x00);
        assert!(!up);
        assert_eq!(arc, 10);
    }

    #[test]
    fn interpolate_hue_wraps_through_zero() {
        // From 250 going up with arc=10 over 1000ms, at 500ms → step=5 → (250+5)%255 =
        // 0
        let hue = interpolate_hue(250, true, 10, 500, 1000);
        assert_eq!(hue, 0);
    }
}
