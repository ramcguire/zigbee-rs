use crate::cluster_server::ClusterReportReady;
use crate::cluster_server::ClusterServer;
use crate::cluster_server::ClusterTick;
use crate::cluster_server::CommandResult;
use crate::cluster_server::ConfigureReportingRecord;
use crate::cluster_server::DispatchContext;
use crate::cluster_server::ReportDeliveryResult;
use crate::cluster_server::ReportToken;
use crate::cluster_server::ReportingDiagnostics;
use crate::frame::Status;
use crate::reporting::LatestReportingTable;
use crate::reporting::ReportDue;
use crate::reporting::ReportPayloadWriter;
use crate::reporting::ReportSkip;
use crate::types::bitmaps::Bitmap8;
use crate::types::descriptors::AccessFlags;
use crate::types::descriptors::AttrInfo;
use crate::types::descriptors::encode_attr;
use crate::types::error::AttrError;
use crate::types::error::ZclError;
use crate::types::ids::AttributeId;
use crate::types::ids::ClusterId;
use crate::types::ids::CommandId;
use crate::types::ids::TypeId;
use crate::types::nullable::Nullable;

/// ZCL Level Control cluster (0x0008).
///
/// Transitions use absolute monotonic time: `transition_start_ms` and
/// `transition_duration_ms` are set when a timed move begins, and
/// `ClusterServer::tick(now_ms)` interpolates via `now_ms.wrapping_sub`.
///
/// `cached_remaining_time` (ZCL attr 0x0001, tenths of seconds) is updated on
/// each `tick` call; it is stale by at most one tick period between calls.
///
/// `take_pending_level()` returns the new level when hardware needs an update
/// (PWM, relay, etc.) and clears the dirty flag.
pub struct LevelControlServer {
    /// Attribute 0x0000 — `CurrentLevel` (Uint8, nullable, null = 0xFF).
    pub current_level: Option<u8>,
    /// Attribute 0x0002 — `MinLevel` (Uint8, R). Default 0x01.
    min_level: u8,
    /// Attribute 0x0003 — `MaxLevel` (Uint8, R). Default 0xFE.
    max_level: u8,
    /// Attribute 0x000F — `Options` (Bitmap8, R/W). Bit 0 = `ExecuteIfOff`.
    options: u8,
    /// `true` while a timed transition is in progress.
    pub moving: bool,

    /// Transition time used when a command specifies 0xFFFF ("device default"),
    /// in 1/10 s units. Defaults to 0 (instant).
    default_transition_tenths: u16,
    cached_remaining_time: u16,
    target_level: u8,
    start_level: u8,
    transition_start_ms: u32,
    transition_duration_ms: u32,
    dirty: bool,
    reporting: LatestReportingTable<1>,
}

impl LevelControlServer {
    pub const fn new(initial_level: Option<u8>) -> Self {
        let level = match initial_level {
            Some(l) => l,
            None => 0,
        };
        Self {
            current_level: initial_level,
            min_level: 0x01,
            max_level: 0xFE,
            options: 0,
            moving: false,
            default_transition_tenths: 0,
            cached_remaining_time: 0,
            target_level: level,
            start_level: level,
            transition_start_ms: 0,
            transition_duration_ms: 0,
            dirty: false,
            reporting: LatestReportingTable::new(),
        }
    }

    /// Sets the transition time (in 1/10 s units) used when a command specifies
    /// `0xFFFF` ("use device default").
    #[must_use]
    pub const fn with_default_transition(mut self, tenths: u16) -> Self {
        self.default_transition_tenths = tenths;
        self
    }

    pub fn min_level(&self) -> u8 {
        self.min_level
    }

    pub fn set_min_level(&mut self, val: u8) {
        self.min_level = val;
    }

    pub fn max_level(&self) -> u8 {
        self.max_level
    }

    pub fn set_max_level(&mut self, val: u8) {
        self.max_level = val;
    }

    pub fn options(&self) -> u8 {
        self.options
    }

    pub fn set_options(&mut self, val: u8) {
        self.options = val;
        self.reporting.note_value_update(AttributeId::new(0x000F));
    }

    /// Returns the new level when it has changed since the last call, clearing
    /// the dirty flag. Use this to drive hardware (PWM, relay, etc.).
    pub fn take_pending_level(&mut self) -> Option<u8> {
        if self.dirty {
            self.dirty = false;
            self.current_level
        } else {
            None
        }
    }

    fn move_to_level(&mut self, now_ms: u32, level: u8, transition_tenths: u16) {
        // Null start has no interpolation origin; snap regardless of transition time.
        if self.current_level.is_none() || transition_tenths == 0 {
            self.current_level = Some(level);
            self.start_level = level;
            self.target_level = level;
            self.transition_start_ms = now_ms;
            self.transition_duration_ms = 0;
            self.cached_remaining_time = 0;
            self.moving = false;
            self.dirty = true;
            self.reporting.note_value_update(AttributeId::new(0x0000));
            return;
        }
        let start = self.current_level.unwrap();
        self.start_level = start;
        self.target_level = level;
        self.transition_start_ms = now_ms;
        self.transition_duration_ms = u32::from(transition_tenths) * 100;
        self.cached_remaining_time = transition_tenths;
        self.moving = true;
        self.dirty = false;
        // note_value_update called in tick as the level interpolates
    }
}

impl Default for LevelControlServer {
    fn default() -> Self {
        Self::new(None)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LevelControlCommand {
    MoveToLevel,
    Move,
    Step,
    Stop,
    MoveToLevelWithOnOff,
    MoveWithOnOff,
    StepWithOnOff,
    StopWithOnOff,
}

impl LevelControlCommand {
    const MOVE_TO_LEVEL: CommandId = CommandId::new(0x00);
    const MOVE: CommandId = CommandId::new(0x01);
    const STEP: CommandId = CommandId::new(0x02);
    const STOP: CommandId = CommandId::new(0x03);
    const MOVE_TO_LEVEL_WITH_ON_OFF: CommandId = CommandId::new(0x04);
    const MOVE_WITH_ON_OFF: CommandId = CommandId::new(0x05);
    const STEP_WITH_ON_OFF: CommandId = CommandId::new(0x06);
    const STOP_WITH_ON_OFF: CommandId = CommandId::new(0x07);

    const IDS: [CommandId; 8] = [
        Self::MOVE_TO_LEVEL,
        Self::MOVE,
        Self::STEP,
        Self::STOP,
        Self::MOVE_TO_LEVEL_WITH_ON_OFF,
        Self::MOVE_WITH_ON_OFF,
        Self::STEP_WITH_ON_OFF,
        Self::STOP_WITH_ON_OFF,
    ];

    fn parse(id: CommandId) -> Option<Self> {
        if id == Self::MOVE_TO_LEVEL {
            Some(Self::MoveToLevel)
        } else if id == Self::MOVE {
            Some(Self::Move)
        } else if id == Self::STEP {
            Some(Self::Step)
        } else if id == Self::STOP {
            Some(Self::Stop)
        } else if id == Self::MOVE_TO_LEVEL_WITH_ON_OFF {
            Some(Self::MoveToLevelWithOnOff)
        } else if id == Self::MOVE_WITH_ON_OFF {
            Some(Self::MoveWithOnOff)
        } else if id == Self::STEP_WITH_ON_OFF {
            Some(Self::StepWithOnOff)
        } else if id == Self::STOP_WITH_ON_OFF {
            Some(Self::StopWithOnOff)
        } else {
            None
        }
    }
}

impl ClusterServer for LevelControlServer {
    const CLUSTER_ID: ClusterId = ClusterId::new(0x0008);

    fn read_attribute(
        &self,
        id: AttributeId,
        buf: &mut [u8],
    ) -> Result<(TypeId, usize), AttrError> {
        match id.0 {
            0x0000 => Ok(encode_attr::<Nullable<u8>>(self.current_level, buf)?),
            0x0001 => Ok(encode_attr::<u16>(self.cached_remaining_time, buf)?),
            0x0002 => Ok(encode_attr::<u8>(self.min_level, buf)?),
            0x0003 => Ok(encode_attr::<u8>(self.max_level, buf)?),
            0x000F => Ok(encode_attr::<Bitmap8<u8>>(self.options, buf)?),
            0xFFFD => Ok(encode_attr::<u16>(3, buf)?),
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }

    fn check_write_attribute(
        &self,
        id: AttributeId,
        type_id: TypeId,
        _data: &[u8],
    ) -> Result<(), AttrError> {
        match id.0 {
            0x000F => {
                if type_id != TypeId::Bitmap8 {
                    return Err(AttrError::InvalidDataType);
                }
                Ok(())
            }
            0x0000 | 0x0001 | 0x0002 | 0x0003 | 0xFFFD => Err(AttrError::ReadOnly),
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
                self.options = data.first().copied().ok_or(AttrError::InvalidValue)?;
                Ok(())
            }
            0x0000 | 0x0001 | 0x0002 | 0x0003 | 0xFFFD => Err(AttrError::ReadOnly),
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }

    fn handle_command(
        &mut self,
        id: CommandId,
        payload: &[u8],
        ctx: DispatchContext,
        _buf: &mut [u8],
    ) -> Result<CommandResult, ZclError> {
        match LevelControlCommand::parse(id) {
            // MoveToLevel and MoveToLevelWithOnOff: Level (u8) +
            // TransitionTime (u16 LE, 1/10 seconds; 0xFFFF = use device default)
            Some(LevelControlCommand::MoveToLevel | LevelControlCommand::MoveToLevelWithOnOff) => {
                if payload.len() < 3 {
                    return Err(ZclError::InsufficientBytes);
                }
                let level = payload[0];
                if level > 0xFE {
                    return Ok(CommandResult::DefaultResponse(Status::InvalidValue));
                }
                let level = level.clamp(self.min_level, self.max_level);
                let raw_time = u16::from_le_bytes([payload[1], payload[2]]);
                let transition = if raw_time == 0xFFFF {
                    self.default_transition_tenths
                } else {
                    raw_time
                };
                self.move_to_level(ctx.now_ms, level, transition);
                Ok(CommandResult::DefaultResponse(Status::Success))
            }
            // Move and MoveWithOnOff: MoveMode (u8), Rate (u8 units/s).
            // Moves continuously toward MinLevel (Down) or MaxLevel (Up) at the given rate.
            // Rate=0 is reserved per ZCL spec §3.10.2.3.3; reject it.
            Some(LevelControlCommand::Move | LevelControlCommand::MoveWithOnOff) => {
                if payload.len() < 2 {
                    return Err(ZclError::InsufficientBytes);
                }
                let mode = payload[0];
                let rate = payload[1];
                if rate == 0 {
                    return Ok(CommandResult::DefaultResponse(Status::InvalidValue));
                }
                let current = self.current_level.unwrap_or(self.min_level);
                let (target, distance) = match mode {
                    0x00 => {
                        let t = self.max_level;
                        (t, u32::from(t).saturating_sub(u32::from(current)))
                    }
                    0x01 => {
                        let t = self.min_level;
                        (t, u32::from(current).saturating_sub(u32::from(t)))
                    }
                    _ => return Err(ZclError::InvalidValue),
                };
                if distance > 0 {
                    #[allow(clippy::cast_possible_truncation)]
                    let tenths = (distance.saturating_mul(10) / u32::from(rate))
                        .min(u32::from(u16::MAX)) as u16;
                    self.move_to_level(ctx.now_ms, target, tenths);
                }
                Ok(CommandResult::DefaultResponse(Status::Success))
            }
            // Stop and StopWithOnOff: halt any active transition, snapping current_level
            // to the interpolated value at now_ms.
            Some(LevelControlCommand::Stop | LevelControlCommand::StopWithOnOff) => {
                if self.moving {
                    let elapsed = ctx.now_ms.wrapping_sub(self.transition_start_ms);
                    let snapped = if elapsed >= self.transition_duration_ms {
                        self.target_level
                    } else {
                        #[allow(
                            clippy::cast_possible_truncation,
                            clippy::cast_possible_wrap,
                            clippy::cast_sign_loss
                        )]
                        {
                            let delta = i16::from(self.target_level) - i16::from(self.start_level);
                            let l = i32::from(self.start_level)
                                + i32::from(delta) * elapsed as i32
                                    / self.transition_duration_ms as i32;
                            l.clamp(0, 254) as u8
                        }
                    };
                    self.current_level = Some(snapped);
                    self.target_level = snapped;
                    self.moving = false;
                    self.cached_remaining_time = 0;
                    self.dirty = true;
                    self.reporting.note_value_update(AttributeId::new(0x0000));
                }
                Ok(CommandResult::DefaultResponse(Status::Success))
            }
            // Step and StepWithOnOff: StepMode (u8), StepSize (u8),
            // TransitionTime (u16 LE, 1/10 s; 0xFFFF = use device default).
            Some(LevelControlCommand::Step | LevelControlCommand::StepWithOnOff) => {
                if payload.len() < 4 {
                    return Err(ZclError::InsufficientBytes);
                }
                let mode = payload[0];
                let size = payload[1];
                let raw_time = u16::from_le_bytes([payload[2], payload[3]]);
                let transition = if raw_time == 0xFFFF {
                    self.default_transition_tenths
                } else {
                    raw_time
                };
                let current = self.current_level.unwrap_or(self.min_level);
                let target = match mode {
                    0x00 => current.saturating_add(size).min(self.max_level),
                    0x01 => current.saturating_sub(size).max(self.min_level),
                    _ => return Err(ZclError::InvalidValue),
                };
                self.move_to_level(ctx.now_ms, target, transition);
                Ok(CommandResult::DefaultResponse(Status::Success))
            }
            None => Ok(CommandResult::DefaultResponse(Status::UnsupCommand)),
        }
    }

    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss
    )]
    fn tick(&mut self, now_ms: u32) -> ClusterTick {
        if !self.moving {
            return ClusterTick::default();
        }

        let elapsed = now_ms.wrapping_sub(self.transition_start_ms);

        if elapsed >= self.transition_duration_ms {
            let old = self.current_level;
            self.current_level = Some(self.target_level);
            self.cached_remaining_time = 0;
            self.moving = false;
            let changed = old != self.current_level;
            if changed {
                self.dirty = true;
                self.reporting.note_value_update(AttributeId::new(0x0000));
            }
            return ClusterTick {
                changed,
                next_tick_ms: None,
            };
        }

        let remaining_ms = self.transition_duration_ms - elapsed;
        self.cached_remaining_time = (remaining_ms / 100).min(u32::from(u16::MAX)) as u16;

        let delta = i16::from(self.target_level) - i16::from(self.start_level);
        let new_level = {
            let l = i32::from(self.start_level)
                + i32::from(delta) * elapsed as i32 / self.transition_duration_ms as i32;
            l.clamp(0, 254) as u8
        };

        let changed = Some(new_level) != self.current_level;
        if changed {
            self.current_level = Some(new_level);
            self.dirty = true;
            self.reporting.note_value_update(AttributeId::new(0x0000));
        }

        // Compute the exact elapsed ms when the interpolated level next increments.
        // delta_abs * elapsed fits u32: max 254 * 6_553_500 ≈ 1.66B < u32::MAX.
        let delta_abs = u32::from(self.target_level).abs_diff(u32::from(self.start_level));
        let next_tick_ms = if delta_abs == 0 {
            // Start == target: no level change until transition end.
            Some(
                self.transition_start_ms
                    .wrapping_add(self.transition_duration_ms),
            )
        } else {
            let step = delta_abs * elapsed / self.transition_duration_ms;
            // +1 ms past integer floor avoids waking fractionally early and recomputing the
            // same step.
            let wake_elapsed = (step + 1) * self.transition_duration_ms / delta_abs + 1;
            Some(self.transition_start_ms.wrapping_add(wake_elapsed))
        };

        ClusterTick {
            changed,
            next_tick_ms,
        }
    }

    fn configure_reporting(
        &mut self,
        record: ConfigureReportingRecord<'_>,
        ctx: DispatchContext,
    ) -> Status {
        self.reporting
            .configure(record, ctx, Self::attribute_list())
    }

    fn collect_reports(
        &mut self,
        now_ms: u32,
        out: &mut ReportPayloadWriter<'_>,
    ) -> Result<Option<ClusterReportReady>, ZclError> {
        let Some(candidate) = self.reporting.next_due(now_ms) else {
            return Ok(None);
        };
        let mut tmp = [0u8; 4];
        let Ok((type_id, n)) = self.read_attribute(candidate.attr_id, &mut tmp) else {
            return Ok(None);
        };
        let current = &tmp[..n];
        if candidate.due == ReportDue::Change
            && self
                .reporting
                .is_below_threshold(candidate.token, type_id, current)
        {
            self.reporting
                .skip(candidate.token, ReportSkip::BelowThreshold);
            return Ok(None);
        }
        if let Err(e) = out.write_encoded(candidate.attr_id, type_id, current) {
            if e == ZclError::BufferTooSmall {
                self.reporting
                    .skip(candidate.token, ReportSkip::BufferTooSmall);
            }
            return Err(e);
        }
        self.reporting.record_value(candidate.token, current);
        Ok(Some(ClusterReportReady {
            destination: candidate.destination,
            token: candidate.token,
        }))
    }

    fn report_delivery_result(
        &mut self,
        token: ReportToken,
        result: ReportDeliveryResult,
        now_ms: u32,
    ) {
        self.reporting.complete(token, result, now_ms);
    }

    fn take_reporting_diagnostics(&mut self) -> ReportingDiagnostics {
        self.reporting.take_diagnostics()
    }

    fn commands_received() -> &'static [CommandId] {
        static CMDS: [CommandId; 8] = LevelControlCommand::IDS;
        &CMDS
    }

    fn attribute_list() -> &'static [AttrInfo] {
        static LIST: [AttrInfo; 6] = [
            AttrInfo {
                id: AttributeId::new(0x0000),
                type_id: TypeId::Uint8,
                access: AccessFlags::READ.union(AccessFlags::REPORTABLE),
            },
            AttrInfo {
                id: AttributeId::new(0x0001),
                type_id: TypeId::Uint16,
                access: AccessFlags::READ,
            },
            AttrInfo {
                id: AttributeId::new(0x0002),
                type_id: TypeId::Uint8,
                access: AccessFlags::READ,
            },
            AttrInfo {
                id: AttributeId::new(0x0003),
                type_id: TypeId::Uint8,
                access: AccessFlags::READ,
            },
            AttrInfo {
                id: AttributeId::new(0x000F),
                type_id: TypeId::Bitmap8,
                access: AccessFlags::READ.union(AccessFlags::WRITE),
            },
            AttrInfo {
                id: AttributeId::new(0xFFFD),
                type_id: TypeId::Uint16,
                access: AccessFlags::READ,
            },
        ];
        &LIST
    }

    fn snapshot(&self, buf: &mut [u8]) -> usize {
        if buf.len() < 2 {
            return 0;
        }
        buf[0] = self.current_level.unwrap_or(0xFF);
        buf[1] = self.options;
        2
    }

    fn restore_snapshot(&mut self, buf: &[u8]) {
        if buf.len() < 2 {
            return;
        }
        self.current_level = if buf[0] == 0xFF { None } else { Some(buf[0]) };
        self.options = buf[1];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_server::ApsPeer;
    use crate::cluster_server::DeliveryMode;
    use crate::cluster_server::DispatchContext;
    use crate::cluster_server::ReportDeliveryResult;
    use crate::cluster_server::zcl_cluster_dispatch;
    use crate::frame::IncomingZclFrame;
    use crate::frame::Status;
    use crate::reporting::ReportPayloadWriter;

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

    fn send_record(min: u16, max: u16) -> ConfigureReportingRecord<'static> {
        ConfigureReportingRecord {
            direction: 0,
            attr_id: AttributeId::new(0x0000),
            attr_type: TypeId::Uint8.as_u8(),
            min_interval: min,
            max_interval: max,
            reportable_change: &[],
            timeout_period: 0,
        }
    }

    fn read_remaining(server: &LevelControlServer) -> u16 {
        let mut buf = [0u8; 4];
        let (_, n) = server
            .read_attribute(AttributeId::new(0x0001), &mut buf)
            .unwrap();
        assert_eq!(n, 2);
        u16::from_le_bytes([buf[0], buf[1]])
    }

    // --- basics ---

    #[test]
    fn current_level_null_encodes_as_0xff() {
        let server = LevelControlServer::new(None);
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint8);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0xFF);
    }

    #[test]
    fn remaining_time_initially_zero() {
        let server = LevelControlServer::new(Some(50));
        assert_eq!(read_remaining(&server), 0);
    }

    // --- instant transitions ---

    #[test]
    fn move_to_level_instant_sets_level_immediately() {
        let mut server = LevelControlServer::new(Some(0));
        let result = server
            .handle_command(CommandId(0x00), &[200, 0x00, 0x00], unicast(), &mut [])
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::Success)
        ));
        assert_eq!(server.current_level, Some(200));
        assert!(!server.moving);
    }

    #[test]
    fn move_to_level_with_on_off_same_behavior() {
        let mut server = LevelControlServer::new(Some(0));
        let result = server
            .handle_command(CommandId(0x04), &[128, 0x00, 0x00], unicast(), &mut [])
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::Success)
        ));
        assert_eq!(server.current_level, Some(128));
    }

    #[test]
    fn move_to_level_0xffff_uses_device_default_transition() {
        // Default is 0 → instant snap.
        let mut server = LevelControlServer::new(Some(0));
        let _ = server.handle_command(CommandId(0x00), &[75, 0xFF, 0xFF], unicast(), &mut []);
        assert_eq!(server.current_level, Some(75));
        assert!(!server.moving);

        // With a configured default the transition is timed, not instant.
        let mut server = LevelControlServer::new(Some(0)).with_default_transition(10);
        let _ = server.handle_command(CommandId(0x00), &[75, 0xFF, 0xFF], unicast_at(0), &mut []);
        assert_eq!(server.current_level, Some(0)); // still at start
        assert!(server.moving);
    }

    #[test]
    fn move_to_level_from_null_with_transition_snaps_immediately() {
        let mut server = LevelControlServer::new(None);
        let result = server
            .handle_command(CommandId(0x00), &[100, 20, 0], unicast(), &mut [])
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::Success)
        ));
        assert_eq!(server.current_level, Some(100));
        assert!(!server.moving);
    }

    #[test]
    fn move_to_level_short_payload_returns_error() {
        let mut server = LevelControlServer::new(Some(0));
        let result = server.handle_command(CommandId(0x00), &[100, 0x05], unicast(), &mut []);
        assert!(result.is_err());
    }

    #[test]
    fn unknown_command_returns_unsup() {
        let mut server = LevelControlServer::new(Some(0));
        let result = server
            .handle_command(CommandId(0xFF), &[], unicast(), &mut [])
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::UnsupCommand)
        ));
    }

    #[test]
    fn step_up_instant_moves_level() {
        let mut server = LevelControlServer::new(Some(50));
        let _ = server.handle_command(CommandId(0x02), &[0x00, 10, 0x00, 0x00], unicast(), &mut []);
        assert_eq!(server.current_level, Some(60));
        assert!(!server.moving);
    }

    #[test]
    fn step_down_clamped_at_min_level() {
        let mut server = LevelControlServer::new(Some(5));
        let _ = server.handle_command(CommandId(0x02), &[0x01, 50, 0x00, 0x00], unicast(), &mut []);
        assert_eq!(server.current_level, Some(1)); // clamped at default min_level (0x01)
    }

    #[test]
    fn step_up_clamped_at_254() {
        let mut server = LevelControlServer::new(Some(250));
        let _ = server.handle_command(
            CommandId(0x02),
            &[0x00, 100, 0x00, 0x00],
            unicast(),
            &mut [],
        );
        assert_eq!(server.current_level, Some(254));
    }

    #[test]
    fn move_up_starts_transition() {
        let mut server = LevelControlServer::new(Some(0));
        let _ = server.handle_command(CommandId(0x01), &[0x00, 50], unicast_at(0), &mut []);
        assert!(server.moving);
        assert_eq!(server.target_level, 254);
    }

    #[test]
    fn move_down_from_zero_is_noop() {
        let mut server = LevelControlServer::new(Some(0));
        let _ = server.handle_command(CommandId(0x01), &[0x01, 50], unicast_at(0), &mut []);
        assert!(!server.moving);
        assert_eq!(server.current_level, Some(0));
    }

    #[test]
    fn stop_halts_moving_transition() {
        let mut server = LevelControlServer::new(Some(0));
        let _ = server.handle_command(CommandId(0x00), &[200, 10, 0], unicast_at(0), &mut []);
        assert!(server.moving);

        let result = server
            .handle_command(CommandId(0x03), &[], unicast_at(500), &mut [])
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::Success)
        ));
        assert!(!server.moving);
        assert_eq!(server.current_level, Some(100)); // 50% of 0→200 at t=500ms
    }

    #[test]
    fn stop_noop_when_idle() {
        let mut server = LevelControlServer::new(Some(77));
        let result = server
            .handle_command(CommandId(0x03), &[], unicast(), &mut [])
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::Success)
        ));
        assert_eq!(server.current_level, Some(77));
        assert!(!server.moving);
    }

    #[test]
    fn all_command_ids_route_to_expected_level_control_behavior() {
        assert_eq!(
            LevelControlServer::commands_received(),
            &[
                CommandId(0x00),
                CommandId(0x01),
                CommandId(0x02),
                CommandId(0x03),
                CommandId(0x04),
                CommandId(0x05),
                CommandId(0x06),
                CommandId(0x07),
            ]
        );

        let mut server = LevelControlServer::new(Some(10));
        server
            .handle_command(CommandId(0x00), &[40, 0, 0], unicast(), &mut [])
            .unwrap();
        assert_eq!(server.current_level, Some(40));

        let mut server = LevelControlServer::new(Some(10));
        server
            .handle_command(CommandId(0x01), &[0x00, 10], unicast_at(0), &mut [])
            .unwrap();
        assert!(server.moving);
        assert_eq!(server.target_level, 0xFE);

        let mut server = LevelControlServer::new(Some(10));
        server
            .handle_command(CommandId(0x02), &[0x00, 5, 0, 0], unicast(), &mut [])
            .unwrap();
        assert_eq!(server.current_level, Some(15));

        let mut server = LevelControlServer::new(Some(10));
        server
            .handle_command(CommandId(0x00), &[110, 10, 0], unicast_at(0), &mut [])
            .unwrap();
        server
            .handle_command(CommandId(0x03), &[], unicast_at(500), &mut [])
            .unwrap();
        assert!(!server.moving);
        assert_eq!(server.current_level, Some(60));

        let mut server = LevelControlServer::new(Some(10));
        server
            .handle_command(CommandId(0x04), &[40, 0, 0], unicast(), &mut [])
            .unwrap();
        assert_eq!(server.current_level, Some(40));

        let mut server = LevelControlServer::new(Some(10));
        server
            .handle_command(CommandId(0x05), &[0x00, 10], unicast_at(0), &mut [])
            .unwrap();
        assert!(server.moving);
        assert_eq!(server.target_level, 0xFE);

        let mut server = LevelControlServer::new(Some(10));
        server
            .handle_command(CommandId(0x06), &[0x00, 5, 0, 0], unicast(), &mut [])
            .unwrap();
        assert_eq!(server.current_level, Some(15));

        let mut server = LevelControlServer::new(Some(10));
        server
            .handle_command(CommandId(0x00), &[110, 10, 0], unicast_at(0), &mut [])
            .unwrap();
        server
            .handle_command(CommandId(0x07), &[], unicast_at(500), &mut [])
            .unwrap();
        assert!(!server.moving);
        assert_eq!(server.current_level, Some(60));
    }

    // --- tick ---

    #[test]
    fn tick_noop_when_not_moving() {
        let mut server = LevelControlServer::new(Some(50));
        let ct = server.tick(100);
        assert!(!ct.changed);
        assert_eq!(ct.next_tick_ms, None);
        assert_eq!(server.current_level, Some(50));
    }

    #[test]
    fn tick_advances_level_toward_target() {
        let mut server = LevelControlServer::new(Some(0));
        // target=100, transition=10 tenths = 1000 ms
        let _ = server.handle_command(CommandId(0x00), &[100, 10, 0], unicast_at(0), &mut []);
        assert!(server.moving);

        let ct = server.tick(500);
        assert!(ct.changed);
        assert_eq!(server.current_level, Some(50));
        assert_eq!(read_remaining(&server), 5); // 500ms left = 5 tenths
    }

    #[test]
    fn tick_completes_transition() {
        let mut server = LevelControlServer::new(Some(0));
        // target=200, 10 tenths = 1000 ms
        let _ = server.handle_command(CommandId(0x00), &[200, 10, 0], unicast_at(0), &mut []);

        let ct = server.tick(1_000);
        assert!(ct.changed);
        assert_eq!(ct.next_tick_ms, None);
        assert_eq!(server.current_level, Some(200));
        assert!(!server.moving);
        assert_eq!(read_remaining(&server), 0);
    }

    #[test]
    fn tick_past_deadline_snaps_to_target() {
        let mut server = LevelControlServer::new(Some(0));
        let _ = server.handle_command(CommandId(0x00), &[200, 10, 0], unicast_at(0), &mut []);

        // Call tick well past the transition end.
        let ct = server.tick(5_000);
        assert_eq!(server.current_level, Some(200));
        assert_eq!(ct.next_tick_ms, None);
    }

    #[test]
    fn level_decreases_toward_lower_target() {
        let mut server = LevelControlServer::new(Some(100));
        // target=50, 10 tenths = 1000 ms
        let _ = server.handle_command(CommandId(0x00), &[50, 10, 0], unicast_at(0), &mut []);

        server.tick(500);
        // start=100, target=50, delta=-50; at 500ms: 100 + (-50)*500/1000 = 75
        assert_eq!(server.current_level, Some(75));
    }

    #[test]
    fn tick_returns_next_tick_ms_during_transition() {
        let mut server = LevelControlServer::new(Some(0));
        let _ = server.handle_command(CommandId(0x00), &[100, 10, 0], unicast_at(0), &mut []);

        let ct = server.tick(0);
        // next_tick_ms must be Some and in the future
        assert!(ct.next_tick_ms.is_some());
        let nxt = ct.next_tick_ms.unwrap();
        assert!(nxt.wrapping_sub(0) > 0);
    }

    #[test]
    fn tick_adaptive_cadence_exact_next_change() {
        // delta=2 (0→2), duration=10000ms: first level change at ~5000ms
        let mut server = LevelControlServer::new(Some(0));
        let _ = server.handle_command(CommandId(0x00), &[2, 100, 0], unicast_at(0), &mut []); // 100 tenths = 10000ms

        let ct = server.tick(0);
        // step=0, wake_elapsed = 1*10000/2 + 1 = 5001
        assert_eq!(ct.next_tick_ms, Some(5001));
    }

    // --- hardware dirty flag ---

    #[test]
    fn take_pending_level_returns_none_initially() {
        let mut server = LevelControlServer::new(Some(50));
        assert_eq!(server.take_pending_level(), None);
    }

    #[test]
    fn take_pending_level_set_after_instant_move() {
        let mut server = LevelControlServer::new(Some(0));
        let _ = server.handle_command(CommandId(0x00), &[100, 0, 0], unicast(), &mut []);
        assert_eq!(server.take_pending_level(), Some(100));
        assert_eq!(server.take_pending_level(), None); // cleared
    }

    #[test]
    fn take_pending_level_set_by_tick_when_level_changes() {
        let mut server = LevelControlServer::new(Some(0));
        let _ = server.handle_command(CommandId(0x00), &[100, 10, 0], unicast_at(0), &mut []);
        // No hardware update yet — level hasn't changed.
        assert_eq!(server.take_pending_level(), None);

        server.tick(500); // level → 50
        assert_eq!(server.take_pending_level(), Some(50));
        assert_eq!(server.take_pending_level(), None); // cleared
    }

    // --- reporting ---

    #[test]
    fn attribute_list_current_level_is_reportable() {
        let attrs = LevelControlServer::attribute_list();
        assert_eq!(attrs.len(), 6);
        assert_eq!(attrs[0].id, AttributeId::new(0x0000));
        assert!(attrs[0].access.is_reportable());
    }

    #[test]
    fn options_reads_initial_zero() {
        let server = LevelControlServer::new(Some(50));
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x000F), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Bitmap8);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x00);
    }

    #[test]
    fn options_write_and_read() {
        let mut server = LevelControlServer::new(Some(50));
        server
            .write_attribute(AttributeId::new(0x000F), TypeId::Bitmap8, &[0x01])
            .unwrap();
        assert_eq!(server.options, 0x01);
        let mut buf = [0u8; 4];
        let (_, n) = server
            .read_attribute(AttributeId::new(0x000F), &mut buf)
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x01);
    }

    #[test]
    fn options_write_empty_data_returns_invalid_value() {
        let mut server = LevelControlServer::new(Some(50));
        assert_eq!(
            server.write_attribute(AttributeId::new(0x000F), TypeId::Bitmap8, &[]),
            Err(AttrError::InvalidValue)
        );
    }

    #[test]
    fn min_level_max_level_default_values() {
        let server = LevelControlServer::new(Some(50));
        assert_eq!(server.min_level(), 0x01);
        assert_eq!(server.max_level(), 0xFE);
    }

    #[test]
    fn min_level_reads_as_uint8() {
        let server = LevelControlServer::new(Some(50));
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0002), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint8);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x01);
    }

    #[test]
    fn max_level_reads_as_uint8() {
        let server = LevelControlServer::new(Some(50));
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0003), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint8);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0xFE);
    }

    #[test]
    fn min_level_max_level_are_read_only() {
        let mut server = LevelControlServer::new(Some(50));
        assert_eq!(
            server.write_attribute(AttributeId::new(0x0002), TypeId::Uint8, &[0x05]),
            Err(AttrError::ReadOnly)
        );
        assert_eq!(
            server.write_attribute(AttributeId::new(0x0003), TypeId::Uint8, &[0xF0]),
            Err(AttrError::ReadOnly)
        );
    }

    #[test]
    fn set_min_max_level_affects_move_targets() {
        let mut server = LevelControlServer::new(Some(50));
        server.set_min_level(10);
        server.set_max_level(200);
        // Move Up → target is max_level
        let _ = server.handle_command(CommandId(0x01), &[0x00, 50], unicast_at(0), &mut []);
        assert_eq!(server.target_level, 200);
    }

    #[test]
    fn move_to_level_below_min_clamped() {
        let mut server = LevelControlServer::new(Some(50));
        // min_level=1, sending level=0 should clamp to 1
        let _ = server.handle_command(CommandId(0x00), &[0, 0x00, 0x00], unicast(), &mut []);
        assert_eq!(server.current_level, Some(1));
    }

    #[test]
    fn move_with_rate_zero_returns_invalid_value() {
        let mut server = LevelControlServer::new(Some(50));
        let result = server
            .handle_command(CommandId(0x01), &[0x00, 0x00], unicast(), &mut [])
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::InvalidValue)
        ));
    }

    #[test]
    fn configure_reporting_current_level_returns_success() {
        let mut server = LevelControlServer::new(Some(0));
        assert_eq!(
            server.configure_reporting(send_record(0, 60), unicast_with_source()),
            Status::Success
        );
    }

    #[test]
    fn move_to_level_instant_marks_pending_report() {
        let mut server = LevelControlServer::new(Some(0));
        server.configure_reporting(send_record(0, 60), unicast_with_source());

        server
            .handle_command(CommandId(0x00), &[128, 0x00, 0x00], unicast(), &mut [])
            .unwrap();

        let mut buf = [0u8; 32];
        let mut writer = ReportPayloadWriter::new(&mut buf);
        let ready = server.collect_reports(0, &mut writer).unwrap();
        assert!(ready.is_some());
        assert_eq!(writer.len(), 4); // attr_id(2) + type_id(1) + value(1)
        assert_eq!(buf[3], 128);
    }

    #[test]
    fn tick_marks_pending_report_mid_transition() {
        let mut server = LevelControlServer::new(Some(0));
        server.configure_reporting(send_record(0, 60), unicast_with_source());

        // Start timed transition — level not changed yet, no report pending.
        server
            .handle_command(CommandId(0x00), &[100, 10, 0], unicast_at(0), &mut [])
            .unwrap();
        let mut buf = [0u8; 32];
        assert!(
            server
                .collect_reports(0, &mut ReportPayloadWriter::new(&mut buf))
                .unwrap()
                .is_none()
        );

        // Tick to midpoint — level changes to 50, report should be pending.
        server.tick(500);
        let mut writer = ReportPayloadWriter::new(&mut buf);
        let ready = server.collect_reports(500, &mut writer).unwrap();
        assert!(ready.is_some());
        assert_eq!(buf[3], 50);
    }

    #[test]
    fn report_delivery_result_sent_clears_pending() {
        let mut server = LevelControlServer::new(Some(0));
        server.configure_reporting(send_record(0, 60), unicast_with_source());
        server
            .handle_command(CommandId(0x00), &[50, 0x00, 0x00], unicast(), &mut [])
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

    // --- dispatch ---

    #[test]
    fn dispatch_move_to_level_command() {
        let req: &[u8] = &[
            0x01, 0x01, 0x00, // cluster-specific, seq=1, cmd=MoveToLevel
            150, 20, 0x00, // level=150, transition=20 tenths = 2000 ms
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = LevelControlServer::new(Some(0));
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        assert_eq!(n, 5);
        assert_eq!(buf[4], Status::Success as u8);
        assert!(server.moving);
        assert_eq!(read_remaining(&server), 20); // 20 tenths set at transition start
    }
}
