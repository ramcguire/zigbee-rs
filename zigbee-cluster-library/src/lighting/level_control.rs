use crate::cluster_server::ClusterServer;
use crate::cluster_server::CommandResult;
use crate::frame::Status;
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

/// ZCL Level Control cluster (0x0008), Strategy 1.
///
/// `tick(elapsed_tenths)` advances level transitions; no timer is held inside
/// the struct. The caller supplies elapsed time in 1/10-second units.
///
/// Null `current_level` (`None`) encodes as the ZCL sentinel `0xFF`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LevelControlServer {
    /// Attribute 0x0000 — `CurrentLevel` (Uint8, nullable, null = 0xFF).
    pub current_level: Option<u8>,
    /// Attribute 0x0001 — `RemainingTime` (Uint16, in 1/10 seconds).
    pub remaining_time: u16,

    target_level: u8,
    start_level: u8,
    transition_total: u16,
}

impl LevelControlServer {
    pub const fn new(initial_level: Option<u8>) -> Self {
        let level = match initial_level {
            Some(l) => l,
            None => 0,
        };
        Self {
            current_level: initial_level,
            remaining_time: 0,
            target_level: level,
            start_level: level,
            transition_total: 0,
        }
    }

    /// Advance a running level transition by `elapsed_tenths` (1/10 seconds).
    /// No-op when no transition is in progress.
    #[allow(clippy::cast_possible_truncation)] // result bounded by start..=target (both u8)
    pub fn tick(&mut self, elapsed_tenths: u16) {
        if self.remaining_time == 0 {
            return;
        }
        let elapsed = elapsed_tenths.min(self.remaining_time);
        self.remaining_time -= elapsed;
        if self.remaining_time == 0 {
            self.current_level = Some(self.target_level);
        } else {
            // Linear interpolation in integer arithmetic.
            // remaining_time > 0 implies transition_total > 0 (invariant).
            let total = u32::from(self.transition_total);
            let done = u32::from(self.transition_total - self.remaining_time);
            let start = u32::from(self.start_level);
            let target = u32::from(self.target_level);
            let level = if target >= start {
                start + (target - start) * done / total
            } else {
                start - (start - target) * done / total
            };
            self.current_level = Some(level as u8);
        }
    }

    fn move_to_level(&mut self, level: u8, transition_tenths: u16) {
        // Null current level has no meaningful start point for interpolation;
        // snap immediately regardless of the requested transition time.
        if self.current_level.is_none() || transition_tenths == 0 {
            self.current_level = Some(level);
            self.start_level = level;
            self.target_level = level;
            self.transition_total = 0;
            self.remaining_time = 0;
            return;
        }
        let start = self.current_level.unwrap();
        self.start_level = start;
        self.target_level = level;
        self.transition_total = transition_tenths;
        self.remaining_time = transition_tenths;
    }
}

impl Default for LevelControlServer {
    fn default() -> Self {
        Self::new(None)
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
            0x0001 => Ok(encode_attr::<u16>(self.remaining_time, buf)?),
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }

    fn check_write_attribute(
        &self,
        id: AttributeId,
        _type_id: TypeId,
        _data: &[u8],
    ) -> Result<(), AttrError> {
        match id.0 {
            0x0000 | 0x0001 => Err(AttrError::ReadOnly),
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }

    fn write_attribute(
        &mut self,
        id: AttributeId,
        _type_id: TypeId,
        _data: &[u8],
    ) -> Result<(), AttrError> {
        match id.0 {
            0x0000 | 0x0001 => Err(AttrError::ReadOnly),
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }

    fn handle_command(
        &mut self,
        id: CommandId,
        payload: &[u8],
        _buf: &mut [u8],
    ) -> Result<CommandResult, ZclError> {
        match id.0 {
            // MoveToLevel (0x00) and MoveToLevelWithOnOff (0x04) share the same payload:
            // Level (u8) + TransitionTime (u16 LE, in 1/10 seconds; 0xFFFF = instant)
            0x00 | 0x04 => {
                if payload.len() < 3 {
                    return Err(ZclError::InsufficientBytes);
                }
                let level = payload[0];
                let raw_time = u16::from_le_bytes([payload[1], payload[2]]);
                // 0xFFFF = device-specific default; treat as instant for MVP
                let transition = if raw_time == 0xFFFF { 0 } else { raw_time };
                self.move_to_level(level, transition);
                Ok(CommandResult::DefaultResponse(Status::Success))
            }
            _ => Ok(CommandResult::DefaultResponse(Status::UnsupCommand)),
        }
    }

    fn attribute_list() -> &'static [AttrInfo] {
        static LIST: [AttrInfo; 2] = [
            AttrInfo {
                id: AttributeId::new(0x0000),
                type_id: TypeId::Uint8,
                access: AccessFlags::READ,
            },
            AttrInfo {
                id: AttributeId::new(0x0001),
                type_id: TypeId::Uint16,
                access: AccessFlags::READ,
            },
        ];
        &LIST
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::cluster_server::DeliveryMode;
    use crate::cluster_server::DispatchContext;
    use crate::cluster_server::zcl_cluster_dispatch;
    use crate::frame::IncomingZclFrame;
    use crate::frame::Status;

    fn unicast() -> DispatchContext {
        DispatchContext {
            delivery: DeliveryMode::Unicast,
        }
    }

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
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0001), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 0);
    }

    #[test]
    fn move_to_level_instant_sets_level_immediately() {
        let mut server = LevelControlServer::new(Some(0));
        let result = server
            .handle_command(CommandId(0x00), &[200, 0x00, 0x00], &mut [])
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::Success)
        ));
        assert_eq!(server.current_level, Some(200));
        assert_eq!(server.remaining_time, 0);
    }

    #[test]
    fn tick_advances_level_toward_target() {
        let mut server = LevelControlServer::new(Some(0));
        // MoveToLevel: target=100, transition=10 tenths
        let _ = server.handle_command(CommandId(0x00), &[100, 10, 0], &mut []);
        assert_eq!(server.remaining_time, 10);

        server.tick(5);
        assert_eq!(server.remaining_time, 5);
        // After 5/10 tenths: level ≈ 50
        assert_eq!(server.current_level, Some(50));
    }

    #[test]
    fn tick_completes_transition() {
        let mut server = LevelControlServer::new(Some(0));
        let _ = server.handle_command(CommandId(0x00), &[200, 10, 0], &mut []);

        server.tick(10);
        assert_eq!(server.remaining_time, 0);
        assert_eq!(server.current_level, Some(200));
    }

    #[test]
    fn tick_no_op_when_no_transition() {
        let mut server = LevelControlServer::new(Some(50));
        server.tick(100);
        assert_eq!(server.current_level, Some(50));
    }

    #[test]
    fn move_to_level_with_on_off_same_behavior() {
        let mut server = LevelControlServer::new(Some(0));
        let result = server
            .handle_command(CommandId(0x04), &[128, 0x00, 0x00], &mut [])
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::Success)
        ));
        assert_eq!(server.current_level, Some(128));
    }

    #[test]
    fn move_to_level_0xffff_transition_treated_as_instant() {
        let mut server = LevelControlServer::new(Some(0));
        let _ = server.handle_command(CommandId(0x00), &[75, 0xFF, 0xFF], &mut []);
        assert_eq!(server.current_level, Some(75));
        assert_eq!(server.remaining_time, 0);
    }

    #[test]
    fn move_to_level_short_payload_returns_error() {
        let mut server = LevelControlServer::new(Some(0));
        let result = server.handle_command(CommandId(0x00), &[100, 0x05], &mut []);
        assert!(result.is_err());
    }

    #[test]
    fn unknown_command_returns_unsup() {
        let mut server = LevelControlServer::new(Some(0));
        let result = server
            .handle_command(CommandId(0xFF), &[], &mut [])
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::UnsupCommand)
        ));
    }

    #[test]
    fn dispatch_move_to_level_command() {
        // cluster-specific MoveToLevel, level=150, time=20
        let req: &[u8] = &[
            0x01, 0x01, 0x00, // cluster-specific, seq=1, cmd=MoveToLevel
            150, 20, 0x00, // level=150, transition=20 tenths
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = LevelControlServer::new(Some(0));
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf).unwrap();

        assert_eq!(n, 5);
        assert_eq!(buf[4], Status::Success as u8);
        assert_eq!(server.remaining_time, 20);
    }

    #[test]
    fn level_decreases_toward_lower_target() {
        let mut server = LevelControlServer::new(Some(100));
        let _ = server.handle_command(CommandId(0x00), &[0, 10, 0], &mut []);
        server.tick(5); // halfway
        // After 5/10 tenths from 100 to 0: level = 50
        assert_eq!(server.current_level, Some(50));
    }

    #[test]
    fn move_to_level_from_null_with_transition_snaps_immediately() {
        let mut server = LevelControlServer::new(None);
        let result = server
            .handle_command(CommandId(0x00), &[100, 20, 0], &mut [])
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::Success)
        ));
        // Null start has no interpolation start point — must snap, not transition.
        assert_eq!(server.current_level, Some(100));
        assert_eq!(server.remaining_time, 0);
    }
}
