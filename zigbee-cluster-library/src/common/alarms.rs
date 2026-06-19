use heapless::Vec;

use crate::cluster_server::ClusterServer;
use crate::cluster_server::CommandResult;
use crate::cluster_server::DispatchContext;
use crate::frame::Status;
use crate::types::descriptors::AttrInfo;
use crate::types::descriptors::encode_attr;
use crate::types::error::AttrError;
use crate::types::error::ZclError;
use crate::types::ids::AttributeId;
use crate::types::ids::ClusterId;
use crate::types::ids::CommandId;
use crate::types::ids::TypeId;

/// One entry in the alarm log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlarmEntry {
    pub cluster_id: u16,
    pub alarm_code: u8,
}

/// ZCL Alarms cluster (0x0009).
///
/// `N` is the maximum number of alarms retained in the log. When the log is
/// full and a new alarm is added, the oldest entry is dropped.
pub struct AlarmsServer<const N: usize> {
    alarms: Vec<AlarmEntry, N>,
}

impl<const N: usize> AlarmsServer<N> {
    pub const fn new() -> Self {
        Self { alarms: Vec::new() }
    }

    /// Add an alarm to the log. Drops the oldest entry if the log is full.
    pub fn add_alarm(&mut self, entry: AlarmEntry) {
        if self.alarms.is_full() && !self.alarms.is_empty() {
            self.alarms.remove(0);
        }
        let _ = self.alarms.push(entry);
    }

    pub fn alarm_count(&self) -> u16 {
        u16::try_from(self.alarms.len()).unwrap_or(u16::MAX)
    }

    pub fn alarms(&self) -> &[AlarmEntry] {
        &self.alarms
    }

    pub fn is_empty(&self) -> bool {
        self.alarms.is_empty()
    }
}

impl<const N: usize> Default for AlarmsServer<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ClusterServer for AlarmsServer<N> {
    const CLUSTER_ID: ClusterId = ClusterId::new(0x0009);

    fn read_attribute(
        &self,
        id: AttributeId,
        buf: &mut [u8],
    ) -> Result<(TypeId, usize), AttrError> {
        match id.0 {
            0x0000 => Ok(encode_attr::<u16>(
                u16::try_from(self.alarms.len()).unwrap_or(u16::MAX),
                buf,
            )?),
            0xFFFD => Ok(encode_attr::<u16>(1, buf)?),
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }

    fn handle_command(
        &mut self,
        id: CommandId,
        payload: &[u8],
        _ctx: DispatchContext,
        buf: &mut [u8],
    ) -> Result<CommandResult, ZclError> {
        match id.0 {
            // ResetAlarm: alarm_code(1), cluster_id(2)
            0x00 => {
                if payload.len() < 3 {
                    return Err(ZclError::InsufficientBytes);
                }
                let alarm_code = payload[0];
                let cluster_id = u16::from_le_bytes([payload[1], payload[2]]);
                let pos = self
                    .alarms
                    .iter()
                    .position(|e| e.cluster_id == cluster_id && e.alarm_code == alarm_code);
                match pos {
                    Some(i) => {
                        self.alarms.remove(i);
                        Ok(CommandResult::DefaultResponse(Status::Success))
                    }
                    None => Ok(CommandResult::DefaultResponse(Status::NotFound)),
                }
            }
            // ResetAllAlarms / ResetAlarmLog — identical effect
            0x01 | 0x03 => {
                self.alarms.clear();
                Ok(CommandResult::DefaultResponse(Status::Success))
            }
            // GetAlarm: no payload; responds with GetAlarmResponse (cmd 0x01 s→c)
            0x02 => {
                if self.alarms.is_empty() {
                    if buf.is_empty() {
                        return Err(ZclError::BufferTooSmall);
                    }
                    buf[0] = Status::NotFound as u8;
                    Ok(CommandResult::Payload {
                        command_id: CommandId::new(0x01),
                        len: 1,
                    })
                } else {
                    if buf.len() < 8 {
                        return Err(ZclError::BufferTooSmall);
                    }
                    let entry = self.alarms.remove(0);
                    buf[0] = Status::Success as u8;
                    buf[1] = entry.alarm_code;
                    buf[2] = (entry.cluster_id & 0xFF) as u8;
                    buf[3] = (entry.cluster_id >> 8) as u8;
                    // timestamp not tracked; write 0
                    buf[4] = 0;
                    buf[5] = 0;
                    buf[6] = 0;
                    buf[7] = 0;
                    Ok(CommandResult::Payload {
                        command_id: CommandId::new(0x01),
                        len: 8,
                    })
                }
            }
            _ => Ok(CommandResult::DefaultResponse(Status::UnsupCommand)),
        }
    }

    fn commands_received() -> &'static [CommandId] {
        static CMDS: [CommandId; 4] = [
            CommandId::new(0x00),
            CommandId::new(0x01),
            CommandId::new(0x02),
            CommandId::new(0x03),
        ];
        &CMDS
    }

    read_only_attrs![0x0000 | 0xFFFD];

    fn attribute_list() -> &'static [AttrInfo] {
        attr_list![(0x0000, Uint16, READ), (0xFFFD, Uint16, READ),]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_server::DispatchContext;
    use crate::cluster_server::zcl_cluster_dispatch;
    use crate::frame::IncomingZclFrame;

    fn unicast() -> DispatchContext {
        DispatchContext::unicast(0, None)
    }

    fn entry(cluster_id: u16, alarm_code: u8) -> AlarmEntry {
        AlarmEntry {
            cluster_id,
            alarm_code,
        }
    }

    // --- AlarmCount attribute ---

    #[test]
    fn alarm_count_zero_initially() {
        let server = AlarmsServer::<4>::new();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 0);
    }

    #[test]
    fn alarm_count_after_add() {
        let mut server = AlarmsServer::<4>::new();
        server.add_alarm(entry(0x0402, 0x01));
        server.add_alarm(entry(0x0201, 0x02));
        let mut buf = [0u8; 4];
        let (_, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 2);
    }

    #[test]
    fn unknown_attribute_returns_unsupported() {
        let server = AlarmsServer::<4>::new();
        let mut buf = [0u8; 4];
        assert_eq!(
            server.read_attribute(AttributeId::new(0xFFFF), &mut buf),
            Err(AttrError::UnsupportedAttribute)
        );
    }

    #[test]
    fn write_alarm_count_returns_read_only() {
        let mut server = AlarmsServer::<4>::new();
        assert_eq!(
            server.write_attribute(AttributeId::new(0x0000), TypeId::Uint16, &[0x00, 0x00]),
            Err(AttrError::ReadOnly)
        );
    }

    #[test]
    fn cluster_revision_reads_rev8_value_and_is_read_only() {
        let mut server = AlarmsServer::<4>::new();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0xFFFD), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 1);
        assert_eq!(
            server.write_attribute(AttributeId::new(0xFFFD), TypeId::Uint16, &[1, 0]),
            Err(AttrError::ReadOnly)
        );
    }

    // --- add_alarm capacity ---

    #[test]
    fn add_alarm_drops_oldest_when_full() {
        let mut server = AlarmsServer::<2>::new();
        server.add_alarm(entry(0x0001, 0x01)); // oldest
        server.add_alarm(entry(0x0002, 0x02));
        server.add_alarm(entry(0x0003, 0x03)); // newest; 0x0001 should be dropped
        assert_eq!(server.alarm_count(), 2);
        let alarms = server.alarms();
        assert_eq!(alarms[0], entry(0x0002, 0x02));
        assert_eq!(alarms[1], entry(0x0003, 0x03));
    }

    // --- ResetAlarm (0x00) ---

    #[test]
    fn reset_alarm_removes_matching_entry() {
        let mut server = AlarmsServer::<4>::new();
        server.add_alarm(entry(0x0402, 0x01));
        server.add_alarm(entry(0x0201, 0x02));
        let payload = [0x01u8, 0x02, 0x04]; // alarm_code=1, cluster_id=0x0402
        let mut buf = [0u8; 32];
        let result = server.handle_command(CommandId::new(0x00), &payload, unicast(), &mut buf);
        assert!(matches!(
            result,
            Ok(CommandResult::DefaultResponse(Status::Success))
        ));
        assert_eq!(server.alarm_count(), 1);
        assert_eq!(server.alarms()[0], entry(0x0201, 0x02));
    }

    #[test]
    fn reset_alarm_returns_not_found_when_no_match() {
        let mut server = AlarmsServer::<4>::new();
        server.add_alarm(entry(0x0402, 0x01));
        let payload = [0x02u8, 0x02, 0x04]; // alarm_code=2 not present
        let mut buf = [0u8; 32];
        let result = server.handle_command(CommandId::new(0x00), &payload, unicast(), &mut buf);
        assert!(matches!(
            result,
            Ok(CommandResult::DefaultResponse(Status::NotFound))
        ));
        assert_eq!(server.alarm_count(), 1);
    }

    #[test]
    fn reset_alarm_short_payload_returns_error() {
        let mut server = AlarmsServer::<4>::new();
        let payload = [0x01u8, 0x02]; // only 2 bytes, need 3
        let mut buf = [0u8; 32];
        assert!(matches!(
            server.handle_command(CommandId::new(0x00), &payload, unicast(), &mut buf),
            Err(ZclError::InsufficientBytes)
        ));
    }

    // --- ResetAllAlarms (0x01) ---

    #[test]
    fn reset_all_alarms_clears_log() {
        let mut server = AlarmsServer::<4>::new();
        server.add_alarm(entry(0x0402, 0x01));
        server.add_alarm(entry(0x0201, 0x02));
        let mut buf = [0u8; 32];
        let result = server.handle_command(CommandId::new(0x01), &[], unicast(), &mut buf);
        assert!(matches!(
            result,
            Ok(CommandResult::DefaultResponse(Status::Success))
        ));
        assert_eq!(server.alarm_count(), 0);
    }

    // --- GetAlarm (0x02) ---

    #[test]
    fn get_alarm_empty_returns_not_found() {
        let mut server = AlarmsServer::<4>::new();
        let mut buf = [0u8; 32];
        let result = server
            .handle_command(CommandId::new(0x02), &[], unicast(), &mut buf)
            .unwrap();
        assert!(
            matches!(result, CommandResult::Payload { command_id, len: 1 } if command_id.0 == 0x01)
        );
        assert_eq!(buf[0], Status::NotFound as u8);
    }

    #[test]
    fn get_alarm_empty_requires_one_byte_response_buffer() {
        let mut server = AlarmsServer::<4>::new();
        assert!(matches!(
            server.handle_command(CommandId::new(0x02), &[], unicast(), &mut []),
            Err(ZclError::BufferTooSmall)
        ));
    }

    #[test]
    fn get_alarm_returns_first_entry_and_removes() {
        let mut server = AlarmsServer::<4>::new();
        server.add_alarm(entry(0x0402, 0x01));
        server.add_alarm(entry(0x0201, 0x02));
        let mut buf = [0u8; 32];
        let result = server
            .handle_command(CommandId::new(0x02), &[], unicast(), &mut buf)
            .unwrap();
        assert!(
            matches!(result, CommandResult::Payload { command_id, len: 8 } if command_id.0 == 0x01)
        );
        assert_eq!(buf[0], Status::Success as u8);
        assert_eq!(buf[1], 0x01); // alarm_code
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), 0x0402); // cluster_id
        // After GetAlarm, first entry removed
        assert_eq!(server.alarm_count(), 1);
        assert_eq!(server.alarms()[0], entry(0x0201, 0x02));
    }

    #[test]
    fn get_alarm_success_requires_eight_byte_response_buffer() {
        let mut server = AlarmsServer::<4>::new();
        server.add_alarm(entry(0x0402, 0x01));
        let mut buf = [0u8; 7];
        assert!(matches!(
            server.handle_command(CommandId::new(0x02), &[], unicast(), &mut buf),
            Err(ZclError::BufferTooSmall)
        ));
        assert_eq!(server.alarm_count(), 1);
    }

    // --- ResetAlarmLog (0x03) ---

    #[test]
    fn reset_alarm_log_clears_log() {
        let mut server = AlarmsServer::<4>::new();
        server.add_alarm(entry(0x0402, 0x01));
        let mut buf = [0u8; 32];
        let result = server.handle_command(CommandId::new(0x03), &[], unicast(), &mut buf);
        assert!(matches!(
            result,
            Ok(CommandResult::DefaultResponse(Status::Success))
        ));
        assert_eq!(server.alarm_count(), 0);
    }

    // --- unknown command ---

    #[test]
    fn unknown_command_returns_unsupcommand() {
        let mut server = AlarmsServer::<4>::new();
        let mut buf = [0u8; 32];
        let result = server.handle_command(CommandId::new(0xFF), &[], unicast(), &mut buf);
        assert!(matches!(
            result,
            Ok(CommandResult::DefaultResponse(Status::UnsupCommand))
        ));
    }

    // --- attribute_list ---

    #[test]
    fn attribute_list_has_two_entries() {
        assert_eq!(AlarmsServer::<4>::attribute_list().len(), 2);
    }

    #[test]
    fn attribute_list_alarm_count_is_read_only() {
        let attrs = AlarmsServer::<4>::attribute_list();
        assert!(attrs[0].access.is_readable());
        assert!(!attrs[0].access.is_writable());
        assert_eq!(attrs[0].type_id, TypeId::Uint16);
    }

    #[test]
    fn attribute_list_includes_cluster_revision() {
        let attrs = AlarmsServer::<4>::attribute_list();
        assert_eq!(attrs[1].id, AttributeId::new(0xFFFD));
        assert_eq!(attrs[1].type_id, TypeId::Uint16);
        assert!(attrs[1].access.is_readable());
        assert!(!attrs[1].access.is_writable());
    }

    #[test]
    fn commands_received_lists_rev8_client_commands() {
        let cmds = AlarmsServer::<4>::commands_received();
        assert_eq!(
            cmds,
            &[
                CommandId::new(0x00),
                CommandId::new(0x01),
                CommandId::new(0x02),
                CommandId::new(0x03),
            ]
        );
    }

    // --- dispatch integration ---

    #[test]
    fn dispatch_read_alarm_count() {
        let req: &[u8] = &[
            0x00, 0x01, 0x00, // ReadAttributes, seq=1
            0x00, 0x00, // attr 0x0000
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = AlarmsServer::<4>::new();
        server.add_alarm(entry(0x0402, 0x01));
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + attr_id(2) + status(1) + type_id(1) + value(2) = 9
        assert_eq!(n, 9);
        assert_eq!(buf[5], 0x00); // Success
        assert_eq!(buf[6], TypeId::Uint16.as_u8());
        assert_eq!(u16::from_le_bytes([buf[7], buf[8]]), 1);
    }

    #[test]
    fn dispatch_reset_all_alarms() {
        let req: &[u8] = &[
            0x01, 0x01, 0x01, // cluster-specific, seq=1, ResetAllAlarms
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = AlarmsServer::<4>::new();
        server.add_alarm(entry(0x0402, 0x01));
        zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf).unwrap();
        assert_eq!(server.alarm_count(), 0);
    }

    #[test]
    fn dispatch_get_alarm_empty() {
        let req: &[u8] = &[
            0x01, 0x01, 0x02, // cluster-specific, seq=1, GetAlarm
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = AlarmsServer::<4>::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + payload(1) = 4 bytes; status = NotFound
        assert_eq!(n, 4);
        assert_eq!(buf[3], Status::NotFound as u8);
    }
}
