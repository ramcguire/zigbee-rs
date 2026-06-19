use crate::cluster_server::ClusterServer;
use crate::cluster_server::CommandResult;
use crate::cluster_server::DispatchContext;
use crate::frame::Status;
use crate::reporting::LatestReportingTable;
use crate::types::descriptors::AttrInfo;
use crate::types::descriptors::encode_attr;
use crate::types::error::AttrError;
use crate::types::error::ZclError;
use crate::types::ids::AttributeId;
use crate::types::ids::ClusterId;
use crate::types::ids::CommandId;
use crate::types::ids::TypeId;

/// ZCL On/Off cluster (0x0006), Strategy 1.
///
/// State is changed by commands (On/Off/Toggle); the `on_off` attribute is
/// read-only from ZCL. The application may read `on_off` directly.
///
/// Optional enhanced attributes (0x4000–0x4002) are stored and discoverable
/// but the `OffWithEffect` / `OnWithTimedOff` commands that consume them are
/// not implemented; applications can read and write these fields directly.
pub struct OnOffServer {
    /// Attribute 0x0000 — `OnOff` (Boolean, R|REPORTABLE).
    on_off: bool,
    /// Attribute 0x4000 — `GlobalSceneControl` (Boolean, R). Default true.
    global_scene_control: bool,
    /// Attribute 0x4001 — `OnTime` (Uint16, R/W, 1/10 s). Default 0.
    on_time: u16,
    /// Attribute 0x4002 — `OffWaitTime` (Uint16, R/W, 1/10 s). Default 0.
    off_wait_time: u16,
    reporting: LatestReportingTable<1, 1>,
}

impl OnOffServer {
    pub const fn new(initial: bool) -> Self {
        Self {
            on_off: initial,
            global_scene_control: true,
            on_time: 0,
            off_wait_time: 0,
            reporting: LatestReportingTable::new(),
        }
    }

    pub fn on_off(&self) -> bool {
        self.on_off
    }

    pub fn set_on_off(&mut self, val: bool) {
        self.on_off = val;
        self.reporting.note_value_update(AttributeId::new(0x0000));
    }

    pub fn global_scene_control(&self) -> bool {
        self.global_scene_control
    }

    pub fn set_global_scene_control(&mut self, val: bool) {
        self.global_scene_control = val;
    }

    pub fn on_time(&self) -> u16 {
        self.on_time
    }

    pub fn set_on_time(&mut self, val: u16) {
        self.on_time = val;
    }

    pub fn off_wait_time(&self) -> u16 {
        self.off_wait_time
    }

    pub fn set_off_wait_time(&mut self, val: u16) {
        self.off_wait_time = val;
    }

    /// Configure reporting to bound peers (APS binding table).
    pub fn configure_bound_reporting(
        &mut self,
        min_interval: u16,
        max_interval: u16,
        now_ms: u32,
    ) -> Status {
        self.reporting.configure_bound(
            AttributeId::new(0x0000),
            TypeId::Boolean,
            min_interval,
            max_interval,
            now_ms,
            Self::attribute_list(),
        )
    }
}

impl Default for OnOffServer {
    fn default() -> Self {
        Self::new(false)
    }
}

impl ClusterServer for OnOffServer {
    const CLUSTER_ID: ClusterId = ClusterId::new(0x0006);

    fn read_attribute(
        &self,
        id: AttributeId,
        buf: &mut [u8],
    ) -> Result<(TypeId, usize), AttrError> {
        match id.0 {
            0x0000 => Ok(encode_attr::<bool>(self.on_off, buf)?),
            0xFFFD => Ok(encode_attr::<u16>(2, buf)?),
            0x4000 => Ok(encode_attr::<bool>(self.global_scene_control, buf)?),
            0x4001 => Ok(encode_attr::<u16>(self.on_time, buf)?),
            0x4002 => Ok(encode_attr::<u16>(self.off_wait_time, buf)?),
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
            0x0000 | 0x4000 | 0xFFFD => Err(AttrError::ReadOnly),
            0x4001 | 0x4002 => {
                if type_id == TypeId::Uint16 {
                    Ok(())
                } else {
                    Err(AttrError::InvalidDataType)
                }
            }
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
            0x0000 | 0x4000 | 0xFFFD => Err(AttrError::ReadOnly),
            0x4001 => {
                if type_id != TypeId::Uint16 {
                    return Err(AttrError::InvalidDataType);
                }
                if data.len() < 2 {
                    return Err(AttrError::InvalidValue);
                }
                self.on_time = u16::from_le_bytes([data[0], data[1]]);
                Ok(())
            }
            0x4002 => {
                if type_id != TypeId::Uint16 {
                    return Err(AttrError::InvalidDataType);
                }
                if data.len() < 2 {
                    return Err(AttrError::InvalidValue);
                }
                self.off_wait_time = u16::from_le_bytes([data[0], data[1]]);
                Ok(())
            }
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }

    fn handle_command(
        &mut self,
        id: CommandId,
        _payload: &[u8],
        _ctx: DispatchContext,
        _buf: &mut [u8],
    ) -> Result<CommandResult, ZclError> {
        match id.0 {
            0x00 => {
                self.on_off = false;
                self.reporting.note_value_update(AttributeId::new(0x0000));
                Ok(CommandResult::DefaultResponse(Status::Success))
            }
            0x01 => {
                self.on_off = true;
                self.reporting.note_value_update(AttributeId::new(0x0000));
                Ok(CommandResult::DefaultResponse(Status::Success))
            }
            0x02 => {
                self.on_off = !self.on_off;
                self.reporting.note_value_update(AttributeId::new(0x0000));
                Ok(CommandResult::DefaultResponse(Status::Success))
            }
            _ => Ok(CommandResult::DefaultResponse(Status::UnsupCommand)),
        }
    }

    impl_reporting!(reporting, 1);

    fn commands_received() -> &'static [CommandId] {
        static CMDS: [CommandId; 3] = [
            CommandId::new(0x00),
            CommandId::new(0x01),
            CommandId::new(0x02),
        ];
        &CMDS
    }

    fn attribute_list() -> &'static [AttrInfo] {
        attr_list![
            (0x0000, Boolean, READ | REPORTABLE),
            (0xFFFD, Uint16, READ),
            (0x4000, Boolean, READ),
            (0x4001, Uint16, READ | WRITE),
            (0x4002, Uint16, READ | WRITE),
        ]
    }

    fn snapshot(&self, buf: &mut [u8]) -> usize {
        if buf.len() < 6 {
            return 0;
        }
        buf[0] = u8::from(self.on_off);
        buf[1] = u8::from(self.global_scene_control);
        buf[2..4].copy_from_slice(&self.on_time.to_le_bytes());
        buf[4..6].copy_from_slice(&self.off_wait_time.to_le_bytes());
        6
    }

    fn restore_snapshot(&mut self, buf: &[u8]) {
        if buf.len() < 6 {
            return;
        }
        self.on_off = buf[0] != 0;
        self.global_scene_control = buf[1] != 0;
        self.on_time = u16::from_le_bytes([buf[2], buf[3]]);
        self.off_wait_time = u16::from_le_bytes([buf[4], buf[5]]);
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

    fn unicast() -> DispatchContext {
        DispatchContext::unicast(0, None)
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
            attr_type: TypeId::Boolean.as_u8(),
            min_interval: min,
            max_interval: max,
            reportable_change: &[],
            timeout_period: 0,
        }
    }

    #[test]
    fn on_off_attribute_reads_false_initially() {
        let server = OnOffServer::new(false);
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Boolean);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x00);
    }

    #[test]
    fn on_command_sets_on_off_true() {
        let mut server = OnOffServer::new(false);
        let result = server
            .handle_command(CommandId(0x01), &[], unicast(), &mut [])
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::Success)
        ));
        assert!(server.on_off);
    }

    #[test]
    fn off_command_sets_on_off_false() {
        let mut server = OnOffServer::new(true);
        let result = server
            .handle_command(CommandId(0x00), &[], unicast(), &mut [])
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::Success)
        ));
        assert!(!server.on_off);
    }

    #[test]
    fn toggle_command_flips_state() {
        let mut server = OnOffServer::new(false);
        let _ = server.handle_command(CommandId(0x02), &[], unicast(), &mut []);
        assert!(server.on_off);
        let _ = server.handle_command(CommandId(0x02), &[], unicast(), &mut []);
        assert!(!server.on_off);
    }

    #[test]
    fn unknown_command_returns_unsup() {
        let mut server = OnOffServer::new(false);
        let result = server
            .handle_command(CommandId(0xFF), &[], unicast(), &mut [])
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::UnsupCommand)
        ));
    }

    #[test]
    fn write_attribute_returns_read_only() {
        let mut server = OnOffServer::new(false);
        assert_eq!(
            server.write_attribute(AttributeId::new(0x0000), TypeId::Boolean, &[0x01]),
            Err(AttrError::ReadOnly)
        );
    }

    #[test]
    fn optional_attrs_default_values() {
        let server = OnOffServer::new(false);
        assert!(server.global_scene_control());
        assert_eq!(server.on_time(), 0);
        assert_eq!(server.off_wait_time(), 0);
    }

    #[test]
    fn global_scene_control_reads_as_boolean() {
        let server = OnOffServer::new(false);
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x4000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Boolean);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x01); // true
    }

    #[test]
    fn global_scene_control_is_read_only_from_zcl() {
        let mut server = OnOffServer::new(false);
        assert_eq!(
            server.write_attribute(AttributeId::new(0x4000), TypeId::Boolean, &[0x00]),
            Err(AttrError::ReadOnly)
        );
    }

    #[test]
    fn on_time_reads_and_writes() {
        let mut server = OnOffServer::new(false);
        server
            .write_attribute(AttributeId::new(0x4001), TypeId::Uint16, &[0x0A, 0x00])
            .unwrap();
        assert_eq!(server.on_time(), 10);
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x4001), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 10);
    }

    #[test]
    fn off_wait_time_reads_and_writes() {
        let mut server = OnOffServer::new(false);
        server
            .write_attribute(AttributeId::new(0x4002), TypeId::Uint16, &[0x14, 0x00])
            .unwrap();
        assert_eq!(server.off_wait_time(), 20);
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x4002), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 20);
    }

    #[test]
    fn on_time_wrong_type_returns_invalid_data_type() {
        let mut server = OnOffServer::new(false);
        assert_eq!(
            server.write_attribute(AttributeId::new(0x4001), TypeId::Uint8, &[0x0A]),
            Err(AttrError::InvalidDataType)
        );
    }

    #[test]
    fn attribute_list_has_five_entries() {
        assert_eq!(OnOffServer::attribute_list().len(), 5);
    }

    #[test]
    fn dispatch_on_command_sends_default_response() {
        // cluster-specific On command, seq=5
        let req: &[u8] = &[0x01, 0x05, 0x01]; // cluster-specific | disable-DR=0, seq, On
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = OnOffServer::new(false);
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        assert_eq!(n, 5); // DefaultResponse is 5 bytes
        assert_eq!(buf[2], 0x0b); // DefaultResponse command id
        assert_eq!(buf[4], Status::Success as u8);
        assert!(server.on_off);
    }

    #[test]
    fn dispatch_toggle_command_flips_state() {
        let req: &[u8] = &[0x01, 0x06, 0x02]; // Toggle
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = OnOffServer::new(true);
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;
        assert_eq!(n, 5);
        assert!(!server.on_off);
    }

    #[test]
    fn attribute_list_on_off_is_reportable() {
        let attrs = OnOffServer::attribute_list();
        assert_eq!(attrs[0].id, AttributeId::new(0x0000));
        assert!(attrs[0].access.is_reportable());
    }

    #[test]
    fn configure_reporting_on_off_returns_success() {
        let mut server = OnOffServer::new(false);
        assert_eq!(
            server.configure_reporting(send_record(0, 60), unicast_with_source()),
            Status::Success
        );
    }

    #[test]
    fn on_command_marks_pending_report() {
        let mut server = OnOffServer::new(false);
        server.configure_reporting(send_record(0, 60), unicast_with_source());

        server
            .handle_command(CommandId(0x01), &[], unicast(), &mut [])
            .unwrap();

        let mut buf = [0u8; 32];
        let mut writer = ReportPayloadWriter::new(&mut buf);
        let ready = server.collect_reports(0, &mut writer).unwrap();
        assert!(ready.is_some());
        // Boolean attr: attr_id(2) + type_id(1) + value(1) = 4 bytes
        assert_eq!(writer.len(), 4);
        assert_eq!(buf[3], 0x01); // on_off = true
    }

    #[test]
    fn toggle_command_marks_pending_report() {
        let mut server = OnOffServer::new(false);
        server.configure_reporting(send_record(0, 60), unicast_with_source());

        server
            .handle_command(CommandId(0x02), &[], unicast(), &mut [])
            .unwrap();

        let mut buf = [0u8; 32];
        let mut writer = ReportPayloadWriter::new(&mut buf);
        assert!(server.collect_reports(0, &mut writer).unwrap().is_some());
    }

    #[test]
    fn report_delivery_result_sent_clears_pending() {
        let mut server = OnOffServer::new(false);
        server.configure_reporting(send_record(0, 60), unicast_with_source());
        server
            .handle_command(CommandId(0x01), &[], unicast(), &mut [])
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
}
