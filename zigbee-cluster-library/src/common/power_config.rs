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

/// ZCL Power Configuration cluster (0x0001).
///
/// All attributes are read-only from ZCL; the application sets values via
/// typed setters. `battery_percentage_remaining` is reportable.
pub struct PowerConfigServer {
    /// Attr 0x0000 — `MainsVoltage` (Uint16, R). Units: 100 mV.
    pub mains_voltage: u16,
    /// Attr 0x0020 — `BatteryVoltage` (Uint8, R). Units: 100 mV.
    pub battery_voltage: u8,
    /// Attr 0x0021 — `BatteryPercentageRemaining` (Uint8, R|REPORTABLE). Units:
    /// 0.5%.
    pub battery_percentage_remaining: u8,
    reporting: LatestReportingTable<1, 1>,
}

impl PowerConfigServer {
    pub const fn new() -> Self {
        Self {
            mains_voltage: 0,
            battery_voltage: 0xFF,
            battery_percentage_remaining: 0xFF,
            reporting: LatestReportingTable::new(),
        }
    }

    pub fn set_mains_voltage(&mut self, v: u16) {
        self.mains_voltage = v;
    }

    pub fn set_battery_voltage(&mut self, v: u8) {
        self.battery_voltage = v;
    }

    pub fn set_battery_percentage_remaining(&mut self, v: u8) {
        self.battery_percentage_remaining = v;
        self.reporting.note_value_update(AttributeId::new(0x0021));
    }
}

impl Default for PowerConfigServer {
    fn default() -> Self {
        Self::new()
    }
}

impl ClusterServer for PowerConfigServer {
    const CLUSTER_ID: ClusterId = ClusterId::new(0x0001);

    fn read_attribute(
        &self,
        id: AttributeId,
        buf: &mut [u8],
    ) -> Result<(TypeId, usize), AttrError> {
        match id.0 {
            0x0000 => Ok(encode_attr::<u16>(self.mains_voltage, buf)?),
            0x0020 => {
                let out = buf
                    .first_mut()
                    .ok_or(AttrError::Codec(ZclError::BufferTooSmall))?;
                *out = self.battery_voltage;
                Ok((TypeId::Uint8, 1))
            }
            0x0021 => {
                let out = buf
                    .first_mut()
                    .ok_or(AttrError::Codec(ZclError::BufferTooSmall))?;
                *out = self.battery_percentage_remaining;
                Ok((TypeId::Uint8, 1))
            }
            0xFFFD => Ok(encode_attr::<u16>(2, buf)?),
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }

    fn handle_command(
        &mut self,
        _id: CommandId,
        _payload: &[u8],
        _ctx: DispatchContext,
        _buf: &mut [u8],
    ) -> Result<CommandResult, ZclError> {
        Ok(CommandResult::DefaultResponse(Status::UnsupCommand))
    }

    impl_reporting!(reporting, 1);

    read_only_attrs![0x0000 | 0x0020 | 0x0021 | 0xFFFD];

    fn attribute_list() -> &'static [AttrInfo] {
        attr_list![
            (0x0000, Uint16, READ),
            (0x0020, Uint8, READ),
            (0x0021, Uint8, READ | REPORTABLE),
            (0xFFFD, Uint16, READ),
        ]
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

    // --- attribute reads ---

    #[test]
    fn mains_voltage_reads_as_uint16() {
        let mut server = PowerConfigServer::new();
        server.set_mains_voltage(2_300); // 230.0 V in 100 mV units
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 2300);
    }

    #[test]
    fn battery_voltage_reads_as_uint8() {
        let mut server = PowerConfigServer::new();
        server.set_battery_voltage(30); // 3.0 V in 100 mV units
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0020), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint8);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 30);
    }

    #[test]
    fn battery_percentage_reads_as_uint8() {
        let mut server = PowerConfigServer::new();
        server.set_battery_percentage_remaining(200); // 100% (200 × 0.5%)
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0021), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint8);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 200);
    }

    #[test]
    fn all_mandatory_attributes_readable() {
        let server = PowerConfigServer::new();
        for attr in [0x0000u16, 0x0020, 0x0021, 0xFFFD] {
            let mut buf = [0u8; 4];
            assert!(
                server
                    .read_attribute(AttributeId::new(attr), &mut buf)
                    .is_ok(),
                "attr 0x{attr:04X} not readable"
            );
        }
    }

    #[test]
    fn battery_attrs_default_to_unknown_sentinels() {
        let server = PowerConfigServer::new();
        assert_eq!(server.mains_voltage, 0);
        assert_eq!(server.battery_voltage, 0xFF);
        assert_eq!(server.battery_percentage_remaining, 0xFF);
    }

    #[test]
    fn cluster_revision_reads_rev8_value() {
        let server = PowerConfigServer::new();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0xFFFD), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 2);
    }

    #[test]
    fn unknown_attribute_returns_unsupported() {
        let server = PowerConfigServer::new();
        let mut buf = [0u8; 4];
        assert_eq!(
            server.read_attribute(AttributeId::new(0xFFFF), &mut buf),
            Err(AttrError::UnsupportedAttribute)
        );
    }

    // --- attribute writes ---

    #[test]
    fn write_attribute_returns_read_only_for_all_attrs() {
        let mut server = PowerConfigServer::new();
        for (attr, tid, data) in [
            (
                0x0000u16,
                TypeId::Uint16,
                [0x00u8, 0x00, 0x00, 0x00].as_ref(),
            ),
            (0x0020, TypeId::Uint8, [0x00u8].as_ref()),
            (0x0021, TypeId::Uint8, [0x00u8].as_ref()),
            (0xFFFD, TypeId::Uint16, [0x02u8, 0x00].as_ref()),
        ] {
            assert_eq!(
                server.write_attribute(AttributeId::new(attr), tid, data),
                Err(AttrError::ReadOnly),
                "expected ReadOnly for attr 0x{attr:04X}"
            );
        }
    }

    // --- attribute_list ---

    #[test]
    fn attribute_list_has_four_entries() {
        assert_eq!(PowerConfigServer::attribute_list().len(), 4);
    }

    #[test]
    fn attribute_list_battery_percentage_is_reportable() {
        let attrs = PowerConfigServer::attribute_list();
        let entry = attrs
            .iter()
            .find(|a| a.id == AttributeId::new(0x0021))
            .unwrap();
        assert!(entry.access.is_reportable());
        assert!(entry.access.is_readable());
    }

    #[test]
    fn attribute_list_mains_voltage_not_reportable() {
        let attrs = PowerConfigServer::attribute_list();
        let entry = attrs
            .iter()
            .find(|a| a.id == AttributeId::new(0x0000))
            .unwrap();
        assert!(!entry.access.is_reportable());
        assert_eq!(entry.type_id, TypeId::Uint16);
    }

    // --- reporting ---

    #[test]
    fn configure_reporting_battery_percentage_success() {
        let mut server = PowerConfigServer::new();
        let record = send_record(0x0021, TypeId::Uint8.as_u8(), 0, 60);
        assert_eq!(
            server.configure_reporting(record, unicast_with_source()),
            Status::Success
        );
    }

    #[test]
    fn configure_reporting_mains_voltage_returns_unreportable() {
        let mut server = PowerConfigServer::new();
        let record = send_record(0x0000, TypeId::Uint16.as_u8(), 0, 60);
        assert_eq!(
            server.configure_reporting(record, unicast_with_source()),
            Status::UnreportableAttribute
        );
    }

    #[test]
    fn collect_reports_none_when_no_subscription() {
        let mut server = PowerConfigServer::new();
        server.set_battery_percentage_remaining(100);
        let mut buf = [0u8; 32];
        let mut writer = ReportPayloadWriter::new(&mut buf);
        assert!(server.collect_reports(0, &mut writer).unwrap().is_none());
    }

    #[test]
    fn collect_reports_after_set_battery_percentage() {
        let mut server = PowerConfigServer::new();
        let record = send_record(0x0021, TypeId::Uint8.as_u8(), 0, 60);
        server.configure_reporting(record, unicast_with_source());
        server.set_battery_percentage_remaining(150);

        let mut buf = [0u8; 32];
        let mut writer = ReportPayloadWriter::new(&mut buf);
        let ready = server.collect_reports(0, &mut writer).unwrap();
        assert!(ready.is_some());
        // attr_id(2) + type_id(1) + value(1) = 4 bytes
        assert_eq!(writer.len(), 4);
        assert_eq!(buf[3], 150); // battery percentage value
    }

    #[test]
    fn report_delivery_result_clears_pending() {
        let mut server = PowerConfigServer::new();
        let record = send_record(0x0021, TypeId::Uint8.as_u8(), 0, 60);
        server.configure_reporting(record, unicast_with_source());
        server.set_battery_percentage_remaining(150);

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
    fn dispatch_read_mains_voltage() {
        let req: &[u8] = &[
            0x00, 0x01, 0x00, // ReadAttributes, seq=1
            0x00, 0x00, // attr 0x0000
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = PowerConfigServer::new();
        server.set_mains_voltage(2300);
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + attr_id(2) + status(1) + type_id(1) + value(2) = 9
        assert_eq!(n, 9);
        assert_eq!(buf[5], 0x00); // Success
        assert_eq!(buf[6], TypeId::Uint16.as_u8());
        assert_eq!(u16::from_le_bytes([buf[7], buf[8]]), 2300);
    }

    #[test]
    fn dispatch_write_battery_voltage_returns_read_only() {
        let req: &[u8] = &[
            0x00, 0x02, 0x02, // WriteAttributes, seq=2
            0x20, 0x00, // attr 0x0020
            0x20, // Uint8 type id
            0x1E, // value 30
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = PowerConfigServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + status(1) + attr_id(2) = 6
        assert_eq!(n, 6);
        assert_eq!(buf[3], Status::ReadOnly as u8);
    }
}
