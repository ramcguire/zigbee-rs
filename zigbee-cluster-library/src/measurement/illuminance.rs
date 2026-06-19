use crate::cluster_server::ClusterServer;
use crate::cluster_server::CommandResult;
use crate::cluster_server::DispatchContext;
use crate::frame::Status;
use crate::reporting::LatestReportingTable;
use crate::types::descriptors::AttrInfo;
use crate::types::descriptors::encode_attr;
use crate::types::enums::Enum8;
use crate::types::enums::LightSensorType;
use crate::types::error::AttrError;
use crate::types::error::ZclError;
use crate::types::ids::AttributeId;
use crate::types::ids::ClusterId;
use crate::types::ids::CommandId;
use crate::types::ids::TypeId;
use crate::types::nullable::Nullable;

/// ZCL Illuminance Measurement cluster (0x0400).
///
/// All attributes are read-only from ZCL; the application sets values via
/// typed setters. `None` encodes as the ZCL null sentinel `0xFFFF`.
pub struct IlluminanceMeasurementServer {
    /// Attribute 0x0000 — `MeasuredValue` (Uint16, nullable).
    pub measured_value: Option<u16>,
    /// Attribute 0x0001 — `MinMeasuredValue` (Uint16, nullable).
    pub min_measured_value: Option<u16>,
    /// Attribute 0x0002 — `MaxMeasuredValue` (Uint16, nullable).
    pub max_measured_value: Option<u16>,
    /// Attribute 0x0003 — `Tolerance` (Uint16).
    pub tolerance: u16,
    /// Attribute 0x0004 — `LightSensorType` (Enum8, nullable).
    pub light_sensor_type: Option<LightSensorType>,
    reporting: LatestReportingTable<1, 2>,
}

impl IlluminanceMeasurementServer {
    pub const fn new() -> Self {
        Self {
            measured_value: None,
            min_measured_value: None,
            max_measured_value: None,
            tolerance: 0,
            light_sensor_type: None,
            reporting: LatestReportingTable::new(),
        }
    }

    pub fn set_measured_value(&mut self, v: Option<u16>) {
        self.measured_value = v;
        self.reporting.note_value_update(AttributeId::new(0x0000));
    }

    pub fn set_min_measured_value(&mut self, v: Option<u16>) {
        self.min_measured_value = v;
    }

    pub fn set_max_measured_value(&mut self, v: Option<u16>) {
        self.max_measured_value = v;
    }

    pub fn set_tolerance(&mut self, v: u16) {
        self.tolerance = v;
    }

    pub fn set_light_sensor_type(&mut self, v: Option<LightSensorType>) {
        self.light_sensor_type = v;
    }
}

impl Default for IlluminanceMeasurementServer {
    fn default() -> Self {
        Self::new()
    }
}

impl ClusterServer for IlluminanceMeasurementServer {
    const CLUSTER_ID: ClusterId = ClusterId::new(0x0400);

    fn read_attribute(
        &self,
        id: AttributeId,
        buf: &mut [u8],
    ) -> Result<(TypeId, usize), AttrError> {
        match id.0 {
            0x0000 => Ok(encode_attr::<Nullable<u16>>(self.measured_value, buf)?),
            0x0001 => Ok(encode_attr::<Nullable<u16>>(self.min_measured_value, buf)?),
            0x0002 => Ok(encode_attr::<Nullable<u16>>(self.max_measured_value, buf)?),
            0x0003 => Ok(encode_attr::<u16>(self.tolerance, buf)?),
            0x0004 => Ok(encode_attr::<Nullable<Enum8<LightSensorType>>>(
                self.light_sensor_type,
                buf,
            )?),
            0xFFFD => Ok(encode_attr::<u16>(1, buf)?),
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

    impl_reporting!(reporting, 2);

    read_only_attrs![0x0000..=0x0004 | 0xFFFD];

    fn attribute_list() -> &'static [AttrInfo] {
        attr_list![
            (0x0000, Uint16, READ | REPORTABLE),
            (0x0001, Uint16, READ),
            (0x0002, Uint16, READ),
            (0x0003, Uint16, READ),
            (0x0004, Enum8, READ),
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

    #[test]
    fn measured_value_none_encodes_as_null_sentinel() {
        let server = IlluminanceMeasurementServer::new();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], &[0xFF, 0xFF]); // null sentinel
    }

    #[test]
    fn measured_value_some_encodes_correctly() {
        let mut server = IlluminanceMeasurementServer::new();
        server.set_measured_value(Some(1000));
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 1000);
    }

    #[test]
    fn all_mandatory_attributes_readable() {
        let mut server = IlluminanceMeasurementServer::new();
        server.set_measured_value(Some(500));
        server.set_min_measured_value(Some(1));
        server.set_max_measured_value(Some(65534));
        server.set_tolerance(10);

        for attr in [0x0000u16, 0x0001, 0x0002, 0x0003, 0x0004] {
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
    fn light_sensor_type_some_encodes_correctly() {
        let mut server = IlluminanceMeasurementServer::new();
        server.set_light_sensor_type(Some(LightSensorType::Photodiode));
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0004), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Enum8);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x00);
    }

    #[test]
    fn light_sensor_type_none_encodes_as_null_sentinel() {
        let server = IlluminanceMeasurementServer::new();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0004), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Enum8);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0xFF);
    }

    #[test]
    fn write_attribute_returns_read_only() {
        let mut server = IlluminanceMeasurementServer::new();
        for attr in [0x0000u16, 0x0001, 0x0002, 0x0003, 0x0004] {
            assert_eq!(
                server.write_attribute(AttributeId::new(attr), TypeId::Uint16, &[0x00, 0x00]),
                Err(AttrError::ReadOnly)
            );
        }
    }

    #[test]
    fn unknown_attribute_returns_unsupported() {
        let server = IlluminanceMeasurementServer::new();
        let mut buf = [0u8; 4];
        assert_eq!(
            server.read_attribute(AttributeId::new(0xFFFF), &mut buf),
            Err(AttrError::UnsupportedAttribute)
        );
    }

    #[test]
    fn attribute_list_measured_value_is_reportable() {
        let attrs = IlluminanceMeasurementServer::attribute_list();
        assert_eq!(attrs[0].id, AttributeId::new(0x0000));
        assert!(attrs[0].access.is_reportable());
    }

    #[test]
    fn attribute_list_has_five_entries() {
        assert_eq!(IlluminanceMeasurementServer::attribute_list().len(), 6);
    }

    #[test]
    fn dispatch_read_measured_value_null() {
        let req: &[u8] = &[0x00, 0x01, 0x00, 0x00, 0x00];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = IlluminanceMeasurementServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + attr_id(2) + status(1) + type_id(1) + value(2) = 9
        assert_eq!(n, 9);
        assert_eq!(buf[5], 0x00); // Success
        assert_eq!(buf[6], TypeId::Uint16.as_u8());
        assert_eq!(&buf[7..9], &[0xFF, 0xFF]); // null sentinel
    }

    #[test]
    fn configure_reporting_measured_value_returns_success() {
        let mut server = IlluminanceMeasurementServer::new();
        let record = send_record(0x0000, TypeId::Uint16.as_u8(), 0, 60);
        assert_eq!(
            server.configure_reporting(record, unicast_with_source()),
            Status::Success
        );
    }

    #[test]
    fn collect_reports_after_set_measured_value() {
        let mut server = IlluminanceMeasurementServer::new();
        let record = send_record(0x0000, TypeId::Uint16.as_u8(), 0, 60);
        server.configure_reporting(record, unicast_with_source());
        server.set_measured_value(Some(800));

        let mut buf = [0u8; 32];
        let mut writer = ReportPayloadWriter::new(&mut buf);
        let ready = server.collect_reports(0, &mut writer).unwrap();
        assert!(ready.is_some());
        // attr_id(2) + type_id(1) + value(2) = 5 bytes
        assert_eq!(writer.len(), 5);
        assert_eq!(u16::from_le_bytes([buf[3], buf[4]]), 800);
    }

    #[test]
    fn report_delivery_result_sent_clears_pending() {
        let mut server = IlluminanceMeasurementServer::new();
        let record = send_record(0x0000, TypeId::Uint16.as_u8(), 0, 60);
        server.configure_reporting(record, unicast_with_source());
        server.set_measured_value(Some(500));

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
