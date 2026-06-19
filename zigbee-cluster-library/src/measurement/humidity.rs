define_measurement_cluster!(
    /// ZCL Relative Humidity Measurement cluster (0x0405).
    ///
    /// All attributes are read-only from ZCL; the application sets values via the
    /// typed setters. `None` encodes as the ZCL null sentinel `0xFFFF`. Values are
    /// in units of 0.01% RH (e.g. `5000` = 50.00% RH), range 0..=10000.
    RelativeHumidityMeasurementServer,
    cluster_id: 0x0405,
    value_ty: u16,
    attr_type_id: Uint16,
);

#[cfg(test)]
mod tests {

    use super::*;
    use crate::cluster_server::ApsPeer;
    use crate::cluster_server::ClusterServer;
    use crate::cluster_server::ConfigureReportingRecord;
    use crate::cluster_server::DeliveryMode;
    use crate::cluster_server::DispatchContext;
    use crate::cluster_server::ReportDeliveryResult;
    use crate::cluster_server::zcl_cluster_dispatch;
    use crate::frame::IncomingZclFrame;
    use crate::frame::Status;
    use crate::reporting::ReportPayloadWriter;
    use crate::types::error::AttrError;
    use crate::types::ids::AttributeId;
    use crate::types::ids::TypeId;

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
        let server = RelativeHumidityMeasurementServer::new();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], &[0xFF, 0xFF]);
    }

    #[test]
    fn measured_value_some_encodes_correctly() {
        let mut server = RelativeHumidityMeasurementServer::new();
        server.set_measured_value(Some(5000)).unwrap(); // 50.00% RH
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 5000u16);
    }

    #[test]
    fn tolerance_reads_as_uint16() {
        let mut server = RelativeHumidityMeasurementServer::new();
        server.set_tolerance(50).unwrap();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0003), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 50u16);
    }

    #[test]
    fn write_attribute_returns_read_only() {
        let mut server = RelativeHumidityMeasurementServer::new();
        for attr in [0x0000u16, 0x0001, 0x0002, 0x0003] {
            assert_eq!(
                server.write_attribute(AttributeId::new(attr), TypeId::Uint16, &[0x00, 0x00]),
                Err(AttrError::ReadOnly)
            );
        }
    }

    #[test]
    fn unknown_attribute_returns_unsupported() {
        let server = RelativeHumidityMeasurementServer::new();
        let mut buf = [0u8; 4];
        assert_eq!(
            server.read_attribute(AttributeId::new(0xFFFF), &mut buf),
            Err(AttrError::UnsupportedAttribute)
        );
    }

    #[test]
    fn attribute_list_measured_value_is_reportable() {
        let attrs = RelativeHumidityMeasurementServer::attribute_list();
        assert_eq!(attrs[0].id, AttributeId::new(0x0000));
        assert!(attrs[0].access.is_reportable());
    }

    #[test]
    fn dispatch_read_measured_value_null() {
        let req: &[u8] = &[
            0x00, 0x01, 0x00, // ReadAttributes, seq=1
            0x00, 0x00, // attr 0x0000
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = RelativeHumidityMeasurementServer::new();
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
        let mut server = RelativeHumidityMeasurementServer::new();
        let record = send_record(0x0000, TypeId::Uint16.as_u8(), 0, 60);
        assert_eq!(
            server.configure_reporting(record, unicast_with_source()),
            Status::Success
        );
    }

    #[test]
    fn configure_reporting_non_reportable_attr_returns_unreportable() {
        let mut server = RelativeHumidityMeasurementServer::new();
        let record = send_record(0x0001, TypeId::Uint16.as_u8(), 0, 60);
        assert_eq!(
            server.configure_reporting(record, unicast_with_source()),
            Status::UnreportableAttribute
        );
    }

    #[test]
    fn collect_reports_none_when_no_entry() {
        let mut server = RelativeHumidityMeasurementServer::new();
        server.set_measured_value(Some(5000)).unwrap();
        let mut buf = [0u8; 32];
        let mut writer = ReportPayloadWriter::new(&mut buf);
        assert!(server.collect_reports(0, &mut writer).unwrap().is_none());
    }

    #[test]
    fn collect_reports_after_set_and_min_interval_elapsed() {
        let mut server = RelativeHumidityMeasurementServer::new();
        let record = send_record(0x0000, TypeId::Uint16.as_u8(), 10, 60);
        server.configure_reporting(record, unicast_with_source());
        server.set_measured_value(Some(5000)).unwrap();

        let mut buf = [0u8; 32];

        let mut writer = ReportPayloadWriter::new(&mut buf);
        assert!(
            server
                .collect_reports(9_000, &mut writer)
                .unwrap()
                .is_none()
        );

        let mut writer = ReportPayloadWriter::new(&mut buf);
        let ready = server.collect_reports(10_000, &mut writer).unwrap();
        assert!(ready.is_some());
        // Payload: attr_id(2) + type_id(1) + value(2) = 5 bytes
        assert_eq!(writer.len(), 5);
    }

    #[test]
    fn report_delivery_result_sent_commits_and_clears_pending() {
        let mut server = RelativeHumidityMeasurementServer::new();
        let record = send_record(0x0000, TypeId::Uint16.as_u8(), 0, 60);
        server.configure_reporting(record, unicast_with_source());
        server.set_measured_value(Some(5000)).unwrap();

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
