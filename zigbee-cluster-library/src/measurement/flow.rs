define_measurement_cluster!(
    /// ZCL Flow Measurement cluster (0x0404).
    ///
    /// All attributes are read-only from ZCL; the application sets values via the
    /// typed setters. `None` encodes as the ZCL null sentinel `0xFFFF`.
    /// Values are in units of 1/10 m³/h.
    FlowMeasurementServer,
    cluster_id: 0x0404,
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
        let server = FlowMeasurementServer::new();
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
        let mut server = FlowMeasurementServer::new();
        server.set_measured_value(Some(250)).unwrap(); // 25.0 m³/h
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 250);
    }

    #[test]
    fn all_mandatory_attributes_readable() {
        let mut server = FlowMeasurementServer::new();
        server.set_measured_value(Some(100)).unwrap();
        server.set_min_measured_value(Some(0)).unwrap();
        server.set_max_measured_value(Some(65534)).unwrap();
        server.set_tolerance(5).unwrap();

        for attr in [0x0000u16, 0x0001, 0x0002, 0x0003] {
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
    fn write_attribute_returns_read_only() {
        let mut server = FlowMeasurementServer::new();
        for attr in [0x0000u16, 0x0001, 0x0002, 0x0003] {
            assert_eq!(
                server.write_attribute(AttributeId::new(attr), TypeId::Uint16, &[0x00, 0x00]),
                Err(AttrError::ReadOnly)
            );
        }
    }

    #[test]
    fn unknown_attribute_returns_unsupported() {
        let server = FlowMeasurementServer::new();
        let mut buf = [0u8; 4];
        assert_eq!(
            server.read_attribute(AttributeId::new(0xFFFF), &mut buf),
            Err(AttrError::UnsupportedAttribute)
        );
    }

    #[test]
    fn attribute_list_measured_value_is_reportable() {
        let attrs = FlowMeasurementServer::attribute_list();
        assert_eq!(attrs[0].id, AttributeId::new(0x0000));
        assert!(attrs[0].access.is_reportable());
    }

    #[test]
    fn attribute_list_has_four_entries() {
        assert_eq!(FlowMeasurementServer::attribute_list().len(), 5);
    }

    #[test]
    fn dispatch_read_measured_value_null() {
        let req: &[u8] = &[0x00, 0x01, 0x00, 0x00, 0x00];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = FlowMeasurementServer::new();
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
        let mut server = FlowMeasurementServer::new();
        let record = send_record(0x0000, TypeId::Uint16.as_u8(), 0, 60);
        assert_eq!(
            server.configure_reporting(record, unicast_with_source()),
            Status::Success
        );
    }

    #[test]
    fn collect_reports_after_set_measured_value() {
        let mut server = FlowMeasurementServer::new();
        let record = send_record(0x0000, TypeId::Uint16.as_u8(), 0, 60);
        server.configure_reporting(record, unicast_with_source());
        server.set_measured_value(Some(350)).unwrap();

        let mut buf = [0u8; 32];
        let mut writer = ReportPayloadWriter::new(&mut buf);
        let ready = server.collect_reports(0, &mut writer).unwrap();
        assert!(ready.is_some());
        // attr_id(2) + type_id(1) + value(2) = 5 bytes
        assert_eq!(writer.len(), 5);
        assert_eq!(u16::from_le_bytes([buf[3], buf[4]]), 350);
    }

    #[test]
    fn report_delivery_result_sent_clears_pending() {
        let mut server = FlowMeasurementServer::new();
        let record = send_record(0x0000, TypeId::Uint16.as_u8(), 0, 60);
        server.configure_reporting(record, unicast_with_source());
        server.set_measured_value(Some(200)).unwrap();

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
