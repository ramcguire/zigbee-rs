define_measurement_cluster!(
    /// ZCL Temperature Measurement cluster (0x0402).
    ///
    /// All attributes are read-only from ZCL; the application sets values via the
    /// typed setters. `None` encodes as the ZCL null sentinel `0x8000`
    /// (`i16::MIN`).
    TemperatureMeasurementServer,
    cluster_id: 0x0402,
    value_ty: i16,
    attr_type_id: Int16,
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
    use crate::types::error::ZclError;
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

    // --- existing attribute tests ---

    #[test]
    fn measured_value_none_encodes_as_null_sentinel() {
        let server = TemperatureMeasurementServer::new();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Int16);
        assert_eq!(n, 2);
        // null sentinel = 0x8000 = i16::MIN in LE
        assert_eq!(&buf[..2], &[0x00, 0x80]);
    }

    #[test]
    fn measured_value_some_encodes_correctly() {
        let mut server = TemperatureMeasurementServer::new();
        server.set_measured_value(Some(-2500)).unwrap(); // -25.00°C in ZCL units (100ths)
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Int16);
        assert_eq!(n, 2);
        let got = i16::from_le_bytes([buf[0], buf[1]]);
        assert_eq!(got, -2500i16);
    }

    #[test]
    fn all_mandatory_attributes_readable() {
        let mut server = TemperatureMeasurementServer::new();
        server.set_measured_value(Some(2000)).unwrap();
        server.set_min_measured_value(Some(-4000)).unwrap();
        server.set_max_measured_value(Some(8500)).unwrap();

        for attr in [0x0000u16, 0x0001, 0x0002, 0x0003] {
            let mut buf = [0u8; 4];
            assert!(
                server
                    .read_attribute(AttributeId::new(attr), &mut buf)
                    .is_ok()
            );
        }
    }

    #[test]
    fn write_attribute_returns_read_only() {
        let mut server = TemperatureMeasurementServer::new();
        for attr in [0x0000u16, 0x0001, 0x0002, 0x0003] {
            let result =
                server.write_attribute(AttributeId::new(attr), TypeId::Int16, &[0x10, 0x00]);
            assert_eq!(result, Err(AttrError::ReadOnly));
        }
    }

    #[test]
    fn tolerance_reads_as_uint16() {
        let mut server = TemperatureMeasurementServer::new();
        server.set_tolerance(25).unwrap();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0003), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 25);
    }

    #[test]
    fn attribute_list_includes_tolerance() {
        let attrs = TemperatureMeasurementServer::attribute_list();
        assert_eq!(attrs.len(), 5);
        assert_eq!(attrs[3].id, AttributeId::new(0x0003));
        assert_eq!(attrs[3].type_id, TypeId::Uint16);
    }

    #[test]
    fn attribute_list_measured_value_is_reportable() {
        let attrs = TemperatureMeasurementServer::attribute_list();
        assert_eq!(attrs[0].id, AttributeId::new(0x0000));
        assert!(attrs[0].access.is_reportable());
    }

    #[test]
    fn unknown_attribute_returns_unsupported() {
        let server = TemperatureMeasurementServer::new();
        let mut buf = [0u8; 4];
        assert_eq!(
            server.read_attribute(AttributeId::new(0xFFFF), &mut buf),
            Err(AttrError::UnsupportedAttribute)
        );
    }

    #[test]
    fn dispatch_read_measured_value_null() {
        let req: &[u8] = &[
            0x00, 0x01, 0x00, // ReadAttributes, seq=1
            0x00, 0x00, // attr 0x0000
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TemperatureMeasurementServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + attr_id(2) + status(1) + type_id(1) + value(2) = 9
        assert_eq!(n, 9);
        assert_eq!(buf[5], 0x00); // Success
        assert_eq!(buf[6], TypeId::Int16.as_u8());
        assert_eq!(&buf[7..9], &[0x00, 0x80]); // null sentinel
    }

    #[test]
    fn dispatch_write_returns_read_only_response() {
        let req: &[u8] = &[
            0x00, 0x02, 0x02, // WriteAttributes, seq=2
            0x00, 0x00, // attr 0x0000
            0x29, // Int16 type id
            0x10, 0x00, // value
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TemperatureMeasurementServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + status(1) + attr_id(2) = 6
        assert_eq!(n, 6);
        assert_eq!(buf[3], Status::ReadOnly as u8);
    }

    // --- reporting ---

    #[test]
    fn configure_reporting_measured_value_returns_success() {
        let mut server = TemperatureMeasurementServer::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 0, 60);
        assert_eq!(
            server.configure_reporting(record, unicast_with_source()),
            Status::Success
        );
    }

    #[test]
    fn read_reporting_config_after_configure_returns_intervals() {
        let mut server = TemperatureMeasurementServer::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 10, 300);
        server.configure_reporting(record, unicast_with_source());

        let mut buf = [0u8; 16];
        let n = server.read_reporting_config(AttributeId::new(0x0000), 0, &mut buf);
        // status(1)+dir(1)+attr(2)+type(1)+min(2)+max(2) = 9 (no reportable_change;
        // send_record passes &[])
        assert_eq!(buf[0], 0x00); // SUCCESS
        assert_eq!(buf[1], 0x00); // direction
        assert_eq!(&buf[2..4], &[0x00, 0x00]); // attr_id=0x0000
        assert_eq!(buf[4], TypeId::Int16.as_u8()); // data_type
        assert_eq!(u16::from_le_bytes([buf[5], buf[6]]), 10); // min_interval
        assert_eq!(u16::from_le_bytes([buf[7], buf[8]]), 300); // max_interval
        assert_eq!(n, 9);
    }

    #[test]
    fn read_reporting_config_unconfigured_attr_returns_not_found() {
        let server = TemperatureMeasurementServer::new();
        let mut buf = [0u8; 16];
        let n = server.read_reporting_config(AttributeId::new(0x0000), 0, &mut buf);
        assert_eq!(n, 4);
        assert_eq!(buf[0], 0x8b); // NOT_FOUND
    }

    #[test]
    fn configure_reporting_non_reportable_attr_returns_unreportable() {
        let mut server = TemperatureMeasurementServer::new();
        // attr 0x0001 (MinMeasuredValue) is READ-only, not REPORTABLE
        let record = send_record(0x0001, TypeId::Int16.as_u8(), 0, 60);
        assert_eq!(
            server.configure_reporting(record, unicast_with_source()),
            Status::UnreportableAttribute
        );
    }

    #[test]
    fn collect_reports_none_when_no_entry() {
        let mut server = TemperatureMeasurementServer::new();
        server.set_measured_value(Some(2500)).unwrap();
        let mut buf = [0u8; 32];
        let mut writer = ReportPayloadWriter::new(&mut buf);
        assert!(server.collect_reports(0, &mut writer).unwrap().is_none());
    }

    #[test]
    fn collect_reports_after_set_and_min_interval_elapsed() {
        let mut server = TemperatureMeasurementServer::new();
        // min_interval = 10 s
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 10, 60);
        server.configure_reporting(record, unicast_with_source());
        server.set_measured_value(Some(2500)).unwrap();

        let mut buf = [0u8; 32];

        // Before min_interval: not due.
        let mut writer = ReportPayloadWriter::new(&mut buf);
        assert!(
            server
                .collect_reports(9_000, &mut writer)
                .unwrap()
                .is_none()
        );

        // After min_interval: due.
        let mut writer = ReportPayloadWriter::new(&mut buf);
        let ready = server.collect_reports(10_000, &mut writer).unwrap();
        assert!(ready.is_some());
        // Payload: attr_id(2) + type_id(1) + value(2) = 5 bytes
        assert_eq!(writer.len(), 5);
    }

    #[test]
    fn report_delivery_result_sent_commits_and_clears_pending() {
        let mut server = TemperatureMeasurementServer::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 0, 60);
        server.configure_reporting(record, unicast_with_source());
        server.set_measured_value(Some(2500)).unwrap();

        let mut buf = [0u8; 32];
        let mut writer = ReportPayloadWriter::new(&mut buf);
        let ready = server
            .collect_reports(0, &mut writer)
            .unwrap()
            .expect("pending report");

        server.report_delivery_result(ready.token, ReportDeliveryResult::Sent, 1_000);

        // No longer due immediately after delivery.
        let mut writer = ReportPayloadWriter::new(&mut buf);
        assert!(
            server
                .collect_reports(1_000, &mut writer)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn collect_reports_buffer_too_small_sets_diagnostic_and_keeps_pending() {
        let mut server = TemperatureMeasurementServer::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 0, 60);
        server.configure_reporting(record, unicast_with_source());
        server.set_measured_value(Some(2500)).unwrap();

        let mut short = [0u8; 4];
        let mut writer = ReportPayloadWriter::new(&mut short);
        assert_eq!(
            server.collect_reports(0, &mut writer),
            Err(ZclError::BufferTooSmall)
        );
        assert!(server.take_reporting_diagnostics().buffer_too_small);

        let mut buf = [0u8; 32];
        let mut writer = ReportPayloadWriter::new(&mut buf);
        assert!(server.collect_reports(0, &mut writer).unwrap().is_some());
    }

    #[test]
    fn two_rapid_set_measured_value_coalesces() {
        let mut server = TemperatureMeasurementServer::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 0, 60);
        server.configure_reporting(record, unicast_with_source());

        server.set_measured_value(Some(2500)).unwrap(); // Pending
        server.set_measured_value(Some(2600)).unwrap(); // Coalesced

        let diag = server.take_reporting_diagnostics();
        assert_eq!(diag.coalesced_updates, 1);
    }
}
