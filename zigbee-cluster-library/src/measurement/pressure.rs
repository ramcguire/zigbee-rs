define_measurement_cluster!(
    /// ZCL Pressure Measurement cluster (0x0403).
    ///
    /// All attributes are read-only from ZCL; the application sets values via the
    /// typed setters. `None` encodes as the ZCL null sentinel `0x8000`
    /// (`i16::MIN`). Values are in units of 0.1 kPa (e.g. `1013` = 101.3 kPa).
    PressureMeasurementServer,
    cluster_id: 0x0403,
    value_ty: i16,
    attr_type_id: Int16,
);

#[cfg(test)]
mod tests {

    use super::*;
    use crate::cluster_server::ClusterServer;
    use crate::cluster_server::DispatchContext;
    use crate::cluster_server::zcl_cluster_dispatch;
    use crate::frame::IncomingZclFrame;
    use crate::types::error::AttrError;
    use crate::types::ids::AttributeId;
    use crate::types::ids::TypeId;

    fn unicast() -> DispatchContext {
        DispatchContext::unicast(0, None)
    }

    #[test]
    fn measured_value_null_encodes_as_sentinel() {
        let server = PressureMeasurementServer::new();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Int16);
        assert_eq!(n, 2);
        assert_eq!(i16::from_le_bytes([buf[0], buf[1]]), i16::MIN);
    }

    #[test]
    fn measured_value_encodes_correctly() {
        let mut server = PressureMeasurementServer::new();
        server.set_measured_value(Some(1013)).unwrap(); // 101.3 kPa
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Int16);
        assert_eq!(n, 2);
        assert_eq!(i16::from_le_bytes([buf[0], buf[1]]), 1013i16);
    }

    #[test]
    fn tolerance_encodes_correctly() {
        let mut server = PressureMeasurementServer::new();
        server.set_tolerance(5).unwrap();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0003), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 5u16);
    }

    #[test]
    fn write_returns_read_only() {
        let mut server = PressureMeasurementServer::new();
        let err = server
            .write_attribute(AttributeId::new(0x0000), TypeId::Int16, &[0x00, 0x00])
            .unwrap_err();
        assert!(matches!(err, AttrError::ReadOnly));
    }

    #[test]
    fn unknown_attribute_returns_unsupported() {
        let server = PressureMeasurementServer::new();
        let mut buf = [0u8; 4];
        let err = server
            .read_attribute(AttributeId::new(0xFFFF), &mut buf)
            .unwrap_err();
        assert!(matches!(err, AttrError::UnsupportedAttribute));
    }

    #[test]
    fn dispatch_read_measured_value() {
        let req: &[u8] = &[
            0x00, 0x01, 0x00, // global, seq=1, ReadAttributes
            0x00, 0x00, // attr 0x0000
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = PressureMeasurementServer::new();
        server.set_measured_value(Some(500)).unwrap(); // 50.0 kPa
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;
        // ReadAttributesResponse header (3) + attr_id (2) + status (1) + type (1) +
        // value (2)
        assert_eq!(n, 9);
        assert_eq!(i16::from_le_bytes([buf[7], buf[8]]), 500i16);
    }
}
