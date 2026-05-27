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

/// ZCL Temperature Measurement cluster (0x0402), Strategy 1.
///
/// All attributes are read-only from ZCL; the application sets values via the
/// typed setters. `None` encodes as the ZCL null sentinel `0x8000`
/// (`i16::MIN`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemperatureMeasurementServer {
    /// Attribute 0x0000 — `MeasuredValue` (Int16, nullable).
    pub measured_value: Option<i16>,
    /// Attribute 0x0001 — `MinMeasuredValue` (Int16, nullable).
    pub min_measured_value: Option<i16>,
    /// Attribute 0x0002 — `MaxMeasuredValue` (Int16, nullable).
    pub max_measured_value: Option<i16>,
    /// Attribute 0x0003 — `Tolerance` (Uint16).
    pub tolerance: u16,
}

impl TemperatureMeasurementServer {
    pub const fn new() -> Self {
        Self {
            measured_value: None,
            min_measured_value: None,
            max_measured_value: None,
            tolerance: 0,
        }
    }

    pub fn set_measured_value(&mut self, v: Option<i16>) {
        self.measured_value = v;
    }

    pub fn set_min_measured_value(&mut self, v: Option<i16>) {
        self.min_measured_value = v;
    }

    pub fn set_max_measured_value(&mut self, v: Option<i16>) {
        self.max_measured_value = v;
    }

    pub fn set_tolerance(&mut self, v: u16) {
        self.tolerance = v;
    }
}

impl Default for TemperatureMeasurementServer {
    fn default() -> Self {
        Self::new()
    }
}

impl ClusterServer for TemperatureMeasurementServer {
    const CLUSTER_ID: ClusterId = ClusterId::new(0x0402);

    fn read_attribute(
        &self,
        id: AttributeId,
        buf: &mut [u8],
    ) -> Result<(TypeId, usize), AttrError> {
        match id.0 {
            0x0000 => Ok(encode_attr::<Nullable<i16>>(self.measured_value, buf)?),
            0x0001 => Ok(encode_attr::<Nullable<i16>>(self.min_measured_value, buf)?),
            0x0002 => Ok(encode_attr::<Nullable<i16>>(self.max_measured_value, buf)?),
            0x0003 => Ok(encode_attr::<u16>(self.tolerance, buf)?),
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
            0x0000..=0x0003 => Err(AttrError::ReadOnly),
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
            0x0000..=0x0003 => Err(AttrError::ReadOnly),
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }

    fn handle_command(
        &mut self,
        _id: CommandId,
        _payload: &[u8],
        _buf: &mut [u8],
    ) -> Result<CommandResult, ZclError> {
        Ok(CommandResult::DefaultResponse(Status::UnsupCommand))
    }

    fn attribute_list() -> &'static [AttrInfo] {
        static LIST: [AttrInfo; 4] = [
            AttrInfo {
                id: AttributeId::new(0x0000),
                type_id: TypeId::Int16,
                access: AccessFlags::READ,
            },
            AttrInfo {
                id: AttributeId::new(0x0001),
                type_id: TypeId::Int16,
                access: AccessFlags::READ,
            },
            AttrInfo {
                id: AttributeId::new(0x0002),
                type_id: TypeId::Int16,
                access: AccessFlags::READ,
            },
            AttrInfo {
                id: AttributeId::new(0x0003),
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
        server.set_measured_value(Some(-2500)); // -25.00°C in ZCL units (100ths)
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
        server.set_measured_value(Some(2000));
        server.set_min_measured_value(Some(-4000));
        server.set_max_measured_value(Some(8500));

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
        server.set_tolerance(25);
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
        assert_eq!(attrs.len(), 4);
        assert_eq!(attrs[3].id, AttributeId::new(0x0003));
        assert_eq!(attrs[3].type_id, TypeId::Uint16);
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
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf).unwrap();

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
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf).unwrap();

        // header(3) + status(1) + attr_id(2) = 6
        assert_eq!(n, 6);
        assert_eq!(buf[3], Status::ReadOnly as u8);
    }
}
