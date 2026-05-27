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

/// ZCL Pressure Measurement cluster (0x0403), Strategy 1.
///
/// All attributes are read-only from ZCL; the application sets values via the
/// typed setters. `None` encodes as the ZCL null sentinel `0x8000`
/// (`i16::MIN`). Values are in units of 0.1 kPa (e.g. `1013` = 101.3 kPa).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PressureMeasurementServer {
    /// Attribute 0x0000 — `MeasuredValue` (Int16, nullable).
    pub measured_value: Option<i16>,
    /// Attribute 0x0001 — `MinMeasuredValue` (Int16, nullable).
    pub min_measured_value: Option<i16>,
    /// Attribute 0x0002 — `MaxMeasuredValue` (Int16, nullable).
    pub max_measured_value: Option<i16>,
    /// Attribute 0x0003 — `Tolerance` (Uint16).
    pub tolerance: u16,
}

impl PressureMeasurementServer {
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

impl Default for PressureMeasurementServer {
    fn default() -> Self {
        Self::new()
    }
}

impl ClusterServer for PressureMeasurementServer {
    const CLUSTER_ID: ClusterId = ClusterId::new(0x0403);

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

    fn unicast() -> DispatchContext {
        DispatchContext {
            delivery: DeliveryMode::Unicast,
        }
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
        server.set_measured_value(Some(1013)); // 101.3 kPa
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
        server.set_tolerance(5);
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
        server.set_measured_value(Some(500)); // 50.0 kPa
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf).unwrap();
        // ReadAttributesResponse header (3) + attr_id (2) + status (1) + type (1) +
        // value (2)
        assert_eq!(n, 9);
        assert_eq!(i16::from_le_bytes([buf[7], buf[8]]), 500i16);
    }
}
