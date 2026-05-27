use core::cell::Cell;

use crate::attribute_store::AttrDescriptor;
use crate::attribute_store::SplitAttributeStore;
use crate::attribute_store::StorageKind;
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

/// Static configuration for the ZCL Basic cluster (0x0000).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BasicConfig {
    /// Attribute 0x0000 — `ZCLVersion`.
    pub zcl_version: u8,
    /// Attribute 0x0004 — `ManufacturerName`.
    pub manufacturer_name: &'static str,
    /// Attribute 0x0005 — `ModelIdentifier`.
    pub model_identifier: &'static str,
    /// Attribute 0x0007 — `PowerSource`.
    pub power_source: u8,
    /// Attribute 0x0012 — `DeviceEnabled` initial value.
    pub device_enabled: bool,
}

impl BasicConfig {
    pub const fn new(
        zcl_version: u8,
        manufacturer_name: &'static str,
        model_identifier: &'static str,
        power_source: u8,
        device_enabled: bool,
    ) -> Self {
        Self {
            zcl_version,
            manufacturer_name,
            model_identifier,
            power_source,
            device_enabled,
        }
    }
}

/// ZCL Basic cluster (0x0000).
///
/// Static strings/scalars are supplied through [`BasicConfig`]. `DeviceEnabled`
/// is mutable and persists across ZCL writes.
pub struct BasicServer {
    zcl_version: u8,
    manufacturer_name: &'static str,
    model_identifier: &'static str,
    power_source: u8,
    device_enabled: SplitAttributeStore<1>,
}

static DEVICE_ENABLED_ATTRS: &[AttrDescriptor] = &[AttrDescriptor {
    attr: AttributeId::new(0x0012),
    access: AccessFlags::READ_WRITE,
    type_id: TypeId::Boolean,
    storage: StorageKind::MutableScalar { index: 0 },
}];

const _: () = assert!(crate::attribute_store::is_sorted(DEVICE_ENABLED_ATTRS));
const _: () = assert!(crate::attribute_store::has_no_duplicate_keys(
    DEVICE_ENABLED_ATTRS
));

impl BasicServer {
    /// Construct a new `BasicServer` without exposing the internal attribute
    /// storage representation.
    pub fn new(config: BasicConfig) -> Self {
        Self {
            zcl_version: config.zcl_version,
            manufacturer_name: config.manufacturer_name,
            model_identifier: config.model_identifier,
            power_source: config.power_source,
            device_enabled: SplitAttributeStore::new(
                DEVICE_ENABLED_ATTRS,
                [Cell::new(u64::from(config.device_enabled))],
            ),
        }
    }

    pub fn device_enabled(&self) -> bool {
        let mut buf = [0u8; 1];
        self.device_enabled
            .read_into(AttributeId::new(0x0012), &mut buf)
            .is_ok_and(|(_, n)| n == 1 && buf[0] == 0x01)
    }

    pub fn set_device_enabled(&mut self, enabled: bool) {
        let _ = self.device_enabled.write_from(
            AttributeId::new(0x0012),
            TypeId::Boolean,
            &[u8::from(enabled)],
        );
    }
}

fn encode_short_text(s: &str, buf: &mut [u8]) -> Result<(TypeId, usize), AttrError> {
    let raw = s.as_bytes();
    let len = raw.len();
    if len > 254 {
        return Err(AttrError::Codec(ZclError::InvalidLength));
    }
    let total = 1 + len;
    if buf.len() < total {
        return Err(AttrError::Codec(ZclError::BufferTooSmall));
    }
    #[allow(clippy::cast_possible_truncation)] // len <= 254 checked above
    let len_byte = len as u8;
    buf[0] = len_byte;
    buf[1..total].copy_from_slice(raw);
    Ok((TypeId::CharacterString, total))
}

impl ClusterServer for BasicServer {
    const CLUSTER_ID: ClusterId = ClusterId::new(0x0000);

    fn read_attribute(
        &self,
        id: AttributeId,
        buf: &mut [u8],
    ) -> Result<(TypeId, usize), AttrError> {
        match id.0 {
            0x0000 => Ok(encode_attr::<u8>(self.zcl_version, buf)?),
            0x0004 => encode_short_text(self.manufacturer_name, buf),
            0x0005 => encode_short_text(self.model_identifier, buf),
            0x0007 => Ok(encode_attr::<u8>(self.power_source, buf)?),
            0x0012 => self.device_enabled.read_into(id, buf),
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }

    fn check_write_attribute(
        &self,
        id: AttributeId,
        type_id: TypeId,
        data: &[u8],
    ) -> Result<(), AttrError> {
        match id.0 {
            0x0012 => self.device_enabled.check_write_from(id, type_id, data),
            0x0000 | 0x0004 | 0x0005 | 0x0007 => Err(AttrError::ReadOnly),
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
            0x0012 => self.device_enabled.write_from(id, type_id, data),
            0x0000 | 0x0004 | 0x0005 | 0x0007 => Err(AttrError::ReadOnly),
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }

    fn handle_command(
        &mut self,
        _id: CommandId,
        _payload: &[u8],
        _buf: &mut [u8],
    ) -> Result<CommandResult, ZclError> {
        // Basic cluster has no mandatory commands (ResetToFactoryDefaults 0x00 is
        // optional).
        Ok(CommandResult::DefaultResponse(Status::UnsupCommand))
    }

    fn attribute_list() -> &'static [AttrInfo] {
        static LIST: [AttrInfo; 5] = [
            AttrInfo {
                id: AttributeId::new(0x0000),
                type_id: TypeId::Uint8,
                access: AccessFlags::READ,
            },
            AttrInfo {
                id: AttributeId::new(0x0004),
                type_id: TypeId::CharacterString,
                access: AccessFlags::READ,
            },
            AttrInfo {
                id: AttributeId::new(0x0005),
                type_id: TypeId::CharacterString,
                access: AccessFlags::READ,
            },
            AttrInfo {
                id: AttributeId::new(0x0007),
                type_id: TypeId::Uint8,
                access: AccessFlags::READ,
            },
            AttrInfo {
                id: AttributeId::new(0x0012),
                type_id: TypeId::Boolean,
                access: AccessFlags::READ_WRITE,
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

    fn make_server(device_enabled: bool) -> BasicServer {
        BasicServer::new(BasicConfig::new(
            3,
            "ACME",
            "Sensor-1",
            0x01,
            device_enabled,
        ))
    }

    fn unicast() -> DispatchContext {
        DispatchContext {
            delivery: DeliveryMode::Unicast,
        }
    }

    #[test]
    fn zcl_version_reads_as_3() {
        let server = make_server(true);
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint8);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 3);
    }

    #[test]
    fn manufacturer_name_reads_correct_string() {
        let server = make_server(true);
        let mut buf = [0u8; 32];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0004), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::CharacterString);
        assert_eq!(n, 5);
        assert_eq!(buf[0], 4);
        assert_eq!(&buf[1..5], b"ACME");
    }

    #[test]
    fn model_identifier_reads_correct_string() {
        let server = make_server(true);
        let mut buf = [0u8; 32];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0005), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::CharacterString);
        assert_eq!(n, 9);
        assert_eq!(&buf[1..n], b"Sensor-1");
    }

    #[test]
    fn power_source_reads_correctly() {
        let server = make_server(true);
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0007), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint8);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x01);
    }

    #[test]
    fn device_enabled_initially_true_and_readable() {
        let server = make_server(true);
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0012), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Boolean);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x01);
    }

    #[test]
    fn device_enabled_initially_false() {
        let server = make_server(false);
        let mut buf = [0u8; 4];
        let (_, _) = server
            .read_attribute(AttributeId::new(0x0012), &mut buf)
            .unwrap();
        assert_eq!(buf[0], 0x00);
    }

    #[test]
    fn device_enabled_write_persists() {
        let mut server = make_server(false);
        server
            .write_attribute(AttributeId::new(0x0012), TypeId::Boolean, &[0x01])
            .unwrap();
        let mut buf = [0u8; 4];
        let (_, n) = server
            .read_attribute(AttributeId::new(0x0012), &mut buf)
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x01);
        assert!(server.device_enabled());
    }

    #[test]
    fn device_enabled_rejects_invalid_boolean() {
        let mut server = make_server(false);
        assert_eq!(
            server.write_attribute(AttributeId::new(0x0012), TypeId::Boolean, &[0x02]),
            Err(AttrError::Codec(ZclError::InvalidValue))
        );
        assert!(!server.device_enabled());
    }

    #[test]
    fn zcl_version_write_returns_read_only() {
        let mut server = make_server(true);
        assert_eq!(
            server.write_attribute(AttributeId::new(0x0000), TypeId::Uint8, &[4]),
            Err(AttrError::ReadOnly)
        );
    }

    #[test]
    fn unknown_attribute_returns_unsupported() {
        let server = make_server(true);
        let mut buf = [0u8; 4];
        assert_eq!(
            server.read_attribute(AttributeId::new(0xFFFF), &mut buf),
            Err(AttrError::UnsupportedAttribute)
        );
    }

    #[test]
    fn attribute_list_includes_basic_attrs() {
        let attrs = BasicServer::attribute_list();
        assert_eq!(attrs.len(), 5);
        assert_eq!(attrs[0].id, AttributeId::new(0x0000));
        assert_eq!(attrs[1].id, AttributeId::new(0x0004));
        assert_eq!(attrs[2].id, AttributeId::new(0x0005));
        assert_eq!(attrs[3].id, AttributeId::new(0x0007));
        assert_eq!(attrs[4].id, AttributeId::new(0x0012));
    }

    #[test]
    fn dispatch_read_zcl_version_via_frame() {
        let req: &[u8] = &[0x00, 0x01, 0x00, 0x00, 0x00];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = make_server(true);
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf).unwrap();

        assert_eq!(n, 8);
        assert_eq!(buf[5], 0x00);
        assert_eq!(buf[7], 3);
    }

    #[test]
    fn dispatch_write_device_enabled_via_frame() {
        let req: &[u8] = &[0x00, 0x02, 0x02, 0x12, 0x00, 0x10, 0x01];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = make_server(false);
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf).unwrap();

        assert_eq!(n, 4);
        assert_eq!(buf[3], Status::Success as u8);

        let mut rbuf = [0u8; 4];
        server
            .read_attribute(AttributeId::new(0x0012), &mut rbuf)
            .unwrap();
        assert_eq!(rbuf[0], 0x01);
    }

    #[test]
    fn discover_attributes_lists_basic_attrs() {
        let req: &[u8] = &[0x00, 0x03, 0x0c, 0x00, 0x00, 0xFF];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = make_server(false);
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf).unwrap();

        assert_eq!(n, 19);
        assert_eq!(buf[2], 0x0d);
        assert_eq!(buf[3], 0x01);
        assert_eq!(&buf[4..7], &[0x00, 0x00, TypeId::Uint8.as_u8()]);
        assert_eq!(&buf[16..19], &[0x12, 0x00, TypeId::Boolean.as_u8()]);
    }
}
