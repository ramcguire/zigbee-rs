use crate::cluster_server::ClusterServer;
use crate::cluster_server::CommandResult;
use crate::cluster_server::DispatchContext;
use crate::frame::Status;
use crate::types::bitmaps::Bitmap8;
use crate::types::descriptors::AttrInfo;
use crate::types::descriptors::decode_attr;
use crate::types::descriptors::encode_attr;
use crate::types::error::AttrError;
use crate::types::error::ZclError;
use crate::types::ids::AttributeId;
use crate::types::ids::ClusterId;
use crate::types::ids::CommandId;
use crate::types::ids::TypeId;

/// ZCL Time cluster (0x000A).
///
/// All attributes are R/W from ZCL. The application also sets values via typed
/// setters. No reporting is defined for this cluster.
pub struct TimeServer {
    /// Attr 0x0000 — `Time` (Uint32, R/W). UTC time in seconds since
    /// 2000-01-01.
    pub time: u32,
    /// Attr 0x0001 — `TimeStatus` (Bitmap8, R/W). Bit 0: master; bit 1:
    /// synchronized.
    pub time_status: u8,
    /// Attr 0x0002 — `TimeZone` (Int32, R/W). Offset in seconds from UTC.
    pub time_zone: i32,
}

impl TimeServer {
    pub const fn new() -> Self {
        Self {
            time: 0,
            time_status: 0,
            time_zone: 0,
        }
    }

    pub fn set_time(&mut self, v: u32) {
        self.time = v;
    }

    pub fn set_time_status(&mut self, v: u8) {
        self.time_status = v;
    }

    pub fn set_time_zone(&mut self, v: i32) {
        self.time_zone = v;
    }
}

impl Default for TimeServer {
    fn default() -> Self {
        Self::new()
    }
}

impl ClusterServer for TimeServer {
    const CLUSTER_ID: ClusterId = ClusterId::new(0x000A);

    fn read_attribute(
        &self,
        id: AttributeId,
        buf: &mut [u8],
    ) -> Result<(TypeId, usize), AttrError> {
        match id.0 {
            0x0000 => Ok(encode_attr::<u32>(self.time, buf)?),
            0x0001 => Ok(encode_attr::<Bitmap8<u8>>(self.time_status, buf)?),
            0x0002 => Ok(encode_attr::<i32>(self.time_zone, buf)?),
            0xFFFD => Ok(encode_attr::<u16>(2, buf)?),
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
            0x0000 => decode_attr::<u32>(type_id, data).map(|_| ()),
            0x0001 => decode_attr::<Bitmap8<u8>>(type_id, data).map(|_| ()),
            0x0002 => decode_attr::<i32>(type_id, data).map(|_| ()),
            0xFFFD => Err(AttrError::ReadOnly),
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
            0x0000 => {
                self.time = decode_attr::<u32>(type_id, data)?;
                Ok(())
            }
            0x0001 => {
                self.time_status = decode_attr::<Bitmap8<u8>>(type_id, data)?;
                Ok(())
            }
            0x0002 => {
                self.time_zone = decode_attr::<i32>(type_id, data)?;
                Ok(())
            }
            0xFFFD => Err(AttrError::ReadOnly),
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

    fn attribute_list() -> &'static [AttrInfo] {
        attr_list![
            (0x0000, Uint32, READ | WRITE),
            (0x0001, Bitmap8, READ | WRITE),
            (0x0002, Int32, READ | WRITE),
            (0xFFFD, Uint16, READ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_server::DispatchContext;
    use crate::cluster_server::zcl_cluster_dispatch;
    use crate::frame::IncomingZclFrame;

    fn unicast() -> DispatchContext {
        DispatchContext::unicast(0, None)
    }

    // --- attribute reads ---

    #[test]
    fn time_reads_as_uint32() {
        let mut server = TimeServer::new();
        server.set_time(946_684_800); // 2000-01-01 in unix epoch
        let mut buf = [0u8; 8];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint32);
        assert_eq!(n, 4);
        assert_eq!(
            u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            946_684_800
        );
    }

    #[test]
    fn time_status_reads_as_bitmap8() {
        let mut server = TimeServer::new();
        server.set_time_status(0x03); // master + synchronized
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0001), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Bitmap8);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x03);
    }

    #[test]
    fn time_zone_reads_as_int32() {
        let mut server = TimeServer::new();
        server.set_time_zone(3600); // UTC+1
        let mut buf = [0u8; 8];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0002), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Int32);
        assert_eq!(n, 4);
        assert_eq!(i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), 3600);
    }

    #[test]
    fn time_zone_negative_reads_correctly() {
        let mut server = TimeServer::new();
        server.set_time_zone(-18000); // UTC-5
        let mut buf = [0u8; 8];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0002), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Int32);
        assert_eq!(n, 4);
        assert_eq!(i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), -18000);
    }

    #[test]
    fn all_mandatory_attributes_readable() {
        let server = TimeServer::new();
        for attr in [0x0000u16, 0x0001, 0x0002] {
            let mut buf = [0u8; 8];
            assert!(
                server
                    .read_attribute(AttributeId::new(attr), &mut buf)
                    .is_ok(),
                "attr 0x{attr:04X} not readable"
            );
        }
    }

    #[test]
    fn unknown_attribute_returns_unsupported() {
        let server = TimeServer::new();
        let mut buf = [0u8; 8];
        assert_eq!(
            server.read_attribute(AttributeId::new(0xFFFF), &mut buf),
            Err(AttrError::UnsupportedAttribute)
        );
    }

    // --- attribute writes ---

    #[test]
    fn write_time_stores_value() {
        let mut server = TimeServer::new();
        let val: u32 = 12345;
        let data = val.to_le_bytes();
        server
            .write_attribute(AttributeId::new(0x0000), TypeId::Uint32, &data)
            .unwrap();
        assert_eq!(server.time, 12345);
    }

    #[test]
    fn write_time_status_stores_value() {
        let mut server = TimeServer::new();
        server
            .write_attribute(AttributeId::new(0x0001), TypeId::Bitmap8, &[0x01])
            .unwrap();
        assert_eq!(server.time_status, 0x01);
    }

    #[test]
    fn write_time_zone_stores_value() {
        let mut server = TimeServer::new();
        let val: i32 = -7200;
        let data = val.to_le_bytes();
        server
            .write_attribute(AttributeId::new(0x0002), TypeId::Int32, &data)
            .unwrap();
        assert_eq!(server.time_zone, -7200);
    }

    #[test]
    fn write_wrong_type_returns_invalid_data_type() {
        let mut server = TimeServer::new();
        assert_eq!(
            server.write_attribute(AttributeId::new(0x0000), TypeId::Uint16, &[0x01, 0x00]),
            Err(AttrError::InvalidDataType)
        );
    }

    #[test]
    fn write_unknown_attr_returns_unsupported() {
        let mut server = TimeServer::new();
        assert_eq!(
            server.write_attribute(AttributeId::new(0xFFFF), TypeId::Uint32, &[0u8; 4]),
            Err(AttrError::UnsupportedAttribute)
        );
    }

    // --- attribute_list ---

    #[test]
    fn attribute_list_has_four_entries() {
        assert_eq!(TimeServer::attribute_list().len(), 4);
    }

    #[test]
    fn attribute_list_normal_attrs_read_write_cluster_revision_read_only() {
        for info in &TimeServer::attribute_list()[..3] {
            assert!(
                info.access.is_readable(),
                "attr 0x{:04X} not readable",
                info.id.0
            );
            assert!(
                info.access.is_writable(),
                "attr 0x{:04X} not writable",
                info.id.0
            );
        }
        let rev = TimeServer::attribute_list()[3];
        assert!(rev.access.is_readable());
        assert!(!rev.access.is_writable());
    }

    #[test]
    fn attribute_list_time_zone_is_int32() {
        let attrs = TimeServer::attribute_list();
        let tz = attrs
            .iter()
            .find(|a| a.id == AttributeId::new(0x0002))
            .unwrap();
        assert_eq!(tz.type_id, TypeId::Int32);
    }

    #[test]
    fn cluster_revision_reads_rev8_value_and_is_read_only() {
        let mut server = TimeServer::new();
        let mut buf = [0u8; 4];
        let (type_id, n) = server
            .read_attribute(AttributeId::new(0xFFFD), &mut buf)
            .unwrap();
        assert_eq!(type_id, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 2);
        assert_eq!(
            server.write_attribute(AttributeId::new(0xFFFD), TypeId::Uint16, &[2, 0]),
            Err(AttrError::ReadOnly)
        );
    }
    // --- dispatch ---

    #[test]
    fn dispatch_read_time() {
        let req: &[u8] = &[
            0x00, 0x01, 0x00, // ReadAttributes, seq=1
            0x00, 0x00, // attr 0x0000
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TimeServer::new();
        server.set_time(3600);
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + attr_id(2) + status(1) + type_id(1) + value(4) = 11
        assert_eq!(n, 11);
        assert_eq!(buf[5], 0x00); // Success
        assert_eq!(buf[6], TypeId::Uint32.as_u8());
        assert_eq!(u32::from_le_bytes([buf[7], buf[8], buf[9], buf[10]]), 3600);
    }

    #[test]
    fn dispatch_write_time() {
        let time_val: u32 = 7200;
        let bytes = time_val.to_le_bytes();
        let req: &[u8] = &[
            0x00, 0x01, 0x02, // WriteAttributes, seq=1
            0x00, 0x00, // attr 0x0000
            0x23, // Uint32 type id
            bytes[0], bytes[1], bytes[2], bytes[3],
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TimeServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + status(1) = 4 (all success)
        assert_eq!(n, 4);
        assert_eq!(buf[3], Status::Success as u8);
        assert_eq!(server.time, 7200);
    }

    #[test]
    fn dispatch_write_time_wrong_type_returns_invalid_data_type() {
        let req: &[u8] = &[
            0x00, 0x01, 0x02, // WriteAttributes, seq=1
            0x00, 0x00, // attr 0x0000
            0x29, // Int16 type id (wrong for Uint32)
            0x00, 0x00,
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TimeServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + status(1) + attr_id(2) = 6
        assert_eq!(n, 6);
        assert_ne!(buf[3], Status::Success as u8);
    }
}
