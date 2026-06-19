use crate::cluster_server::ClusterServer;
use crate::cluster_server::CommandResult;
use crate::cluster_server::DispatchContext;
use crate::frame::Status;
use crate::reporting::LatestReportingTable;
use crate::types::bitmaps::Bitmap8;
use crate::types::descriptors::AttrInfo;
use crate::types::descriptors::encode_attr;
use crate::types::enums::Enum8;
use crate::types::enums::OccupancySensorType;
use crate::types::error::AttrError;
use crate::types::error::ZclError;
use crate::types::ids::AttributeId;
use crate::types::ids::ClusterId;
use crate::types::ids::CommandId;
use crate::types::ids::TypeId;

/// ZCL Occupancy Sensing cluster (0x0406).
///
/// All attributes are read-only from ZCL; the application sets values via
/// typed setters.
///
/// `occupancy` is a Bitmap8 where bit 0 = occupied (1) / unoccupied (0).
/// `occupancy_sensor_type_bitmap` is a Bitmap8 where bits 0–2 indicate
/// supported sensor types: bit 0 = PIR, bit 1 = Ultrasonic, bit 2 = Physical
/// Contact.
pub struct OccupancySensingServer {
    /// Attribute 0x0000 — `Occupancy` (Bitmap8, R|REPORTABLE). Bit 0: occupied.
    occupancy: u8,
    /// Attribute 0x0001 — `OccupancySensorType` (Enum8, R).
    occupancy_sensor_type: OccupancySensorType,
    /// Attribute 0x0002 — `OccupancySensorTypeBitmap` (Bitmap8, R).
    occupancy_sensor_type_bitmap: u8,
    reporting: LatestReportingTable<1, 1>,
}

impl OccupancySensingServer {
    pub const fn new(sensor_type: OccupancySensorType, type_bitmap: u8) -> Self {
        Self {
            occupancy: 0,
            occupancy_sensor_type: sensor_type,
            occupancy_sensor_type_bitmap: type_bitmap & 0x07,
            reporting: LatestReportingTable::new(),
        }
    }

    pub fn set_occupied(&mut self, occupied: bool) {
        let new_val = u8::from(occupied);
        if new_val != self.occupancy {
            self.occupancy = new_val;
            self.reporting.note_value_update(AttributeId::new(0x0000));
        }
    }

    pub const fn occupancy(&self) -> u8 {
        self.occupancy
    }

    pub const fn occupancy_sensor_type(&self) -> OccupancySensorType {
        self.occupancy_sensor_type
    }

    pub const fn occupancy_sensor_type_bitmap(&self) -> u8 {
        self.occupancy_sensor_type_bitmap
    }

    pub fn is_occupied(&self) -> bool {
        self.occupancy & 0x01 != 0
    }
}

impl Default for OccupancySensingServer {
    fn default() -> Self {
        Self::new(OccupancySensorType::Pir, 0x01)
    }
}

impl ClusterServer for OccupancySensingServer {
    const CLUSTER_ID: ClusterId = ClusterId::new(0x0406);

    fn read_attribute(
        &self,
        id: AttributeId,
        buf: &mut [u8],
    ) -> Result<(TypeId, usize), AttrError> {
        match id.0 {
            0x0000 => Ok(encode_attr::<Bitmap8<u8>>(self.occupancy, buf)?),
            0x0001 => Ok(encode_attr::<Enum8<OccupancySensorType>>(
                self.occupancy_sensor_type,
                buf,
            )?),
            0x0002 => Ok(encode_attr::<Bitmap8<u8>>(
                self.occupancy_sensor_type_bitmap,
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

    impl_reporting!(reporting, 1);

    read_only_attrs![0x0000..=0x0002 | 0xFFFD];

    fn attribute_list() -> &'static [AttrInfo] {
        attr_list![
            (0x0000, Bitmap8, READ | REPORTABLE),
            (0x0001, Enum8, READ),
            (0x0002, Bitmap8, READ),
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
    fn default_occupancy_is_unoccupied() {
        let server = OccupancySensingServer::default();
        assert!(!server.is_occupied());
        assert_eq!(server.occupancy(), 0x00);
    }

    #[test]
    fn set_occupied_sets_bit_0() {
        let mut server = OccupancySensingServer::default();
        server.set_occupied(true);
        assert!(server.is_occupied());
        assert_eq!(server.occupancy() & 0x01, 0x01);
    }

    #[test]
    fn set_occupied_false_clears_bit_0() {
        let mut server = OccupancySensingServer::default();
        server.set_occupied(true);
        server.set_occupied(false);
        assert!(!server.is_occupied());
        assert_eq!(server.occupancy() & 0x01, 0x00);
    }

    #[test]
    fn occupancy_attr_encodes_as_bitmap8() {
        let mut server = OccupancySensingServer::default();
        server.set_occupied(true);
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Bitmap8);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x01);
    }

    #[test]
    fn sensor_type_attr_encodes_as_enum8() {
        let server = OccupancySensingServer::new(OccupancySensorType::Ultrasonic, 0x02);
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0001), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Enum8);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x01); // Ultrasonic = 0x01
    }

    #[test]
    fn sensor_type_bitmap_attr_encodes_as_bitmap8() {
        let server = OccupancySensingServer::new(OccupancySensorType::Pir, 0x05);
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0002), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Bitmap8);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x05);
    }

    #[test]
    fn constructor_masks_sensor_type_bitmap_to_defined_bits() {
        let server = OccupancySensingServer::new(OccupancySensorType::Pir, 0xFF);
        assert_eq!(server.occupancy_sensor_type_bitmap(), 0x07);
        assert_eq!(server.occupancy_sensor_type(), OccupancySensorType::Pir);
    }

    #[test]
    fn all_mandatory_attributes_readable() {
        let server = OccupancySensingServer::default();
        for attr in [0x0000u16, 0x0001, 0x0002] {
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
        let mut server = OccupancySensingServer::default();
        for attr in [0x0000u16, 0x0001, 0x0002] {
            assert_eq!(
                server.write_attribute(AttributeId::new(attr), TypeId::Bitmap8, &[0x00]),
                Err(AttrError::ReadOnly)
            );
        }
    }

    #[test]
    fn unknown_attribute_returns_unsupported() {
        let server = OccupancySensingServer::default();
        let mut buf = [0u8; 4];
        assert_eq!(
            server.read_attribute(AttributeId::new(0xFFFF), &mut buf),
            Err(AttrError::UnsupportedAttribute)
        );
    }

    #[test]
    fn attribute_list_occupancy_is_reportable() {
        let attrs = OccupancySensingServer::attribute_list();
        assert_eq!(attrs[0].id, AttributeId::new(0x0000));
        assert!(attrs[0].access.is_reportable());
    }

    #[test]
    fn attribute_list_has_three_entries() {
        assert_eq!(OccupancySensingServer::attribute_list().len(), 4);
    }

    #[test]
    fn dispatch_read_occupancy_unoccupied() {
        let req: &[u8] = &[0x00, 0x01, 0x00, 0x00, 0x00];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = OccupancySensingServer::default();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + attr_id(2) + status(1) + type_id(1) + value(1) = 8
        assert_eq!(n, 8);
        assert_eq!(buf[5], 0x00); // Success
        assert_eq!(buf[6], TypeId::Bitmap8.as_u8());
        assert_eq!(buf[7], 0x00); // unoccupied
    }

    #[test]
    fn configure_reporting_occupancy_returns_success() {
        let mut server = OccupancySensingServer::default();
        let record = send_record(0x0000, TypeId::Bitmap8.as_u8(), 0, 30);
        assert_eq!(
            server.configure_reporting(record, unicast_with_source()),
            Status::Success
        );
    }

    #[test]
    fn collect_reports_after_set_occupied() {
        let mut server = OccupancySensingServer::default();
        let record = send_record(0x0000, TypeId::Bitmap8.as_u8(), 0, 30);
        server.configure_reporting(record, unicast_with_source());
        server.set_occupied(true);

        let mut buf = [0u8; 32];
        let mut writer = ReportPayloadWriter::new(&mut buf);
        let ready = server.collect_reports(0, &mut writer).unwrap();
        assert!(ready.is_some());
        // attr_id(2) + type_id(1) + value(1) = 4 bytes
        assert_eq!(writer.len(), 4);
        assert_eq!(buf[3], 0x01); // occupied
    }

    #[test]
    fn report_delivery_result_sent_clears_pending() {
        let mut server = OccupancySensingServer::default();
        let record = send_record(0x0000, TypeId::Bitmap8.as_u8(), 0, 30);
        server.configure_reporting(record, unicast_with_source());
        server.set_occupied(true);

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
