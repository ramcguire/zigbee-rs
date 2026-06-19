use crate::cluster_server::ClusterServer;
use crate::cluster_server::CommandResult;
use crate::cluster_server::DispatchContext;
use crate::frame::Status;
use crate::reporting::LatestReportingTable;
use crate::types::bitmaps::Bitmap32;
use crate::types::descriptors::AttrInfo;
use crate::types::descriptors::encode_attr;
use crate::types::error::AttrError;
use crate::types::error::ZclError;
use crate::types::ids::AttributeId;
use crate::types::ids::ClusterId;
use crate::types::ids::CommandId;
use crate::types::ids::TypeId;

/// ZCL Electrical Measurement cluster (0x0B04).
///
/// All attributes are read-only from ZCL; the application sets values via
/// typed setters. `active_power` is reportable.
pub struct ElectricalMeasurementServer {
    /// Attr 0x0000 — `MeasurementType` (Bitmap32, R). Bitmask indicating AC/DC
    /// type.
    measurement_type: u32,
    /// Attr 0x0505 — `RMSVoltage` (Uint16, R). Units: V (default multiplier 1).
    rms_voltage: u16,
    /// Attr 0x0508 — `RMSCurrent` (Uint16, R). Units: A (default multiplier
    /// 0.001).
    rms_current: u16,
    /// Attr 0x050B — `ActivePower` (Int16, R|REPORTABLE). Units: W.
    active_power: i16,
    /// Attr 0x0510 — `PowerFactor` (Int8, R). Range: -100 to 100.
    power_factor: i8,
    reporting: LatestReportingTable<1, 2>,
}

pub trait NullableU16Input {
    fn into_nullable_u16(self) -> Option<u16>;
}

impl NullableU16Input for u16 {
    fn into_nullable_u16(self) -> Option<u16> {
        Some(self)
    }
}

impl NullableU16Input for Option<u16> {
    fn into_nullable_u16(self) -> Option<u16> {
        self
    }
}

pub trait NullableI16Input {
    fn into_nullable_i16(self) -> Option<i16>;
}

impl NullableI16Input for i16 {
    fn into_nullable_i16(self) -> Option<i16> {
        Some(self)
    }
}

impl NullableI16Input for Option<i16> {
    fn into_nullable_i16(self) -> Option<i16> {
        self
    }
}

pub trait NullableI8Input {
    fn into_nullable_i8(self) -> Option<i8>;
}

impl NullableI8Input for i8 {
    fn into_nullable_i8(self) -> Option<i8> {
        Some(self)
    }
}

impl NullableI8Input for Option<i8> {
    fn into_nullable_i8(self) -> Option<i8> {
        self
    }
}

fn encode_u16_allowing_null(value: u16, buf: &mut [u8]) -> Result<(TypeId, usize), AttrError> {
    let out = buf
        .get_mut(..2)
        .ok_or(AttrError::Codec(ZclError::BufferTooSmall))?;
    out.copy_from_slice(&value.to_le_bytes());
    Ok((TypeId::Uint16, 2))
}

fn encode_i16_allowing_null(value: i16, buf: &mut [u8]) -> Result<(TypeId, usize), AttrError> {
    let out = buf
        .get_mut(..2)
        .ok_or(AttrError::Codec(ZclError::BufferTooSmall))?;
    out.copy_from_slice(&value.to_le_bytes());
    Ok((TypeId::Int16, 2))
}

fn encode_i8_allowing_null(value: i8, buf: &mut [u8]) -> Result<(TypeId, usize), AttrError> {
    let out = buf
        .first_mut()
        .ok_or(AttrError::Codec(ZclError::BufferTooSmall))?;
    *out = value.cast_unsigned();
    Ok((TypeId::Int8, 1))
}

impl ElectricalMeasurementServer {
    const MEASUREMENT_TYPE_SINGLE_PHASE_AC: u32 = 0x0000_0008;
    const UNKNOWN_U16: u16 = 0xFFFF;
    const UNKNOWN_I16: i16 = i16::MIN;
    const UNKNOWN_I8: i8 = i8::MIN;

    pub const fn new() -> Self {
        Self {
            measurement_type: Self::MEASUREMENT_TYPE_SINGLE_PHASE_AC,
            rms_voltage: Self::UNKNOWN_U16,
            rms_current: Self::UNKNOWN_U16,
            active_power: Self::UNKNOWN_I16,
            power_factor: Self::UNKNOWN_I8,
            reporting: LatestReportingTable::new(),
        }
    }

    pub const fn measurement_type(&self) -> u32 {
        self.measurement_type
    }

    pub const fn rms_voltage(&self) -> Option<u16> {
        if self.rms_voltage == Self::UNKNOWN_U16 {
            None
        } else {
            Some(self.rms_voltage)
        }
    }

    pub const fn rms_current(&self) -> Option<u16> {
        if self.rms_current == Self::UNKNOWN_U16 {
            None
        } else {
            Some(self.rms_current)
        }
    }

    pub const fn active_power(&self) -> Option<i16> {
        if self.active_power == Self::UNKNOWN_I16 {
            None
        } else {
            Some(self.active_power)
        }
    }

    pub const fn power_factor(&self) -> Option<i8> {
        if self.power_factor == Self::UNKNOWN_I8 {
            None
        } else {
            Some(self.power_factor)
        }
    }

    pub fn set_measurement_type(&mut self, v: u32) {
        self.measurement_type = v;
    }

    pub fn set_rms_voltage(&mut self, v: impl NullableU16Input) {
        self.rms_voltage = v.into_nullable_u16().unwrap_or(Self::UNKNOWN_U16);
    }

    pub fn set_rms_current(&mut self, v: impl NullableU16Input) {
        self.rms_current = v.into_nullable_u16().unwrap_or(Self::UNKNOWN_U16);
    }

    pub fn set_active_power(&mut self, v: impl NullableI16Input) {
        self.active_power = v.into_nullable_i16().unwrap_or(Self::UNKNOWN_I16);
        self.reporting.note_value_update(AttributeId::new(0x050B));
    }

    pub fn set_power_factor(&mut self, v: impl NullableI8Input) {
        self.power_factor = v.into_nullable_i8().unwrap_or(Self::UNKNOWN_I8);
    }
}

impl Default for ElectricalMeasurementServer {
    fn default() -> Self {
        Self::new()
    }
}

impl ClusterServer for ElectricalMeasurementServer {
    const CLUSTER_ID: ClusterId = ClusterId::new(0x0B04);

    fn read_attribute(
        &self,
        id: AttributeId,
        buf: &mut [u8],
    ) -> Result<(TypeId, usize), AttrError> {
        match id.0 {
            0x0000 => Ok(encode_attr::<Bitmap32<u32>>(self.measurement_type, buf)?),
            0x0505 => encode_u16_allowing_null(self.rms_voltage, buf),
            0x0508 => encode_u16_allowing_null(self.rms_current, buf),
            0x050B => encode_i16_allowing_null(self.active_power, buf),
            0x0510 => encode_i8_allowing_null(self.power_factor, buf),
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

    read_only_attrs![0x0000 | 0x0505 | 0x0508 | 0x050B | 0x0510 | 0xFFFD];

    fn attribute_list() -> &'static [AttrInfo] {
        attr_list![
            (0x0000, Bitmap32, READ),
            (0x0505, Uint16, READ),
            (0x0508, Uint16, READ),
            (0x050B, Int16, READ | REPORTABLE),
            (0x0510, Int8, READ),
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

    // --- attribute reads ---

    #[test]
    fn measurement_type_reads_as_bitmap32() {
        let server = ElectricalMeasurementServer::new();
        assert_eq!(server.measurement_type(), 0x0000_0008);
        let mut buf = [0u8; 8];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Bitmap32);
        assert_eq!(n, 4);
        assert_eq!(
            u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            0x0000_0008
        );
    }

    #[test]
    fn defaults_use_unknown_null_sentinels() {
        let server = ElectricalMeasurementServer::new();
        assert_eq!(server.rms_voltage(), None);
        assert_eq!(server.rms_current(), None);
        assert_eq!(server.active_power(), None);
        assert_eq!(server.power_factor(), None);

        let mut buf = [0u8; 8];
        server
            .read_attribute(AttributeId::new(0x0505), &mut buf)
            .unwrap();
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 0xFFFF);
        server
            .read_attribute(AttributeId::new(0x0508), &mut buf)
            .unwrap();
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 0xFFFF);
        server
            .read_attribute(AttributeId::new(0x050B), &mut buf)
            .unwrap();
        assert_eq!(i16::from_le_bytes([buf[0], buf[1]]), i16::MIN);
        server
            .read_attribute(AttributeId::new(0x0510), &mut buf)
            .unwrap();
        assert_eq!(i8::from_le_bytes([buf[0]]), i8::MIN);
    }

    #[test]
    fn rms_voltage_reads_as_uint16() {
        let mut server = ElectricalMeasurementServer::new();
        server.set_rms_voltage(Some(230));
        assert_eq!(server.rms_voltage(), Some(230));
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0505), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 230);
    }

    #[test]
    fn rms_current_reads_as_uint16() {
        let mut server = ElectricalMeasurementServer::new();
        server.set_rms_current(Some(1500)); // 1.5 A with default multiplier 0.001
        assert_eq!(server.rms_current(), Some(1500));
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0508), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 1500);
    }

    #[test]
    fn active_power_reads_as_int16() {
        let mut server = ElectricalMeasurementServer::new();
        server.set_active_power(Some(350));
        assert_eq!(server.active_power(), Some(350));
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x050B), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Int16);
        assert_eq!(n, 2);
        assert_eq!(i16::from_le_bytes([buf[0], buf[1]]), 350);
    }

    #[test]
    fn power_factor_reads_as_int8() {
        let mut server = ElectricalMeasurementServer::new();
        server.set_power_factor(Some(95));
        assert_eq!(server.power_factor(), Some(95));
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0510), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Int8);
        assert_eq!(n, 1);
        assert_eq!(i8::from_le_bytes([buf[0]]), 95);
    }

    #[test]
    fn setters_accept_none_for_unknown() {
        let mut server = ElectricalMeasurementServer::new();
        server.set_rms_voltage(230);
        server.set_rms_current(1500);
        server.set_active_power(350);
        server.set_power_factor(95);

        server.set_rms_voltage(None::<u16>);
        server.set_rms_current(None::<u16>);
        server.set_active_power(None::<i16>);
        server.set_power_factor(None::<i8>);

        assert_eq!(server.rms_voltage(), None);
        assert_eq!(server.rms_current(), None);
        assert_eq!(server.active_power(), None);
        assert_eq!(server.power_factor(), None);
    }

    #[test]
    fn all_mandatory_attributes_readable() {
        let server = ElectricalMeasurementServer::new();
        for attr in [0x0000u16, 0x0505, 0x0508, 0x050B, 0x0510] {
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
        let server = ElectricalMeasurementServer::new();
        let mut buf = [0u8; 8];
        assert_eq!(
            server.read_attribute(AttributeId::new(0xFFFF), &mut buf),
            Err(AttrError::UnsupportedAttribute)
        );
    }

    // --- attribute writes (all read-only) ---

    #[test]
    fn write_attribute_returns_read_only_for_all_attrs() {
        let mut server = ElectricalMeasurementServer::new();
        for (attr, tid, data) in [
            (0x0000u16, TypeId::Bitmap32, [0u8, 0, 0, 0].as_ref()),
            (0x0505, TypeId::Uint16, [0u8, 0].as_ref()),
            (0x0508, TypeId::Uint16, [0u8, 0].as_ref()),
            (0x050B, TypeId::Int16, [0u8, 0].as_ref()),
            (0x0510, TypeId::Int8, [0u8].as_ref()),
        ] {
            assert_eq!(
                server.write_attribute(AttributeId::new(attr), tid, data),
                Err(AttrError::ReadOnly),
                "expected ReadOnly for attr 0x{attr:04X}"
            );
        }
    }

    // --- attribute_list ---

    #[test]
    fn attribute_list_has_five_entries() {
        assert_eq!(ElectricalMeasurementServer::attribute_list().len(), 6);
    }

    #[test]
    fn attribute_list_active_power_is_reportable() {
        let attrs = ElectricalMeasurementServer::attribute_list();
        let ap = attrs
            .iter()
            .find(|a| a.id == AttributeId::new(0x050B))
            .unwrap();
        assert!(ap.access.is_reportable());
        assert!(ap.access.is_readable());
        assert_eq!(ap.type_id, TypeId::Int16);
    }

    #[test]
    fn attribute_list_measurement_type_is_bitmap32() {
        let attrs = ElectricalMeasurementServer::attribute_list();
        let mt = attrs
            .iter()
            .find(|a| a.id == AttributeId::new(0x0000))
            .unwrap();
        assert_eq!(mt.type_id, TypeId::Bitmap32);
        assert!(!mt.access.is_reportable());
    }

    // --- reporting ---

    #[test]
    fn configure_reporting_active_power_success() {
        let mut server = ElectricalMeasurementServer::new();
        let record = send_record(0x050B, TypeId::Int16.as_u8(), 0, 60);
        assert_eq!(
            server.configure_reporting(record, unicast_with_source()),
            Status::Success
        );
    }

    #[test]
    fn configure_reporting_rms_voltage_unreportable() {
        let mut server = ElectricalMeasurementServer::new();
        let record = send_record(0x0505, TypeId::Uint16.as_u8(), 0, 60);
        assert_eq!(
            server.configure_reporting(record, unicast_with_source()),
            Status::UnreportableAttribute
        );
    }

    #[test]
    fn collect_reports_none_when_no_subscription() {
        let mut server = ElectricalMeasurementServer::new();
        server.set_active_power(350);
        let mut buf = [0u8; 32];
        let mut writer = ReportPayloadWriter::new(&mut buf);
        assert!(server.collect_reports(0, &mut writer).unwrap().is_none());
    }

    #[test]
    fn collect_reports_after_set_active_power() {
        let mut server = ElectricalMeasurementServer::new();
        let record = send_record(0x050B, TypeId::Int16.as_u8(), 0, 60);
        server.configure_reporting(record, unicast_with_source());
        server.set_active_power(350);

        let mut buf = [0u8; 32];
        let mut writer = ReportPayloadWriter::new(&mut buf);
        let ready = server.collect_reports(0, &mut writer).unwrap();
        assert!(ready.is_some());
        // attr_id(2) + type_id(1) + value(2) = 5 bytes
        assert_eq!(writer.len(), 5);
        assert_eq!(i16::from_le_bytes([buf[3], buf[4]]), 350);
    }

    #[test]
    fn report_delivery_clears_pending() {
        let mut server = ElectricalMeasurementServer::new();
        let record = send_record(0x050B, TypeId::Int16.as_u8(), 0, 60);
        server.configure_reporting(record, unicast_with_source());
        server.set_active_power(350);

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

    // --- dispatch integration ---

    #[test]
    fn dispatch_read_active_power() {
        let req: &[u8] = &[
            0x00, 0x01, 0x00, // ReadAttributes, seq=1
            0x0B, 0x05, // attr 0x050B
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = ElectricalMeasurementServer::new();
        server.set_active_power(240);
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + attr_id(2) + status(1) + type_id(1) + value(2) = 9
        assert_eq!(n, 9);
        assert_eq!(buf[5], 0x00); // Success
        assert_eq!(buf[6], TypeId::Int16.as_u8());
        assert_eq!(i16::from_le_bytes([buf[7], buf[8]]), 240);
    }

    #[test]
    fn dispatch_write_active_power_returns_read_only() {
        let req: &[u8] = &[
            0x00, 0x01, 0x02, // WriteAttributes, seq=1
            0x0B, 0x05, // attr 0x050B
            0x29, // Int16
            0x64, 0x00, // value 100
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = ElectricalMeasurementServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + status(1) + attr_id(2) = 6
        assert_eq!(n, 6);
        assert_eq!(buf[3], Status::ReadOnly as u8);
    }
}
