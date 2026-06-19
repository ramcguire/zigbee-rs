use crate::cluster_server::ClusterServer;
use crate::cluster_server::CommandResult;
use crate::cluster_server::DispatchContext;
use crate::frame::Status;
use crate::reporting::LatestReportingTable;
use crate::types::descriptors::AttrInfo;
use crate::types::descriptors::decode_attr;
use crate::types::descriptors::encode_attr;
use crate::types::enums::Enum8;
use crate::types::enums::ThermostatControlSequence;
use crate::types::enums::ThermostatSystemMode;
use crate::types::enums::ZclEnum8;
use crate::types::error::AttrError;
use crate::types::error::ZclError;
use crate::types::ids::AttributeId;
use crate::types::ids::ClusterId;
use crate::types::ids::CommandId;
use crate::types::ids::TypeId;
use crate::types::nullable::Nullable;

/// ZCL Thermostat cluster (0x0201).
///
/// `local_temperature` is updated by the application via
/// `set_local_temperature`. Setpoints and operating mode are writable from ZCL.
/// `SetpointRaiseLower` (0x00) adjusts setpoints by an amount in units of 1/10
/// °C (10 centidegrees).
pub struct ThermostatServer {
    /// Attr 0x0000 — `LocalTemperature` (Int16, nullable, R|REPORTABLE).
    local_temperature: Option<i16>,
    /// Attr 0x0011 — `OccupiedCoolingSetpoint` (Int16, R/W). Centidegrees.
    pub occupied_cooling_setpoint: i16,
    /// Attr 0x0012 — `OccupiedHeatingSetpoint` (Int16, R/W). Centidegrees.
    pub occupied_heating_setpoint: i16,
    /// Attr 0x001B — `ControlSequenceOfOperation` (Enum8, R/W).
    pub control_sequence: ThermostatControlSequence,
    /// Attr 0x001C — `SystemMode` (Enum8, R/W).
    pub system_mode: ThermostatSystemMode,
    reporting: LatestReportingTable<1, 2>,
}

impl ThermostatServer {
    pub const fn new() -> Self {
        Self {
            local_temperature: None,
            occupied_cooling_setpoint: 2600,
            occupied_heating_setpoint: 2000,
            control_sequence: ThermostatControlSequence::CoolingAndHeating,
            system_mode: ThermostatSystemMode::Off,
            reporting: LatestReportingTable::new(),
        }
    }

    pub fn set_local_temperature(&mut self, v: Option<i16>) {
        self.local_temperature = v;
        self.reporting.note_value_update(AttributeId::new(0x0000));
    }

    pub const fn local_temperature(&self) -> Option<i16> {
        self.local_temperature
    }

    fn is_system_mode_compatible(
        control_sequence: ThermostatControlSequence,
        system_mode: ThermostatSystemMode,
    ) -> bool {
        match control_sequence {
            ThermostatControlSequence::CoolingOnly
            | ThermostatControlSequence::CoolingWithReheat => matches!(
                system_mode,
                ThermostatSystemMode::Off | ThermostatSystemMode::Cool
            ),
            ThermostatControlSequence::HeatingOnly
            | ThermostatControlSequence::HeatingWithReheat => {
                matches!(
                    system_mode,
                    ThermostatSystemMode::Off
                        | ThermostatSystemMode::Heat
                        | ThermostatSystemMode::EmergencyHeating
                )
            }
            ThermostatControlSequence::CoolingAndHeating
            | ThermostatControlSequence::CoolingAndHeatingWithReheat => {
                matches!(
                    system_mode,
                    ThermostatSystemMode::Off
                        | ThermostatSystemMode::Auto
                        | ThermostatSystemMode::Cool
                        | ThermostatSystemMode::Heat
                        | ThermostatSystemMode::EmergencyHeating
                )
            }
        }
    }

    fn validate_write(
        &self,
        id: AttributeId,
        type_id: TypeId,
        data: &[u8],
    ) -> Result<ThermostatWrite, AttrError> {
        match id.0 {
            0x0011 => Ok(ThermostatWrite::OccupiedCoolingSetpoint(
                decode_attr::<i16>(type_id, data)?,
            )),
            0x0012 => Ok(ThermostatWrite::OccupiedHeatingSetpoint(
                decode_attr::<i16>(type_id, data)?,
            )),
            0x001B => {
                let control_sequence = decode_attr::<Enum8<ThermostatControlSequence>>(
                    type_id, data,
                )
                .map_err(|err| match err {
                    AttrError::Codec(ZclError::InvalidEnumValue | ZclError::NullSentinel) => {
                        AttrError::InvalidValue
                    }
                    other => other,
                })?;
                if Self::is_system_mode_compatible(control_sequence, self.system_mode) {
                    Ok(ThermostatWrite::ControlSequence(control_sequence))
                } else {
                    Err(AttrError::InvalidValue)
                }
            }
            0x001C => {
                let system_mode = decode_attr::<Enum8<ThermostatSystemMode>>(type_id, data)
                    .map_err(|err| match err {
                        AttrError::Codec(ZclError::InvalidEnumValue | ZclError::NullSentinel) => {
                            AttrError::InvalidValue
                        }
                        other => other,
                    })?;
                if Self::is_system_mode_compatible(self.control_sequence, system_mode) {
                    Ok(ThermostatWrite::SystemMode(system_mode))
                } else {
                    Err(AttrError::InvalidValue)
                }
            }
            0x0000 | 0xFFFD => Err(AttrError::ReadOnly),
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }
}

enum ThermostatWrite {
    OccupiedCoolingSetpoint(i16),
    OccupiedHeatingSetpoint(i16),
    ControlSequence(ThermostatControlSequence),
    SystemMode(ThermostatSystemMode),
}

impl Default for ThermostatServer {
    fn default() -> Self {
        Self::new()
    }
}

impl ClusterServer for ThermostatServer {
    const CLUSTER_ID: ClusterId = ClusterId::new(0x0201);

    fn read_attribute(
        &self,
        id: AttributeId,
        buf: &mut [u8],
    ) -> Result<(TypeId, usize), AttrError> {
        match id.0 {
            0x0000 => Ok(encode_attr::<Nullable<i16>>(self.local_temperature, buf)?),
            0x0011 => Ok(encode_attr::<i16>(self.occupied_cooling_setpoint, buf)?),
            0x0012 => Ok(encode_attr::<i16>(self.occupied_heating_setpoint, buf)?),
            0x001B => Ok(encode_attr::<Enum8<ThermostatControlSequence>>(
                self.control_sequence,
                buf,
            )?),
            0x001C => Ok(encode_attr::<Enum8<ThermostatSystemMode>>(
                self.system_mode,
                buf,
            )?),
            0xFFFD => Ok(encode_attr::<u16>(3, buf)?),
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }

    fn check_write_attribute(
        &self,
        id: AttributeId,
        type_id: TypeId,
        data: &[u8],
    ) -> Result<(), AttrError> {
        self.validate_write(id, type_id, data).map(|_| ())
    }

    fn write_attribute(
        &mut self,
        id: AttributeId,
        type_id: TypeId,
        data: &[u8],
    ) -> Result<(), AttrError> {
        match self.validate_write(id, type_id, data)? {
            ThermostatWrite::OccupiedCoolingSetpoint(v) => {
                self.occupied_cooling_setpoint = v;
            }
            ThermostatWrite::OccupiedHeatingSetpoint(v) => {
                self.occupied_heating_setpoint = v;
            }
            ThermostatWrite::ControlSequence(v) => {
                self.control_sequence = v;
            }
            ThermostatWrite::SystemMode(v) => {
                self.system_mode = v;
            }
        }
        Ok(())
    }

    fn handle_command(
        &mut self,
        id: CommandId,
        payload: &[u8],
        _ctx: DispatchContext,
        _buf: &mut [u8],
    ) -> Result<CommandResult, ZclError> {
        match id.0 {
            // SetpointRaiseLower: [mode: u8, amount: i8]
            // amount in units of 1/10 °C; ZCL setpoints in centidegrees → multiply by 10.
            0x00 => {
                if payload.len() < 2 {
                    return Err(ZclError::InsufficientBytes);
                }
                let mode = payload[0];
                let amount = payload[1].cast_signed();
                let delta = i16::from(amount).saturating_mul(10);
                match mode {
                    0x00 => {
                        self.occupied_heating_setpoint =
                            self.occupied_heating_setpoint.saturating_add(delta);
                    }
                    0x01 => {
                        self.occupied_cooling_setpoint =
                            self.occupied_cooling_setpoint.saturating_add(delta);
                    }
                    0x02 => {
                        self.occupied_heating_setpoint =
                            self.occupied_heating_setpoint.saturating_add(delta);
                        self.occupied_cooling_setpoint =
                            self.occupied_cooling_setpoint.saturating_add(delta);
                    }
                    _ => return Ok(CommandResult::DefaultResponse(Status::InvalidField)),
                }
                Ok(CommandResult::DefaultResponse(Status::Success))
            }
            _ => Ok(CommandResult::DefaultResponse(Status::UnsupCommand)),
        }
    }

    impl_reporting!(reporting, 2);

    fn attribute_list() -> &'static [AttrInfo] {
        attr_list![
            (0x0000, Int16, READ | REPORTABLE),
            (0x0011, Int16, READ | WRITE),
            (0x0012, Int16, READ | WRITE),
            (0x001B, Enum8, READ | WRITE),
            (0x001C, Enum8, READ | WRITE),
            (0xFFFD, Uint16, READ),
        ]
    }

    fn snapshot(&self, buf: &mut [u8]) -> usize {
        if buf.len() < 6 {
            return 0;
        }
        buf[0..2].copy_from_slice(&self.occupied_cooling_setpoint.to_le_bytes());
        buf[2..4].copy_from_slice(&self.occupied_heating_setpoint.to_le_bytes());
        buf[4] = self.control_sequence.into_raw();
        buf[5] = self.system_mode.into_raw();
        6
    }

    fn restore_snapshot(&mut self, buf: &[u8]) {
        if buf.len() < 6 {
            return;
        }
        self.occupied_cooling_setpoint = i16::from_le_bytes([buf[0], buf[1]]);
        self.occupied_heating_setpoint = i16::from_le_bytes([buf[2], buf[3]]);
        if let Ok(cs) = ThermostatControlSequence::from_raw(buf[4]) {
            self.control_sequence = cs;
        }
        if let Ok(sm) = ThermostatSystemMode::from_raw(buf[5]) {
            self.system_mode = sm;
        }
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
    fn local_temperature_none_encodes_as_null_sentinel() {
        let server = ThermostatServer::new();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Int16);
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], &[0x00, 0x80]); // i16::MIN LE
    }

    #[test]
    fn local_temperature_some_encodes_correctly() {
        let mut server = ThermostatServer::new();
        server.set_local_temperature(Some(2150)); // 21.50 °C
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Int16);
        assert_eq!(n, 2);
        assert_eq!(i16::from_le_bytes([buf[0], buf[1]]), 2150);
    }

    #[test]
    fn occupied_cooling_setpoint_reads_default() {
        let server = ThermostatServer::new();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0011), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Int16);
        assert_eq!(n, 2);
        assert_eq!(i16::from_le_bytes([buf[0], buf[1]]), 2600);
    }

    #[test]
    fn occupied_heating_setpoint_reads_default() {
        let server = ThermostatServer::new();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0012), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Int16);
        assert_eq!(n, 2);
        assert_eq!(i16::from_le_bytes([buf[0], buf[1]]), 2000);
    }

    #[test]
    fn control_sequence_reads_as_enum8() {
        let server = ThermostatServer::new();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x001B), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Enum8);
        assert_eq!(n, 1);
        assert_eq!(buf[0], ThermostatControlSequence::CoolingAndHeating as u8);
    }

    #[test]
    fn system_mode_reads_as_enum8() {
        let server = ThermostatServer::new();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x001C), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Enum8);
        assert_eq!(n, 1);
        assert_eq!(buf[0], ThermostatSystemMode::Off as u8);
    }

    #[test]
    fn cluster_revision_reads_three() {
        let server = ThermostatServer::new();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0xFFFD), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 3);
    }

    #[test]
    fn unknown_attribute_returns_unsupported() {
        let server = ThermostatServer::new();
        let mut buf = [0u8; 4];
        assert_eq!(
            server.read_attribute(AttributeId::new(0xFFFF), &mut buf),
            Err(AttrError::UnsupportedAttribute)
        );
    }

    // --- attribute writes ---

    #[test]
    fn write_cooling_setpoint() {
        let mut server = ThermostatServer::new();
        server
            .write_attribute(
                AttributeId::new(0x0011),
                TypeId::Int16,
                &3000i16.to_le_bytes(),
            )
            .unwrap();
        assert_eq!(server.occupied_cooling_setpoint, 3000);
    }

    #[test]
    fn write_heating_setpoint() {
        let mut server = ThermostatServer::new();
        server
            .write_attribute(
                AttributeId::new(0x0012),
                TypeId::Int16,
                &1800i16.to_le_bytes(),
            )
            .unwrap();
        assert_eq!(server.occupied_heating_setpoint, 1800);
    }

    #[test]
    fn write_control_sequence() {
        let mut server = ThermostatServer::new();
        server
            .write_attribute(
                AttributeId::new(0x001B),
                TypeId::Enum8,
                &[ThermostatControlSequence::HeatingOnly as u8],
            )
            .unwrap();
        assert_eq!(
            server.control_sequence,
            ThermostatControlSequence::HeatingOnly
        );
    }

    #[test]
    fn write_system_mode() {
        let mut server = ThermostatServer::new();
        server
            .write_attribute(
                AttributeId::new(0x001C),
                TypeId::Enum8,
                &[ThermostatSystemMode::Heat as u8],
            )
            .unwrap();
        assert_eq!(server.system_mode, ThermostatSystemMode::Heat);
    }

    #[test]
    fn check_write_rejects_invalid_type_length_and_enum() {
        let server = ThermostatServer::new();
        assert_eq!(
            server.check_write_attribute(AttributeId::new(0x0011), TypeId::Uint16, &[0, 0]),
            Err(AttrError::InvalidDataType)
        );
        assert_eq!(
            server.check_write_attribute(AttributeId::new(0x0011), TypeId::Int16, &[0]),
            Err(AttrError::Codec(ZclError::InsufficientBytes))
        );
        assert_eq!(
            server.check_write_attribute(AttributeId::new(0x0011), TypeId::Int16, &[0, 0, 0]),
            Err(AttrError::Codec(ZclError::InvalidLength))
        );
        assert_eq!(
            server.check_write_attribute(AttributeId::new(0x001C), TypeId::Enum8, &[0xFF]),
            Err(AttrError::InvalidValue)
        );
    }

    #[test]
    fn system_mode_must_match_control_sequence() {
        let mut server = ThermostatServer::new();
        server.control_sequence = ThermostatControlSequence::CoolingOnly;
        assert_eq!(
            server.check_write_attribute(
                AttributeId::new(0x001C),
                TypeId::Enum8,
                &[ThermostatSystemMode::Heat as u8],
            ),
            Err(AttrError::InvalidValue)
        );
        assert_eq!(
            server.write_attribute(
                AttributeId::new(0x001C),
                TypeId::Enum8,
                &[ThermostatSystemMode::Cool as u8],
            ),
            Ok(())
        );
        assert_eq!(server.system_mode, ThermostatSystemMode::Cool);
    }

    #[test]
    fn control_sequence_change_must_keep_current_system_mode_compatible() {
        let mut server = ThermostatServer::new();
        server.system_mode = ThermostatSystemMode::Cool;
        assert_eq!(
            server.write_attribute(
                AttributeId::new(0x001B),
                TypeId::Enum8,
                &[ThermostatControlSequence::HeatingOnly as u8],
            ),
            Err(AttrError::InvalidValue)
        );
        assert_eq!(
            server.control_sequence,
            ThermostatControlSequence::CoolingAndHeating
        );
    }

    #[test]
    fn write_local_temperature_returns_read_only() {
        let mut server = ThermostatServer::new();
        assert_eq!(
            server.write_attribute(AttributeId::new(0x0000), TypeId::Int16, &[0x00, 0x00]),
            Err(AttrError::ReadOnly)
        );
    }

    #[test]
    fn write_unknown_attribute_returns_unsupported() {
        let mut server = ThermostatServer::new();
        assert_eq!(
            server.write_attribute(AttributeId::new(0xFFFF), TypeId::Int16, &[0x00, 0x00]),
            Err(AttrError::UnsupportedAttribute)
        );
    }

    // --- SetpointRaiseLower ---

    #[test]
    fn setpoint_raise_lower_heat_mode() {
        let mut server = ThermostatServer::new();
        // heating = 2000, amount = 5 → +50 centidegrees
        let result = server
            .handle_command(CommandId::new(0x00), &[0x00, 5u8], unicast(), &mut [])
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::Success)
        ));
        assert_eq!(server.occupied_heating_setpoint, 2050);
        assert_eq!(server.occupied_cooling_setpoint, 2600); // unchanged
    }

    #[test]
    fn setpoint_raise_lower_cool_mode() {
        let mut server = ThermostatServer::new();
        // cooling = 2600, amount = -3 → -30 centidegrees
        let result = server
            .handle_command(
                CommandId::new(0x00),
                &[0x01, u8::from_le_bytes((-3i8).to_le_bytes())],
                unicast(),
                &mut [],
            )
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::Success)
        ));
        assert_eq!(server.occupied_cooling_setpoint, 2570);
        assert_eq!(server.occupied_heating_setpoint, 2000); // unchanged
    }

    #[test]
    fn setpoint_raise_lower_both_mode() {
        let mut server = ThermostatServer::new();
        // amount = 2 → +20 centidegrees on both
        let result = server
            .handle_command(CommandId::new(0x00), &[0x02, 2u8], unicast(), &mut [])
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::Success)
        ));
        assert_eq!(server.occupied_heating_setpoint, 2020);
        assert_eq!(server.occupied_cooling_setpoint, 2620);
    }

    #[test]
    fn setpoint_raise_lower_short_payload_returns_error() {
        let mut server = ThermostatServer::new();
        assert!(matches!(
            server.handle_command(CommandId::new(0x00), &[0x00], unicast(), &mut []),
            Err(ZclError::InsufficientBytes)
        ));
    }

    #[test]
    fn setpoint_raise_lower_invalid_mode_returns_invalid_field() {
        let mut server = ThermostatServer::new();
        let result = server
            .handle_command(CommandId::new(0x00), &[0xFF, 1u8], unicast(), &mut [])
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::InvalidField)
        ));
    }

    #[test]
    fn unknown_command_returns_unsup_command() {
        let mut server = ThermostatServer::new();
        let result = server
            .handle_command(CommandId::new(0xFF), &[], unicast(), &mut [])
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::UnsupCommand)
        ));
    }

    // --- attribute_list ---

    #[test]
    fn attribute_list_local_temperature_is_reportable() {
        let attrs = ThermostatServer::attribute_list();
        let local_temp = attrs
            .iter()
            .find(|a| a.id == AttributeId::new(0x0000))
            .unwrap();
        assert!(local_temp.access.is_reportable());
        assert!(local_temp.access.is_readable());
        assert!(!local_temp.access.is_writable());
    }

    #[test]
    fn attribute_list_setpoints_are_readwrite() {
        let attrs = ThermostatServer::attribute_list();
        for id in [0x0011u16, 0x0012] {
            let entry = attrs.iter().find(|a| a.id == AttributeId::new(id)).unwrap();
            assert!(entry.access.is_readable());
            assert!(entry.access.is_writable());
            assert!(!entry.access.is_reportable());
        }
    }

    #[test]
    fn attribute_list_cluster_revision_is_read_only() {
        let attrs = ThermostatServer::attribute_list();
        let revision = attrs
            .iter()
            .find(|a| a.id == AttributeId::new(0xFFFD))
            .unwrap();
        assert_eq!(revision.type_id, TypeId::Uint16);
        assert!(revision.access.is_readable());
        assert!(!revision.access.is_writable());
        assert_eq!(
            ThermostatServer::new().check_write_attribute(
                AttributeId::new(0xFFFD),
                TypeId::Uint16,
                &3u16.to_le_bytes(),
            ),
            Err(AttrError::ReadOnly)
        );
    }

    // --- reporting ---

    #[test]
    fn configure_reporting_local_temperature_success() {
        let mut server = ThermostatServer::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 0, 60);
        assert_eq!(
            server.configure_reporting(record, unicast_with_source()),
            Status::Success
        );
    }

    #[test]
    fn configure_reporting_non_reportable_returns_unreportable() {
        let mut server = ThermostatServer::new();
        let record = send_record(0x0011, TypeId::Int16.as_u8(), 0, 60);
        assert_eq!(
            server.configure_reporting(record, unicast_with_source()),
            Status::UnreportableAttribute
        );
    }

    #[test]
    fn collect_reports_after_set_temperature() {
        let mut server = ThermostatServer::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 0, 60);
        server.configure_reporting(record, unicast_with_source());
        server.set_local_temperature(Some(2150));

        let mut buf = [0u8; 32];
        let mut writer = ReportPayloadWriter::new(&mut buf);
        let ready = server.collect_reports(0, &mut writer).unwrap();
        assert!(ready.is_some());
        // attr_id(2) + type_id(1) + value(2) = 5 bytes
        assert_eq!(writer.len(), 5);
    }

    #[test]
    fn report_delivery_result_clears_pending() {
        let mut server = ThermostatServer::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 0, 60);
        server.configure_reporting(record, unicast_with_source());
        server.set_local_temperature(Some(2150));

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

    // --- dispatch ---

    #[test]
    fn dispatch_read_local_temperature_null() {
        let req: &[u8] = &[
            0x00, 0x01, 0x00, // ReadAttributes, seq=1
            0x00, 0x00, // attr 0x0000
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = ThermostatServer::new();
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
    fn dispatch_write_cooling_setpoint() {
        let mut value_bytes = [0u8; 2];
        value_bytes.copy_from_slice(&3200i16.to_le_bytes());
        let req: &[u8] = &[
            0x00,
            0x02,
            0x02, // WriteAttributes, seq=2
            0x11,
            0x00, // attr 0x0011
            0x29, // Int16 type id
            value_bytes[0],
            value_bytes[1],
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = ThermostatServer::new();
        zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf).unwrap();
        assert_eq!(server.occupied_cooling_setpoint, 3200);
    }
}
