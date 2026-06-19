/// Generates the four `ClusterServer` reporting methods for a cluster that
/// holds a `LatestReportingTable` field.
///
/// Arguments:
/// - `$field`: the reporting table field name (e.g. `reporting`)
/// - `$max_bytes`: max encoded byte size of any single reportable attribute
///   value — must equal the `VALUE_BYTES` const generic on the table field
///
/// Usage inside `impl ClusterServer for Foo { ... }`:
/// ```ignore
/// impl_reporting!(reporting, 2);   // field=reporting, u16 attrs → 2 bytes
/// ```
macro_rules! impl_reporting {
    ($field:ident, $max_bytes:expr) => {
        fn configure_reporting(
            &mut self,
            record: crate::cluster_server::ConfigureReportingRecord<'_>,
            ctx: crate::cluster_server::DispatchContext,
        ) -> crate::frame::Status {
            self.$field.configure(record, ctx, Self::attribute_list())
        }

        fn collect_reports(
            &mut self,
            now_ms: u32,
            out: &mut crate::reporting::ReportPayloadWriter<'_>,
        ) -> Result<
            Option<crate::cluster_server::ClusterReportReady>,
            crate::types::error::ZclError,
        > {
            let Some(candidate) = self.$field.next_due(now_ms) else {
                return Ok(None);
            };
            let mut tmp = [0u8; $max_bytes];
            let Ok((type_id, n)) = self.read_attribute(candidate.attr_id, &mut tmp) else {
                return Ok(None);
            };
            let current = &tmp[..n];
            if candidate.due == crate::reporting::ReportDue::Change
                && self
                    .$field
                    .is_below_threshold(candidate.token, type_id, current)
            {
                self.$field
                    .skip(candidate.token, crate::reporting::ReportSkip::BelowThreshold);
                return Ok(None);
            }
            if let Err(e) = out.write_encoded(candidate.attr_id, type_id, current) {
                if e == crate::types::error::ZclError::BufferTooSmall {
                    self.$field
                        .skip(candidate.token, crate::reporting::ReportSkip::BufferTooSmall);
                }
                return Err(e);
            }
            self.$field.record_value(candidate.token, current);
            Ok(Some(crate::cluster_server::ClusterReportReady {
                destination: candidate.destination,
                token: candidate.token,
            }))
        }

        fn report_delivery_result(
            &mut self,
            token: crate::cluster_server::ReportToken,
            result: crate::cluster_server::ReportDeliveryResult,
            now_ms: u32,
        ) {
            self.$field.complete(token, result, now_ms);
        }

        fn take_reporting_diagnostics(&mut self) -> crate::cluster_server::ReportingDiagnostics {
            self.$field.take_diagnostics()
        }

        fn read_reporting_config(
            &self,
            attr_id: crate::types::AttributeId,
            direction: u8,
            buf: &mut [u8],
        ) -> usize {
            self.$field.write_read_response_record(attr_id, direction, buf)
        }
    };
}

/// Generates the `attribute_list()` body as a `const` slice reference.
///
/// Each entry: `(attr_id, TypeId variant, ACCESS_FLAG | ...)`. Access flags
/// are `|`-separated `AccessFlags` constant names. The macro expands to
/// chained `.union()` calls so it is valid in `const` context.
///
/// Usage:
/// ```ignore
/// fn attribute_list() -> &'static [AttrInfo] {
///     attr_list![
///         (0x0000, Int16, READ | REPORTABLE),
///         (0x0001, Uint16, READ),
///     ]
/// }
/// ```
macro_rules! attr_list {
    ( $( ($id:expr, $type:ident, $first:ident $(| $rest:ident)*) ),+ $(,)? ) => {{
        const LIST: &[crate::types::descriptors::AttrInfo] = &[
            $(
                crate::types::descriptors::AttrInfo {
                    id: crate::types::ids::AttributeId::new($id),
                    type_id: crate::types::ids::TypeId::$type,
                    access: crate::types::descriptors::AccessFlags::$first
                        $(.union(crate::types::descriptors::AccessFlags::$rest))*,
                },
            )+
        ];
        LIST
    }};
}

/// Generates a ZCL measurement cluster server with the standard 4-attribute
/// layout: `MeasuredValue` (0x0000), `MinMeasuredValue` (0x0001),
/// `MaxMeasuredValue` (0x0002) — all `Nullable<$value_ty>` — and `Tolerance`
/// (0x0003, `Uint16`). All attributes are read-only from ZCL.
///
/// Arguments:
/// - `$meta`: outer doc/attr annotations on the struct
/// - `$name`: struct name (e.g. `TemperatureMeasurementServer`)
/// - `$cluster_id`: ZCL cluster ID literal (e.g. `0x0402`)
/// - `$value_ty`: Rust type for measured/min/max (e.g. `i16` or `u16`)
/// - `$attr_type_id`: `TypeId` variant matching `$value_ty` (e.g. `Int16`)
macro_rules! define_measurement_cluster {
    (
        $(#[$meta:meta])*
        $name:ident,
        cluster_id: $cluster_id:expr,
        value_ty: $value_ty:ty,
        attr_type_id: $attr_type_id:ident $(,)?
    ) => {
        $(#[$meta])*
        pub struct $name {
            /// Attribute 0x0000 — `MeasuredValue` (nullable).
            measured_value: Option<$value_ty>,
            /// Attribute 0x0001 — `MinMeasuredValue` (nullable).
            min_measured_value: Option<$value_ty>,
            /// Attribute 0x0002 — `MaxMeasuredValue` (nullable).
            max_measured_value: Option<$value_ty>,
            /// Attribute 0x0003 — `Tolerance` (Uint16).
            tolerance: u16,
            reporting: crate::reporting::LatestReportingTable<1, 2>,
        }

        impl $name {
            pub const fn new() -> Self {
                Self {
                    measured_value: None,
                    min_measured_value: None,
                    max_measured_value: None,
                    tolerance: 0,
                    reporting: crate::reporting::LatestReportingTable::new(),
                }
            }

            fn validate_measurement_bounds(
                measured: Option<$value_ty>,
                min: Option<$value_ty>,
                max: Option<$value_ty>,
            ) -> Result<(), crate::types::error::AttrError> {
                if let (Some(min), Some(max)) = (min, max) {
                    if min > max {
                        return Err(crate::types::error::AttrError::InvalidValue);
                    }
                }
                if let (Some(measured), Some(min)) = (measured, min) {
                    if measured < min {
                        return Err(crate::types::error::AttrError::InvalidValue);
                    }
                }
                if let (Some(measured), Some(max)) = (measured, max) {
                    if measured > max {
                        return Err(crate::types::error::AttrError::InvalidValue);
                    }
                }
                Ok(())
            }

            pub const fn measured_value(&self) -> Option<$value_ty> {
                self.measured_value
            }

            pub const fn min_measured_value(&self) -> Option<$value_ty> {
                self.min_measured_value
            }

            pub const fn max_measured_value(&self) -> Option<$value_ty> {
                self.max_measured_value
            }

            pub const fn tolerance(&self) -> u16 {
                self.tolerance
            }

            pub fn set_measured_value(
                &mut self,
                v: Option<$value_ty>,
            ) -> Result<(), crate::types::error::AttrError> {
                Self::validate_measurement_bounds(
                    v,
                    self.min_measured_value,
                    self.max_measured_value,
                )?;
                self.measured_value = v;
                self.reporting
                    .note_value_update(crate::types::ids::AttributeId::new(0x0000));
                Ok(())
            }

            pub fn set_min_measured_value(
                &mut self,
                v: Option<$value_ty>,
            ) -> Result<(), crate::types::error::AttrError> {
                Self::validate_measurement_bounds(
                    self.measured_value,
                    v,
                    self.max_measured_value,
                )?;
                self.min_measured_value = v;
                Ok(())
            }

            pub fn set_max_measured_value(
                &mut self,
                v: Option<$value_ty>,
            ) -> Result<(), crate::types::error::AttrError> {
                Self::validate_measurement_bounds(
                    self.measured_value,
                    self.min_measured_value,
                    v,
                )?;
                self.max_measured_value = v;
                Ok(())
            }

            pub fn set_tolerance(&mut self, v: u16) -> Result<(), crate::types::error::AttrError> {
                self.tolerance = v;
                Ok(())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl crate::cluster_server::ClusterServer for $name {
            const CLUSTER_ID: crate::types::ids::ClusterId =
                crate::types::ids::ClusterId::new($cluster_id);

            fn read_attribute(
                &self,
                id: crate::types::ids::AttributeId,
                buf: &mut [u8],
            ) -> Result<(crate::types::ids::TypeId, usize), crate::types::error::AttrError>
            {
                use crate::types::descriptors::encode_attr;
                use crate::types::nullable::Nullable;
                match id.0 {
                    0x0000 => Ok(encode_attr::<Nullable<$value_ty>>(self.measured_value, buf)?),
                    0x0001 => Ok(encode_attr::<Nullable<$value_ty>>(self.min_measured_value, buf)?),
                    0x0002 => Ok(encode_attr::<Nullable<$value_ty>>(self.max_measured_value, buf)?),
                    0x0003 => Ok(encode_attr::<u16>(self.tolerance, buf)?),
                    0xFFFD => Ok(encode_attr::<u16>(1, buf)?),
                    _ => Err(crate::types::error::AttrError::UnsupportedAttribute),
                }
            }

            fn handle_command(
                &mut self,
                _id: crate::types::ids::CommandId,
                _payload: &[u8],
                _ctx: crate::cluster_server::DispatchContext,
                _buf: &mut [u8],
            ) -> Result<crate::cluster_server::CommandResult, crate::types::error::ZclError>
            {
                Ok(crate::cluster_server::CommandResult::DefaultResponse(
                    crate::frame::Status::UnsupCommand,
                ))
            }

            impl_reporting!(reporting, 2);
            read_only_attrs![0x0000..=0x0003 | 0xFFFD];

            fn attribute_list() -> &'static [crate::types::descriptors::AttrInfo] {
                attr_list![
                    (0x0000, $attr_type_id, READ | REPORTABLE),
                    (0x0001, $attr_type_id, READ),
                    (0x0002, $attr_type_id, READ),
                    (0x0003, Uint16, READ),
                    (0xFFFD, Uint16, READ),
                ]
            }

            fn snapshot(&self, buf: &mut [u8]) -> usize {
                use crate::attribute_store::MeasurementValue;
                let vsz = <$value_ty as MeasurementValue>::mv_size();
                let needed = 3 * (1 + vsz) + 2;
                if buf.len() < needed {
                    return 0;
                }
                let mut p = 0usize;
                if let Some(v) = self.measured_value {
                    buf[p] = 1;
                    v.mv_write_le(&mut buf[p + 1..p + 1 + vsz]);
                } else {
                    buf[p] = 0;
                    buf[p + 1..p + 1 + vsz].fill(0);
                }
                p += 1 + vsz;
                if let Some(v) = self.min_measured_value {
                    buf[p] = 1;
                    v.mv_write_le(&mut buf[p + 1..p + 1 + vsz]);
                } else {
                    buf[p] = 0;
                    buf[p + 1..p + 1 + vsz].fill(0);
                }
                p += 1 + vsz;
                if let Some(v) = self.max_measured_value {
                    buf[p] = 1;
                    v.mv_write_le(&mut buf[p + 1..p + 1 + vsz]);
                } else {
                    buf[p] = 0;
                    buf[p + 1..p + 1 + vsz].fill(0);
                }
                p += 1 + vsz;
                buf[p..p + 2].copy_from_slice(&self.tolerance.to_le_bytes());
                p + 2
            }

            fn restore_snapshot(&mut self, buf: &[u8]) {
                use crate::attribute_store::MeasurementValue;
                let vsz = <$value_ty as MeasurementValue>::mv_size();
                let needed = 3 * (1 + vsz) + 2;
                if buf.len() < needed {
                    return;
                }
                let mut p = 0usize;
                self.measured_value = if buf[p] != 0 {
                    Some(<$value_ty as MeasurementValue>::mv_read_le(
                        &buf[p + 1..p + 1 + vsz],
                    ))
                } else {
                    None
                };
                p += 1 + vsz;
                self.min_measured_value = if buf[p] != 0 {
                    Some(<$value_ty as MeasurementValue>::mv_read_le(
                        &buf[p + 1..p + 1 + vsz],
                    ))
                } else {
                    None
                };
                p += 1 + vsz;
                self.max_measured_value = if buf[p] != 0 {
                    Some(<$value_ty as MeasurementValue>::mv_read_le(
                        &buf[p + 1..p + 1 + vsz],
                    ))
                } else {
                    None
                };
                p += 1 + vsz;
                self.tolerance = u16::from_le_bytes([buf[p], buf[p + 1]]);
            }
        }
    };
}

/// Generates `check_write_attribute` and `write_attribute` for clusters where
/// all known attribute IDs are read-only. Returns `ReadOnly` for matched IDs
/// and `UnsupportedAttribute` for everything else.
///
/// Accepts a range pattern or `|`-separated individual IDs:
/// ```ignore
/// read_only_attrs![0x0000..=0x0003];
/// read_only_attrs![0x0000 | 0x0002 | 0x0505];
/// ```
macro_rules! read_only_attrs {
    ($($pat:pat_param)|+) => {
        fn check_write_attribute(
            &self,
            id: crate::types::ids::AttributeId,
            _type_id: crate::types::ids::TypeId,
            _data: &[u8],
        ) -> Result<(), crate::types::error::AttrError> {
            match id.0 {
                $($pat)|+ => Err(crate::types::error::AttrError::ReadOnly),
                _ => Err(crate::types::error::AttrError::UnsupportedAttribute),
            }
        }

        fn write_attribute(
            &mut self,
            id: crate::types::ids::AttributeId,
            _type_id: crate::types::ids::TypeId,
            _data: &[u8],
        ) -> Result<(), crate::types::error::AttrError> {
            match id.0 {
                $($pat)|+ => Err(crate::types::error::AttrError::ReadOnly),
                _ => Err(crate::types::error::AttrError::UnsupportedAttribute),
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::types::error::AttrError;

    define_measurement_cluster!(
        TestMeasurementServer,
        cluster_id: 0xFC00,
        value_ty: i16,
        attr_type_id: Int16,
    );

    #[test]
    fn generated_measurement_getters_expose_private_fields() {
        let mut server = TestMeasurementServer::new();
        server.set_measured_value(Some(10)).unwrap();
        server.set_min_measured_value(Some(0)).unwrap();
        server.set_max_measured_value(Some(20)).unwrap();
        server.set_tolerance(3).unwrap();

        assert_eq!(server.measured_value(), Some(10));
        assert_eq!(server.min_measured_value(), Some(0));
        assert_eq!(server.max_measured_value(), Some(20));
        assert_eq!(server.tolerance(), 3);
    }

    #[test]
    fn generated_measurement_setters_enforce_known_bounds() {
        let mut server = TestMeasurementServer::new();
        server.set_min_measured_value(Some(0)).unwrap();
        server.set_max_measured_value(Some(20)).unwrap();

        assert_eq!(
            server.set_measured_value(Some(21)),
            Err(AttrError::InvalidValue)
        );
        assert_eq!(server.measured_value(), None);

        server.set_measured_value(Some(10)).unwrap();
        assert_eq!(
            server.set_min_measured_value(Some(11)),
            Err(AttrError::InvalidValue)
        );
        assert_eq!(
            server.set_max_measured_value(Some(9)),
            Err(AttrError::InvalidValue)
        );
    }
}
