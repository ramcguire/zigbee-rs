//! ZCL compliance harness
//!
//! Run: `cargo test --test zcl_compliance`
//!
//! Each module loads its generated vector file with `include!` and exercises
//! both encode and decode directions against byte-exact wire representations
//! from `cargo xtask generate-vectors` (vectors generated via zigpy).
//!
//! ## Vector static conventions (all files)
//!
//! | Static          | Type                           | Used by                      |
//! |-----------------|--------------------------------|------------------------------|
//! | `ROUNDTRIP`     | `&[(&[u8], T)]`                | scalars, enums, strings, collections, struct |
//! | `ROUNDTRIP_BITS`| `&[(&[u8], u32/u64)]`          | f32, f64 (NaN-safe bit repr) |
//! | `ROUNDTRIP_RAW` | `&[(&[u8], u8/u16/u32/u64)]`   | bitmaps (raw primitive repr) |
//! | `NULL_WIRE`     | `&[&[u8]]`                     | all nullable types           |
//! | `TYPE_MISMATCH` | `&[&[u8]]`                     | typed collections            |
//! | `VALID`         | `&[(&[u8], &[T])]`             | set collections              |
//! | `DUPLICATE`     | `&[&[u8]]`                     | set collections              |
//! | `INVALID_VALUE` | `&[&[u8]]`                     | bool invalid non-null values |
//! | `INVALID_UTF8`  | `&[&[u8]]`                     | short_text                   |

use zigbee_cluster_library::frame::DefaultResponse;
use zigbee_cluster_library::frame::Direction;
use zigbee_cluster_library::frame::IncomingZclFrame;
use zigbee_cluster_library::frame::OutgoingGlobalCommand;
use zigbee_cluster_library::frame::OutgoingZclFrame;
use zigbee_cluster_library::frame::Status;
use zigbee_cluster_library::frame::ZclFrameMeta;
use zigbee_cluster_library::types::AccessFlags;
use zigbee_cluster_library::types::Array;
use zigbee_cluster_library::types::ArrayOf;
use zigbee_cluster_library::types::ArrayRef;
use zigbee_cluster_library::types::AttributeDescriptor;
use zigbee_cluster_library::types::AttributeId;
use zigbee_cluster_library::types::Bag;
use zigbee_cluster_library::types::BagOf;
use zigbee_cluster_library::types::Bitmap8;
use zigbee_cluster_library::types::Bitmap16;
use zigbee_cluster_library::types::Bitmap32;
use zigbee_cluster_library::types::Bitmap64;
use zigbee_cluster_library::types::ClusterId;
use zigbee_cluster_library::types::CollectionEncoder;
use zigbee_cluster_library::types::CommandId;
use zigbee_cluster_library::types::Enum8;
use zigbee_cluster_library::types::Enum16;
use zigbee_cluster_library::types::Nullable;
use zigbee_cluster_library::types::RawUniqueSet;
use zigbee_cluster_library::types::Set;
use zigbee_cluster_library::types::SetOf;
use zigbee_cluster_library::types::SetPolicy;
use zigbee_cluster_library::types::ShortOctetString;
use zigbee_cluster_library::types::ShortStr;
use zigbee_cluster_library::types::ShortText;
use zigbee_cluster_library::types::StructDecoder;
use zigbee_cluster_library::types::StructEncoder;
use zigbee_cluster_library::types::StructOf;
use zigbee_cluster_library::types::TypeId;
use zigbee_cluster_library::types::ZclBitmap8;
use zigbee_cluster_library::types::ZclBitmap16;
use zigbee_cluster_library::types::ZclBitmap32;
use zigbee_cluster_library::types::ZclBitmap64;
use zigbee_cluster_library::types::ZclEnum8;
use zigbee_cluster_library::types::ZclEnum16;
use zigbee_cluster_library::types::ZclError;
use zigbee_cluster_library::types::ZclSchema;
use zigbee_cluster_library::types::ZclStructSchema;

#[test]
fn outgoing_cluster_command_integration_encodes_byte_exact() {
    let frame = OutgoingZclFrame::cluster_specific(
        ZclFrameMeta::new(0x77, Direction::ClientToServer),
        CommandId::new(0x80),
        &[0x01, 0x02],
    );

    let mut buf = [0u8; 8];
    let written = frame.encode(&mut buf).expect("outgoing cluster encodes");

    assert_eq!(&buf[..written], &[0x01, 0x77, 0x80, 0x01, 0x02]);
}

#[test]
fn default_response_from_incoming_request_integration_encodes_byte_exact() {
    let request = IncomingZclFrame::decode(&[0x00, 0x42, 0x00])
        .expect("incoming request parses")
        .0;
    let response = OutgoingZclFrame::default_response(&request, Status::UnsupportedAttribute)
        .expect("default response should be emitted");

    let mut buf = [0u8; 8];
    let written = response.encode(&mut buf).expect("default response encodes");

    assert_eq!(&buf[..written], &[0x18, 0x42, 0x0b, 0x00, 0x86]);
}

#[test]
fn outgoing_global_default_response_integration_encodes_byte_exact() {
    let frame = OutgoingZclFrame::global(
        ZclFrameMeta::new(0x42, Direction::ServerToClient).disable_default_response(),
        OutgoingGlobalCommand::DefaultResponse(DefaultResponse {
            command_identifier: 0x00,
            status: Status::Success,
        }),
    );

    let mut buf = [0u8; 8];
    let written = frame.encode(&mut buf).expect("outgoing global encodes");

    assert_eq!(&buf[..written], &[0x18, 0x42, 0x0b, 0x00, 0x00]);
}
// ---------------------------------------------------------------------------
// Test-only passthrough helpers for parametric schemas
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Debug)]
struct RawBitmap8(u8);
impl ZclBitmap8 for RawBitmap8 {
    fn from_bits(b: u8) -> Self {
        Self(b)
    }
    fn into_bits(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
struct RawBitmap16(u16);
impl ZclBitmap16 for RawBitmap16 {
    fn from_bits(b: u16) -> Self {
        Self(b)
    }
    fn into_bits(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
struct RawBitmap32(u32);
impl ZclBitmap32 for RawBitmap32 {
    fn from_bits(b: u32) -> Self {
        Self(b)
    }
    fn into_bits(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
struct RawBitmap64(u64);
impl ZclBitmap64 for RawBitmap64 {
    fn from_bits(b: u64) -> Self {
        Self(b)
    }
    fn into_bits(self) -> u64 {
        self.0
    }
}

/// Enum8 helper: accepts every raw discriminant the vectors produce.
#[derive(Clone, Copy, PartialEq, Debug)]
struct RawEnum8(u8);
impl ZclEnum8 for RawEnum8 {
    fn from_raw(raw: u8) -> Result<Self, ZclError> {
        Ok(Self(raw))
    }
    fn into_raw(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
struct RawEnum16(u16);
impl ZclEnum16 for RawEnum16 {
    fn from_raw(raw: u16) -> Result<Self, ZclError> {
        Ok(Self(raw))
    }
    fn into_raw(self) -> u16 {
        self.0
    }
}

struct ExternalSetPolicy;
impl SetPolicy for ExternalSetPolicy {}

#[test]
fn public_attribute_descriptor_is_constructible_downstream() {
    let descriptor = AttributeDescriptor {
        cluster: ClusterId::new(0x0006),
        manufacturer: None,
        attribute: AttributeId::new(0x0000),
        type_id: TypeId::Boolean,
        access: AccessFlags::READ,
        name: "OnOff",
    };

    assert_eq!(descriptor.cluster, ClusterId::new(0x0006));
    assert_eq!(descriptor.attribute, AttributeId::new(0x0000));
}

#[test]
fn downstream_set_policy_works_with_set_of() {
    let wire = [TypeId::Uint8.as_u8(), 1, 0, 0x2a];
    let (set, used) = SetOf::<u8, ExternalSetPolicy>::decode(&wire).unwrap();

    assert_eq!(used, wire.len());
    assert_eq!(set.len(), 1);
    assert_eq!(set.iter().next().unwrap().unwrap(), 0x2a);
}

// ---------------------------------------------------------------------------
// Scalar macro — ROUNDTRIP + NULL_WIRE (bare rejection + Nullable wrapping)
// ---------------------------------------------------------------------------

macro_rules! scalar_compliance {
    ($mod_name:ident, $schema:ty, $vectors:literal) => {
        mod $mod_name {
            use super::*;
            include!($vectors);

            #[test]
            fn decode_roundtrip() {
                for &(wire, expected) in ROUNDTRIP {
                    let (val, n) = <$schema>::decode(wire)
                        .unwrap_or_else(|e| panic!("decode {wire:?} → {e:?}"));
                    assert_eq!(val, expected, "{wire:?}");
                    assert_eq!(n, wire.len(), "{wire:?}: consumed {n} of {}", wire.len());
                }
            }

            #[test]
            fn encode_roundtrip() {
                let mut buf = [0u8; 32];
                for &(wire, expected) in ROUNDTRIP {
                    let n = <$schema>::encode(expected, &mut buf)
                        .unwrap_or_else(|e| panic!("encode {expected:?} → {e:?}"));
                    assert_eq!(&buf[..n], wire, "{expected:?}");
                }
            }

            #[test]
            fn null_wire_rejected() {
                for &wire in NULL_WIRE {
                    assert_eq!(
                        <$schema>::decode(wire).unwrap_err(),
                        ZclError::NullSentinel,
                        "{wire:?}",
                    );
                }
            }

            #[test]
            fn nullable_none_decode() {
                for &wire in NULL_WIRE {
                    let (val, n) = Nullable::<$schema>::decode(wire)
                        .unwrap_or_else(|e| panic!("Nullable decode {wire:?} → {e:?}"));
                    assert!(val.is_none(), "{wire:?}");
                    assert_eq!(n, wire.len(), "{wire:?}");
                }
            }

            #[test]
            fn nullable_none_encode() {
                let mut buf = [0u8; 32];
                for &wire in NULL_WIRE {
                    let n = Nullable::<$schema>::encode(None, &mut buf)
                        .unwrap_or_else(|e| panic!("Nullable encode None → {e:?}"));
                    assert_eq!(&buf[..n], wire, "nullable None encode mismatch");
                }
            }
        }
    };
}

scalar_compliance!(u8_compliance, u8, "vectors/u8.rs");
scalar_compliance!(u16_compliance, u16, "vectors/u16.rs");
scalar_compliance!(u32_compliance, u32, "vectors/u32.rs");
scalar_compliance!(u64_compliance, u64, "vectors/u64.rs");
scalar_compliance!(i8_compliance, i8, "vectors/i8.rs");
scalar_compliance!(i16_compliance, i16, "vectors/i16.rs");
scalar_compliance!(i32_compliance, i32, "vectors/i32.rs");
scalar_compliance!(i64_compliance, i64, "vectors/i64.rs");
scalar_compliance!(
    short_octet_string_compliance,
    ShortOctetString,
    "vectors/short_octet_string.rs"
);

// ---------------------------------------------------------------------------
// Float macro — ROUNDTRIP_BITS (bit-exact, NaN-safe) + NULL_WIRE
// ---------------------------------------------------------------------------

macro_rules! float_compliance {
    ($mod_name:ident, $schema:ty, $vectors:literal) => {
        mod $mod_name {
            use super::*;
            include!($vectors);

            #[test]
            fn decode_roundtrip() {
                for &(wire, expected_bits) in ROUNDTRIP_BITS {
                    let (val, n) = <$schema>::decode(wire)
                        .unwrap_or_else(|e| panic!("decode {wire:?} → {e:?}"));
                    assert_eq!(val.to_bits(), expected_bits, "{wire:?}");
                    assert_eq!(n, wire.len());
                }
            }

            #[test]
            fn encode_roundtrip() {
                let mut buf = [0u8; 16];
                for &(wire, expected_bits) in ROUNDTRIP_BITS {
                    let val = <$schema>::from_bits(expected_bits);
                    let n = <$schema>::encode(val, &mut buf)
                        .unwrap_or_else(|e| panic!("encode bits={expected_bits} → {e:?}"));
                    assert_eq!(&buf[..n], wire, "bits={expected_bits}");
                }
            }

            #[test]
            fn null_wire_rejected() {
                for &wire in NULL_WIRE {
                    assert_eq!(
                        <$schema>::decode(wire).unwrap_err(),
                        ZclError::NullSentinel,
                        "{wire:?}",
                    );
                }
            }

            #[test]
            fn nullable_none_decode() {
                for &wire in NULL_WIRE {
                    let (val, n) = Nullable::<$schema>::decode(wire)
                        .unwrap_or_else(|e| panic!("Nullable decode {wire:?} → {e:?}"));
                    assert!(val.is_none(), "{wire:?}");
                    assert_eq!(n, wire.len());
                }
            }

            #[test]
            fn nullable_none_encode() {
                let mut buf = [0u8; 16];
                for &wire in NULL_WIRE {
                    let n = Nullable::<$schema>::encode(None, &mut buf)
                        .unwrap_or_else(|e| panic!("Nullable encode None → {e:?}"));
                    assert_eq!(&buf[..n], wire);
                }
            }
        }
    };
}

float_compliance!(f32_compliance, f32, "vectors/f32.rs");
float_compliance!(f64_compliance, f64, "vectors/f64.rs");

// ---------------------------------------------------------------------------
// Bitmap macro — ROUNDTRIP_RAW, no null sentinel (all bit patterns valid)
// ---------------------------------------------------------------------------

macro_rules! bitmap_compliance {
    ($mod_name:ident, $schema:ty, $raw_type:ty, $vectors:literal) => {
        mod $mod_name {
            use super::*;
            include!($vectors);

            #[test]
            fn decode_roundtrip() {
                for &(wire, expected_raw) in ROUNDTRIP_RAW {
                    let (val, n) = <$schema>::decode(wire)
                        .unwrap_or_else(|e| panic!("decode {wire:?} → {e:?}"));
                    assert_eq!(val.into_bits(), expected_raw, "{wire:?}");
                    assert_eq!(n, wire.len());
                }
            }

            #[test]
            fn encode_roundtrip() {
                let mut buf = [0u8; 16];
                for &(wire, expected_raw) in ROUNDTRIP_RAW {
                    let val = <$raw_type>::from_bits(expected_raw);
                    let n = <$schema>::encode(val, &mut buf)
                        .unwrap_or_else(|e| panic!("encode raw={expected_raw} → {e:?}"));
                    assert_eq!(&buf[..n], wire, "raw={expected_raw}");
                }
            }
        }
    };
}

bitmap_compliance!(
    bitmap8_compliance,
    Bitmap8<RawBitmap8>,
    RawBitmap8,
    "vectors/bitmap8.rs"
);
bitmap_compliance!(
    bitmap16_compliance,
    Bitmap16<RawBitmap16>,
    RawBitmap16,
    "vectors/bitmap16.rs"
);
bitmap_compliance!(
    bitmap32_compliance,
    Bitmap32<RawBitmap32>,
    RawBitmap32,
    "vectors/bitmap32.rs"
);
bitmap_compliance!(
    bitmap64_compliance,
    Bitmap64<RawBitmap64>,
    RawBitmap64,
    "vectors/bitmap64.rs"
);

// ---------------------------------------------------------------------------
// Enum macro — ROUNDTRIP (raw discriminant) + NULL_WIRE
// ---------------------------------------------------------------------------

macro_rules! enum_compliance {
    ($mod_name:ident, $schema:ty, $raw_helper:ident, $buf_size:expr, $vectors:literal) => {
        mod $mod_name {
            use super::*;
            include!($vectors);

            #[test]
            fn decode_roundtrip() {
                for &(wire, expected_raw) in ROUNDTRIP {
                    let (val, n) = <$schema>::decode(wire)
                        .unwrap_or_else(|e| panic!("decode {wire:?} → {e:?}"));
                    assert_eq!(val, $raw_helper(expected_raw), "{wire:?}");
                    assert_eq!(n, wire.len());
                }
            }

            #[test]
            fn encode_roundtrip() {
                let mut buf = [0u8; $buf_size];
                for &(wire, expected_raw) in ROUNDTRIP {
                    let n = <$schema>::encode($raw_helper(expected_raw), &mut buf)
                        .unwrap_or_else(|e| panic!("encode raw={expected_raw} → {e:?}"));
                    assert_eq!(&buf[..n], wire, "raw={expected_raw}");
                }
            }

            #[test]
            fn null_wire_rejected() {
                for &wire in NULL_WIRE {
                    assert_eq!(
                        <$schema>::decode(wire).unwrap_err(),
                        ZclError::NullSentinel,
                        "{wire:?}",
                    );
                }
            }

            #[test]
            fn nullable_none_decode() {
                for &wire in NULL_WIRE {
                    let (val, n) = Nullable::<$schema>::decode(wire)
                        .unwrap_or_else(|e| panic!("Nullable decode {wire:?} → {e:?}"));
                    assert!(val.is_none(), "{wire:?}");
                    assert_eq!(n, wire.len());
                }
            }

            #[test]
            fn nullable_none_encode() {
                let mut buf = [0u8; $buf_size];
                for &wire in NULL_WIRE {
                    let n = Nullable::<$schema>::encode(None, &mut buf)
                        .unwrap_or_else(|e| panic!("Nullable encode None → {e:?}"));
                    assert_eq!(&buf[..n], wire);
                }
            }
        }
    };
}

enum_compliance!(
    enum8_compliance,
    Enum8<RawEnum8>,
    RawEnum8,
    1,
    "vectors/enum8.rs"
);
enum_compliance!(
    enum16_compliance,
    Enum16<RawEnum16>,
    RawEnum16,
    2,
    "vectors/enum16.rs"
);

// ---------------------------------------------------------------------------
// Bool — ROUNDTRIP + NULL_WIRE + INVALID_VALUE
// ---------------------------------------------------------------------------

mod bool_compliance {
    use super::*;
    include!("vectors/bool.rs");

    #[test]
    fn decode_roundtrip() {
        for &(wire, expected) in ROUNDTRIP {
            let (val, n) = bool::decode(wire).unwrap_or_else(|e| panic!("decode {wire:?} → {e:?}"));
            assert_eq!(val, expected, "{wire:?}");
            assert_eq!(n, wire.len());
        }
    }

    #[test]
    fn encode_roundtrip() {
        let mut buf = [0u8; 1];
        for &(wire, expected) in ROUNDTRIP {
            let n = bool::encode(expected, &mut buf)
                .unwrap_or_else(|e| panic!("encode {expected} → {e:?}"));
            assert_eq!(&buf[..n], wire, "{expected}");
        }
    }

    #[test]
    fn null_sentinel_rejected() {
        for &wire in NULL_WIRE {
            assert_eq!(
                bool::decode(wire).unwrap_err(),
                ZclError::NullSentinel,
                "{wire:?} should be NullSentinel",
            );
        }
    }

    #[test]
    fn invalid_value_rejected() {
        for &wire in INVALID_VALUE {
            assert_eq!(
                bool::decode(wire).unwrap_err(),
                ZclError::InvalidValue,
                "{wire:?} should be InvalidValue",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// ShortText — ROUNDTRIP + NULL_WIRE + INVALID_UTF8
// (inline: ShortStr value type requires .as_str() comparison)
// ---------------------------------------------------------------------------

mod short_text_compliance {
    use super::*;
    include!("vectors/short_text.rs");

    #[test]
    fn decode_roundtrip() {
        for &(wire, expected_str) in ROUNDTRIP {
            let (val, n) =
                ShortText::decode(wire).unwrap_or_else(|e| panic!("decode {wire:?} → {e:?}"));
            assert_eq!(val.as_str(), expected_str, "{wire:?}");
            assert_eq!(n, wire.len());
        }
    }

    #[test]
    fn encode_roundtrip() {
        let mut buf = [0u8; 256];
        for &(wire, expected_str) in ROUNDTRIP {
            let s = ShortStr::new(expected_str).unwrap();
            let n = ShortText::encode(s, &mut buf)
                .unwrap_or_else(|e| panic!("encode {expected_str:?} → {e:?}"));
            assert_eq!(&buf[..n], wire, "{expected_str:?}");
        }
    }

    #[test]
    fn null_wire_rejected() {
        for &wire in NULL_WIRE {
            assert_eq!(
                ShortText::decode(wire).unwrap_err(),
                ZclError::NullSentinel,
                "{wire:?}",
            );
        }
    }

    #[test]
    fn nullable_none_decode() {
        for &wire in NULL_WIRE {
            let (val, n) = Nullable::<ShortText>::decode(wire)
                .unwrap_or_else(|e| panic!("Nullable decode {wire:?} → {e:?}"));
            assert!(val.is_none(), "{wire:?}");
            assert_eq!(n, wire.len());
        }
    }

    #[test]
    fn nullable_none_encode() {
        let mut buf = [0u8; 1];
        for &wire in NULL_WIRE {
            let n = Nullable::<ShortText>::encode(None, &mut buf)
                .unwrap_or_else(|e| panic!("Nullable encode None → {e:?}"));
            assert_eq!(&buf[..n], wire);
        }
    }

    #[test]
    fn invalid_utf8_decode_rejected() {
        for &wire in INVALID_UTF8 {
            assert_eq!(
                ShortText::decode(wire).unwrap_err(),
                ZclError::InvalidUtf8,
                "{wire:?}",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Collection matrix macros
// ---------------------------------------------------------------------------

/// Tests Array and Bag collections with element-value verification.
///
/// Vectors file must export:
///   ROUNDTRIP: &[(&[u8], &[$elem_schema])]
///   NULL_WIRE: &[&[u8]]
///   TYPE_MISMATCH: &[&[u8]]
macro_rules! collection_array_bag_compliance {
    ($mod_name:ident, $coll_schema:ty, $elem_schema:ty, $kind:ty, $vectors:literal) => {
        mod $mod_name {
            use super::*;
            include!($vectors);

            #[test]
            fn decoder_element_values() {
                for &(wire, expected_elems) in ROUNDTRIP {
                    let (coll, n) = <$coll_schema>::decode(wire)
                        .unwrap_or_else(|e| panic!("decode {wire:?} → {e:?}"));
                    assert_eq!(n, wire.len(), "{wire:?}");
                    assert_eq!(coll.len() as usize, expected_elems.len(), "{wire:?}");
                    let mut dec = coll.decoder();
                    for &expected in expected_elems {
                        let val = dec.next().unwrap().unwrap();
                        assert_eq!(val, expected, "{wire:?}");
                    }
                    assert!(dec.next().is_none());
                    dec.finish().unwrap();
                }
            }

            #[test]
            fn iter_element_values() {
                for &(wire, expected_elems) in ROUNDTRIP {
                    let (coll, _) = <$coll_schema>::decode(wire).unwrap();
                    let mut i = 0;
                    for result in coll.iter() {
                        let val = result.unwrap();
                        assert_eq!(val, expected_elems[i], "{wire:?}[{i}]");
                        i += 1;
                    }
                    assert_eq!(i, expected_elems.len());
                }
            }

            #[test]
            fn encoder_builds_from_scratch() {
                let mut buf = [0u8; 64];
                for &(wire, elems) in ROUNDTRIP {
                    let mut enc = CollectionEncoder::<$kind, $elem_schema>::new(&mut buf)
                        .unwrap_or_else(|e| panic!("encoder new → {e:?}"));
                    for &e in elems {
                        enc.push(e)
                            .unwrap_or_else(|err| panic!("push {e:?} → {err:?}"));
                    }
                    let n = enc.finish().unwrap_or_else(|e| panic!("finish → {e:?}"));
                    assert_eq!(&buf[..n], wire, "encoder mismatch for {wire:?}");
                }
            }

            #[test]
            fn null_wire_rejected() {
                for &wire in NULL_WIRE {
                    assert_eq!(
                        <$coll_schema>::decode(wire).unwrap_err(),
                        ZclError::NullSentinel,
                        "{wire:?}",
                    );
                }
            }

            #[test]
            fn nullable_none_decode() {
                for &wire in NULL_WIRE {
                    let (val, n) = Nullable::<$coll_schema>::decode(wire)
                        .unwrap_or_else(|e| panic!("Nullable decode {wire:?} → {e:?}"));
                    assert!(val.is_none(), "{wire:?}");
                    assert_eq!(n, wire.len());
                }
            }

            #[test]
            fn nullable_none_encode() {
                let mut buf = [0u8; 8];
                for &wire in NULL_WIRE {
                    let n = Nullable::<$coll_schema>::encode(None, &mut buf)
                        .unwrap_or_else(|e| panic!("Nullable encode None → {e:?}"));
                    assert_eq!(&buf[..n], wire);
                }
            }

            #[test]
            fn type_mismatch_rejected() {
                for &wire in TYPE_MISMATCH {
                    assert!(
                        matches!(
                            <$coll_schema>::decode(wire).unwrap_err(),
                            ZclError::TypeIdMismatch { .. }
                        ),
                        "{wire:?}",
                    );
                }
            }
        }
    };
}

/// Tests Set collections with element-value verification and uniqueness
/// enforcement.
///
/// Vectors file must export:
///   VALID: &[(&[u8], &[$elem_schema])]
///   DUPLICATE: &[&[u8]]
macro_rules! set_compliance {
    ($mod_name:ident, $elem_schema:ty, $policy:ty, $vectors:literal) => {
        mod $mod_name {
            use super::*;
            include!($vectors);

            type Schema = SetOf<$elem_schema, $policy>;

            #[test]
            fn valid_sets_decode_element_values_and_encode() {
                let mut buf = [0u8; 64];
                for &(wire, expected_elems) in VALID {
                    let (coll, n) =
                        Schema::decode(wire).unwrap_or_else(|e| panic!("decode {wire:?} → {e:?}"));
                    assert_eq!(n, wire.len());
                    assert_eq!(coll.len() as usize, expected_elems.len());
                    let mut dec = coll.decoder();
                    for &expected in expected_elems {
                        assert_eq!(dec.next().unwrap().unwrap(), expected, "{wire:?}");
                    }
                    assert!(dec.next().is_none());
                    dec.finish().unwrap();
                    let written = Schema::encode(coll, &mut buf)
                        .unwrap_or_else(|e| panic!("encode {wire:?} → {e:?}"));
                    assert_eq!(&buf[..written], wire);
                }
            }

            #[test]
            fn encoder_builds_from_scratch() {
                let mut buf = [0u8; 64];
                for &(wire, elems) in VALID {
                    let mut enc =
                        CollectionEncoder::<Set<$policy>, $elem_schema>::new(&mut buf).unwrap();
                    for &e in elems {
                        enc.push(e).unwrap();
                    }
                    let n = enc.finish().unwrap();
                    assert_eq!(&buf[..n], wire);
                }
            }

            #[test]
            fn duplicate_element_rejected() {
                for &wire in DUPLICATE {
                    assert_eq!(
                        Schema::decode(wire).unwrap_err(),
                        ZclError::InvalidValue,
                        "{wire:?}",
                    );
                }
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Array matrix
// ---------------------------------------------------------------------------

collection_array_bag_compliance!(
    coll_array_u8_compliance,
    ArrayOf<u8>,
    u8,
    Array,
    "vectors/collections/array_u8.rs"
);
collection_array_bag_compliance!(
    coll_array_u16_compliance,
    ArrayOf<u16>,
    u16,
    Array,
    "vectors/collections/array_u16.rs"
);
collection_array_bag_compliance!(
    coll_array_i16_compliance,
    ArrayOf<i16>,
    i16,
    Array,
    "vectors/collections/array_i16.rs"
);
collection_array_bag_compliance!(
    coll_array_bool_compliance,
    ArrayOf<bool>,
    bool,
    Array,
    "vectors/collections/array_bool.rs"
);

// ---------------------------------------------------------------------------
// Bag matrix
// ---------------------------------------------------------------------------

collection_array_bag_compliance!(
    coll_bag_u8_compliance,
    BagOf<u8>,
    u8,
    Bag,
    "vectors/collections/bag_u8.rs"
);
collection_array_bag_compliance!(
    coll_bag_u16_compliance,
    BagOf<u16>,
    u16,
    Bag,
    "vectors/collections/bag_u16.rs"
);

// ---------------------------------------------------------------------------
// Set matrix — RawUniqueSet policy, element values verified
// ---------------------------------------------------------------------------

set_compliance!(
    coll_set_u8_compliance,
    u8,
    RawUniqueSet,
    "vectors/collections/set_u8.rs"
);
set_compliance!(
    coll_set_u16_compliance,
    u16,
    RawUniqueSet,
    "vectors/collections/set_u16.rs"
);

// ---------------------------------------------------------------------------
// Struct — (u8, u16) pair via StructEncoder / StructDecoder / StructOf
// ---------------------------------------------------------------------------

struct PairStruct;

impl ZclStructSchema for PairStruct {
    type Value<'a> = (u8, u16);

    fn decode_fields<'a>(dec: &mut StructDecoder<'a>) -> Result<(u8, u16), ZclError> {
        Ok((dec.field::<u8>()?, dec.field::<u16>()?))
    }

    fn encode_fields(value: (u8, u16), enc: &mut StructEncoder<'_>) -> Result<(), ZclError> {
        enc.field::<u8>(value.0)?;
        enc.field::<u16>(value.1)
    }
}

// ---------------------------------------------------------------------------
// Nesting — ArrayOf<ArrayOf<u8>>
// ---------------------------------------------------------------------------

mod coll_array_of_array_u8_compliance {
    use super::*;
    include!("vectors/collections/array_of_array_u8.rs");

    type OuterSchema = ArrayOf<ArrayOf<u8>>;

    #[test]
    fn decode_outer_count_and_inner_elements() {
        for (outer_wire, inner_wires) in ROUNDTRIP {
            let (outer, n) = OuterSchema::decode(outer_wire)
                .unwrap_or_else(|e| panic!("decode {outer_wire:?} → {e:?}"));
            assert_eq!(n, outer_wire.len());
            assert_eq!(outer.len() as usize, inner_wires.len());
            let mut dec = outer.decoder();
            for &inner_wire in *inner_wires {
                let inner = dec.next().unwrap().unwrap();
                let mut buf = [0u8; 32];
                let m = ArrayOf::<u8>::encode(inner, &mut buf).unwrap();
                assert_eq!(&buf[..m], inner_wire, "inner wire mismatch");
            }
            assert!(dec.next().is_none());
            dec.finish().unwrap();
        }
    }

    #[test]
    fn encoder_builds_from_scratch() {
        let mut buf = [0u8; 128];
        for (wire, inner_wires) in ROUNDTRIP {
            let mut enc = CollectionEncoder::<Array, ArrayOf<u8>>::new(&mut buf).unwrap();
            for &inner_wire in *inner_wires {
                let (inner, _) = ArrayOf::<u8>::decode(inner_wire).unwrap();
                enc.push(inner).unwrap();
            }
            let n = enc.finish().unwrap();
            assert_eq!(&buf[..n], *wire);
        }
    }

    #[test]
    fn null_wire_rejected() {
        for &wire in NULL_WIRE {
            assert_eq!(
                OuterSchema::decode(wire).unwrap_err(),
                ZclError::NullSentinel
            );
        }
    }

    #[test]
    fn nullable_none_decode() {
        for &wire in NULL_WIRE {
            let (val, n) = Nullable::<OuterSchema>::decode(wire).unwrap();
            assert!(val.is_none());
            assert_eq!(n, wire.len());
        }
    }

    #[test]
    fn nullable_none_encode() {
        let mut buf = [0u8; 4];
        for &wire in NULL_WIRE {
            let n = Nullable::<OuterSchema>::encode(None, &mut buf).unwrap();
            assert_eq!(&buf[..n], wire);
        }
    }

    #[test]
    fn type_mismatch_rejected() {
        for &wire in TYPE_MISMATCH {
            assert!(
                matches!(
                    OuterSchema::decode(wire).unwrap_err(),
                    ZclError::TypeIdMismatch { .. }
                ),
                "{wire:?}",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Nesting — ArrayOf<StructOf<PairStruct>>
// ---------------------------------------------------------------------------

mod coll_array_of_struct_pair_compliance {
    use super::*;
    include!("vectors/collections/array_of_struct_pair.rs");

    type OuterSchema = ArrayOf<StructOf<PairStruct>>;

    #[test]
    fn decode_element_values() {
        for (wire, expected_pairs) in ROUNDTRIP {
            let (outer, n) =
                OuterSchema::decode(wire).unwrap_or_else(|e| panic!("decode {wire:?} → {e:?}"));
            assert_eq!(n, wire.len());
            assert_eq!(outer.len() as usize, expected_pairs.len());
            let mut dec = outer.decoder();
            for &expected in *expected_pairs {
                let val = dec.next().unwrap().unwrap();
                assert_eq!(val, expected, "{wire:?}");
            }
            assert!(dec.next().is_none());
            dec.finish().unwrap();
        }
    }

    #[test]
    fn encoder_builds_from_scratch() {
        let mut buf = [0u8; 128];
        for (wire, pairs) in ROUNDTRIP {
            let mut enc = CollectionEncoder::<Array, StructOf<PairStruct>>::new(&mut buf).unwrap();
            for &pair in *pairs {
                enc.push(pair).unwrap();
            }
            let n = enc.finish().unwrap();
            assert_eq!(&buf[..n], *wire);
        }
    }

    #[test]
    fn null_wire_rejected() {
        for &wire in NULL_WIRE {
            assert_eq!(
                OuterSchema::decode(wire).unwrap_err(),
                ZclError::NullSentinel
            );
        }
    }

    #[test]
    fn nullable_none_decode() {
        for &wire in NULL_WIRE {
            let (val, n) = Nullable::<OuterSchema>::decode(wire).unwrap();
            assert!(val.is_none());
            assert_eq!(n, wire.len());
        }
    }

    #[test]
    fn nullable_none_encode() {
        let mut buf = [0u8; 4];
        for &wire in NULL_WIRE {
            let n = Nullable::<OuterSchema>::encode(None, &mut buf).unwrap();
            assert_eq!(&buf[..n], wire);
        }
    }

    #[test]
    fn type_mismatch_rejected() {
        for &wire in TYPE_MISMATCH {
            assert!(
                matches!(
                    OuterSchema::decode(wire).unwrap_err(),
                    ZclError::TypeIdMismatch { .. }
                ),
                "{wire:?}",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Nesting — struct containing an ArrayOf<u8> field
// ---------------------------------------------------------------------------

struct ArrayFieldStruct;

impl ZclStructSchema for ArrayFieldStruct {
    type Value<'a> = (u8, ArrayRef<'a, u8>);

    fn decode_fields<'a>(dec: &mut StructDecoder<'a>) -> Result<Self::Value<'a>, ZclError> {
        Ok((dec.field::<u8>()?, dec.field::<ArrayOf<u8>>()?))
    }

    fn encode_fields(value: Self::Value<'_>, enc: &mut StructEncoder<'_>) -> Result<(), ZclError> {
        enc.field::<u8>(value.0)?;
        enc.field::<ArrayOf<u8>>(value.1)
    }
}

mod coll_struct_with_array_compliance {
    use super::*;
    include!("vectors/collections/struct_with_array.rs");

    #[test]
    fn decode_field_values() {
        for &(wire, (expected_u8, expected_arr)) in ROUNDTRIP {
            let ((u8_val, arr_ref), n) = StructOf::<ArrayFieldStruct>::decode(wire)
                .unwrap_or_else(|e| panic!("decode {wire:?} → {e:?}"));
            assert_eq!(n, wire.len());
            assert_eq!(u8_val, expected_u8);
            assert_eq!(arr_ref.len() as usize, expected_arr.len());
            let mut dec = arr_ref.decoder();
            for &expected_elem in expected_arr {
                assert_eq!(dec.next().unwrap().unwrap(), expected_elem);
            }
            assert!(dec.next().is_none());
            dec.finish().unwrap();
        }
    }

    #[test]
    fn schema_encode_roundtrip() {
        let mut buf = [0u8; 32];
        for &(wire, _) in ROUNDTRIP {
            let (val, _) = StructOf::<ArrayFieldStruct>::decode(wire).unwrap();
            let n = StructOf::<ArrayFieldStruct>::encode(val, &mut buf).unwrap();
            assert_eq!(&buf[..n], wire);
        }
    }

    #[test]
    fn encoder_builds_from_scratch() {
        let mut buf = [0u8; 32];
        let mut arr_scratch = [0u8; 16];
        for &(wire, (u8_val, arr_elems)) in ROUNDTRIP {
            let mut enc = StructEncoder::new(&mut buf).unwrap();
            enc.field::<u8>(u8_val).unwrap();
            let mut arr_enc = CollectionEncoder::<Array, u8>::new(&mut arr_scratch).unwrap();
            for &e in arr_elems {
                arr_enc.push(e).unwrap();
            }
            let arr_n = arr_enc.finish().unwrap();
            let (arr_ref, _) = ArrayOf::<u8>::decode(&arr_scratch[..arr_n]).unwrap();
            enc.field::<ArrayOf<u8>>(arr_ref).unwrap();
            let n = enc.finish().unwrap();
            assert_eq!(&buf[..n], wire);
        }
    }

    #[test]
    fn null_wire_rejected() {
        for &wire in NULL_WIRE {
            assert_eq!(
                StructOf::<ArrayFieldStruct>::decode(wire).unwrap_err(),
                ZclError::NullSentinel,
            );
        }
    }

    #[test]
    fn nullable_none_decode() {
        for &wire in NULL_WIRE {
            let (val, n) = Nullable::<StructOf<ArrayFieldStruct>>::decode(wire).unwrap();
            assert!(val.is_none());
            assert_eq!(n, wire.len());
        }
    }

    #[test]
    fn nullable_none_encode() {
        let mut buf = [0u8; 4];
        for &wire in NULL_WIRE {
            let n = Nullable::<StructOf<ArrayFieldStruct>>::encode(None, &mut buf).unwrap();
            assert_eq!(&buf[..n], wire);
        }
    }
}

// ---------------------------------------------------------------------------
// Struct — (u8, u16) pair via StructEncoder / StructDecoder / StructOf
// ---------------------------------------------------------------------------

mod struct_pair_compliance {
    use super::*;
    include!("vectors/collections/struct_pair.rs");

    #[test]
    fn schema_decode_roundtrip() {
        for &(wire, expected) in ROUNDTRIP {
            let (val, n) = StructOf::<PairStruct>::decode(wire)
                .unwrap_or_else(|e| panic!("decode {wire:?} → {e:?}"));
            assert_eq!(val, expected, "{wire:?}");
            assert_eq!(n, wire.len());
        }
    }

    #[test]
    fn schema_encode_roundtrip() {
        let mut buf = [0u8; 16];
        for &(wire, expected) in ROUNDTRIP {
            let n = StructOf::<PairStruct>::encode(expected, &mut buf)
                .unwrap_or_else(|e| panic!("encode {expected:?} → {e:?}"));
            assert_eq!(&buf[..n], wire, "{expected:?}");
        }
    }

    #[test]
    fn encoder_builds_from_scratch() {
        let mut buf = [0u8; 16];
        for &(wire, (u8_val, u16_val)) in ROUNDTRIP {
            let mut enc = StructEncoder::new(&mut buf).unwrap();
            enc.field::<u8>(u8_val).unwrap();
            enc.field::<u16>(u16_val).unwrap();
            let n = enc.finish().unwrap();
            assert_eq!(&buf[..n], wire);
        }
    }

    #[test]
    fn decoder_streams_fields() {
        for &(wire, (expected_u8, expected_u16)) in ROUNDTRIP {
            let (mut dec, _) = StructDecoder::new(wire)
                .unwrap_or_else(|e| panic!("StructDecoder::new {wire:?} → {e:?}"));
            let v1 = dec.field::<u8>().unwrap();
            let v2 = dec.field::<u16>().unwrap();
            dec.finish().unwrap();
            assert_eq!(v1, expected_u8, "{wire:?}");
            assert_eq!(v2, expected_u16, "{wire:?}");
        }
    }

    #[test]
    fn null_wire_rejected() {
        for &wire in NULL_WIRE {
            assert_eq!(
                StructOf::<PairStruct>::decode(wire).unwrap_err(),
                ZclError::NullSentinel,
                "{wire:?}",
            );
        }
    }

    #[test]
    fn nullable_none_decode() {
        for &wire in NULL_WIRE {
            let (val, n) = Nullable::<StructOf<PairStruct>>::decode(wire)
                .unwrap_or_else(|e| panic!("Nullable decode {wire:?} → {e:?}"));
            assert!(val.is_none(), "{wire:?}");
            assert_eq!(n, wire.len());
        }
    }

    #[test]
    fn nullable_none_encode() {
        let mut buf = [0u8; 4];
        for &wire in NULL_WIRE {
            let n = Nullable::<StructOf<PairStruct>>::encode(None, &mut buf)
                .unwrap_or_else(|e| panic!("Nullable encode None → {e:?}"));
            assert_eq!(&buf[..n], wire);
        }
    }
}
