use crate::types::error::ZclError;
use crate::types::ids::AttributeId;
use crate::types::ids::TypeId;

/// Raw write-attribute record list shared by all three write-attribute
/// commands. Wire format per record: `attribute_id` (u16 LE), `type_id` (u8),
/// value (...).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WriteAttributesPayload<'a>(pub(crate) &'a [u8]);

impl<'a> WriteAttributesPayload<'a> {
    pub fn records(&self) -> WriteAttrIter<'a> {
        WriteAttrIter { remaining: self.0 }
    }
}

/// A single parsed write-attribute record.
#[derive(Debug, PartialEq)]
pub struct WriteAttrRecord<'a> {
    pub attr_id: AttributeId,
    pub type_id: TypeId,
    /// Raw encoded value bytes (after the `type_id` byte on the wire).
    pub value: &'a [u8],
}

/// Parse error from `WriteAttrIter`. Carries the attribute identifier when it
/// was parsed before the error; `attr_id` is `None` only when the record header
/// itself was truncated (fewer than 3 bytes remaining).
#[derive(Debug)]
pub struct WriteAttrParseErr {
    pub attr_id: Option<AttributeId>,
}

/// Fallible iterator over write-attribute records.
pub struct WriteAttrIter<'a> {
    remaining: &'a [u8],
}

impl<'a> Iterator for WriteAttrIter<'a> {
    type Item = Result<WriteAttrRecord<'a>, WriteAttrParseErr>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        Some(self.parse_next())
    }
}

impl<'a> WriteAttrIter<'a> {
    fn parse_next(&mut self) -> Result<WriteAttrRecord<'a>, WriteAttrParseErr> {
        if self.remaining.len() < 3 {
            return Err(WriteAttrParseErr { attr_id: None });
        }
        let attr_id = AttributeId::new(u16::from_le_bytes([self.remaining[0], self.remaining[1]]));
        let type_id = TypeId::from_u8(self.remaining[2]);
        let data = &self.remaining[3..];
        match write_attr_value_len(type_id, data) {
            Ok(val_len) => {
                let value = &data[..val_len];
                self.remaining = &self.remaining[3 + val_len..];
                Ok(WriteAttrRecord {
                    attr_id,
                    type_id,
                    value,
                })
            }
            Err(_) => Err(WriteAttrParseErr {
                attr_id: Some(attr_id),
            }),
        }
    }
}

fn write_attr_value_len(type_id: TypeId, data: &[u8]) -> Result<usize, ZclError> {
    if let Some(n) = type_id.fixed_size() {
        return if data.len() >= n {
            Ok(n)
        } else {
            Err(ZclError::InsufficientBytes)
        };
    }
    match type_id {
        TypeId::OctetString | TypeId::CharacterString => {
            let len = *data.first().ok_or(ZclError::InsufficientBytes)?;
            if len == 0xFF {
                return Ok(1); // null sentinel
            }
            let total = 1 + usize::from(len);
            if data.len() < total {
                Err(ZclError::InsufficientBytes)
            } else {
                Ok(total)
            }
        }
        TypeId::LongOctetString | TypeId::LongCharacterString => {
            if data.len() < 2 {
                return Err(ZclError::InsufficientBytes);
            }
            let len = u16::from_le_bytes([data[0], data[1]]);
            if len == 0xFFFF {
                return Ok(2); // null sentinel
            }
            let total = 2 + usize::from(len);
            if data.len() < total {
                Err(ZclError::InsufficientBytes)
            } else {
                Ok(total)
            }
        }
        _ => Err(ZclError::InvalidValue),
    }
}
