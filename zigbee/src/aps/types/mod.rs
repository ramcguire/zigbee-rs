#![allow(dead_code)]

use super::error::ApsError;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SrcAddrMode {
    Reserved = 0x00,
    #[default]
    Short,
    Extended = 0x02,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DstAddrMode {
    #[default]
    None,
    Group = 0x01,
    Network = 0x02,
    Extended = 0x03,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Address {
    #[default]
    None,
    Group(u16),
    Network(u16),
    Extended(u64),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TxOptions(pub u8);

impl TxOptions {
    pub const SECURITY_ENABLED: Self = Self(0x01);
    pub const USE_NETWORK_KEY: Self = Self(0x02);
    pub const ACKNOWLEDGED: Self = Self(0x04);
    pub const FRAGMENTATION_PERMITTED: Self = Self(0x08);
    pub const INCLUDE_EXTENDED_NONCE: Self = Self(0x10);

    pub const fn security_enabled(self) -> bool {
        self.0 & Self::SECURITY_ENABLED.0 != 0
    }

    pub const fn use_network_key(self) -> bool {
        self.0 & Self::USE_NETWORK_KEY.0 != 0
    }

    pub const fn ack_requested(self) -> bool {
        self.0 & Self::ACKNOWLEDGED.0 != 0
    }

    pub const fn fragmentation_permitted(self) -> bool {
        self.0 & Self::FRAGMENTATION_PERMITTED.0 != 0
    }

    pub const fn include_extended_nonce(self) -> bool {
        self.0 & Self::INCLUDE_EXTENDED_NONCE.0 != 0
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SrcEndpoint {
    pub(crate) value: u8,
}

impl SrcEndpoint {
    pub fn new(value: u8) -> Result<Self, ApsError> {
        if value <= 254 {
            Ok(Self { value })
        } else {
            Err(ApsError::InvalidValue)
        }
    }
    pub const fn value(self) -> u8 {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_value_should_succeed() {
        let src_endpoint = SrcEndpoint::new(254);

        assert!(src_endpoint.is_ok());
    }

    #[test]
    fn oversized_value_should_fail() {
        let src_endpoint = SrcEndpoint::new(255);

        assert!(src_endpoint.is_err());
    }
}
