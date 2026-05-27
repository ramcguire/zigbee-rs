#![allow(dead_code)]

use byte::BytesExt;
use heapless::Vec;
use zigbee_types::IeeeAddress;
use zigbee_types::ShortAddress;

use crate::apl::descriptors::node_descriptor::ServerMask;
use crate::apl::descriptors::user_descriptor::UserDescriptor;

pub const NWK_ADDR_REQ_CLUSTER_ID: u16 = 0x0000;
pub const IEEE_ADDR_REQ_CLUSTER_ID: u16 = 0x0001;
pub const NODE_DESC_REQ_CLUSTER_ID: u16 = 0x0002;
pub const SIMPLE_DESC_REQ_CLUSTER_ID: u16 = 0x0004;
pub const ACTIVE_EP_REQ_CLUSTER_ID: u16 = 0x0005;
pub const MATCH_DESC_REQ_CLUSTER_ID: u16 = 0x0006;

pub const MATCH_DESC_CLUSTER_LIST_CAPACITY: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryRequestError {
    InvalidRequestType,
    InvalidStartIndex,
    TooManyClusters,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressRequestType {
    Single = 0x00,
    Extended = 0x01,
}

impl AddressRequestType {
    pub const fn from_u8(value: u8) -> Result<Self, DiscoveryRequestError> {
        match value {
            0x00 => Ok(Self::Single),
            0x01 => Ok(Self::Extended),
            _ => Err(DiscoveryRequestError::InvalidRequestType),
        }
    }
}

const fn validate_start_index(
    request_type: AddressRequestType,
    start_index: u8,
) -> Result<(), DiscoveryRequestError> {
    if request_type as u8 == AddressRequestType::Single as u8 && start_index != 0 {
        Err(DiscoveryRequestError::InvalidStartIndex)
    } else {
        Ok(())
    }
}

/// 2.4.3.1.1 NWK_addr_req.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NWKAddrReq {
    pub ieee_address: IeeeAddress,
    pub request_type: AddressRequestType,
    pub start_index: u8,
}

impl NWKAddrReq {
    pub const CLUSTER_ID: u16 = NWK_ADDR_REQ_CLUSTER_ID;

    pub const fn new(
        ieee_address: IeeeAddress,
        request_type: AddressRequestType,
        start_index: u8,
    ) -> Result<Self, DiscoveryRequestError> {
        match validate_start_index(request_type, start_index) {
            Ok(()) => Ok(Self {
                ieee_address,
                request_type,
                start_index,
            }),
            Err(e) => Err(e),
        }
    }

    pub fn write_payload(self, seq: u8, buf: &mut [u8]) -> byte::Result<usize> {
        let offset = &mut 0;
        buf.write(offset, seq)?;
        buf.write_with(offset, self.ieee_address, ())?;
        buf.write(offset, self.request_type as u8)?;
        buf.write(offset, self.start_index)?;
        Ok(*offset)
    }
}

/// 2.4.3.1.2 IEEE_addr_req.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IeeeAddrReq {
    pub nwk_addr_of_interest: ShortAddress,
    pub request_type: AddressRequestType,
    pub start_index: u8,
}

impl IeeeAddrReq {
    pub const CLUSTER_ID: u16 = IEEE_ADDR_REQ_CLUSTER_ID;

    pub const fn new(
        nwk_addr_of_interest: ShortAddress,
        request_type: AddressRequestType,
        start_index: u8,
    ) -> Result<Self, DiscoveryRequestError> {
        match validate_start_index(request_type, start_index) {
            Ok(()) => Ok(Self {
                nwk_addr_of_interest,
                request_type,
                start_index,
            }),
            Err(e) => Err(e),
        }
    }

    pub fn write_payload(self, seq: u8, buf: &mut [u8]) -> byte::Result<usize> {
        let offset = &mut 0;
        buf.write(offset, seq)?;
        buf.write_with(offset, self.nwk_addr_of_interest, ())?;
        buf.write(offset, self.request_type as u8)?;
        buf.write(offset, self.start_index)?;
        Ok(*offset)
    }
}

/// 2.4.3.1.3 Node_Desc_req.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeDescReq {
    pub nwk_addr_of_interest: ShortAddress,
}

impl NodeDescReq {
    pub const CLUSTER_ID: u16 = NODE_DESC_REQ_CLUSTER_ID;

    pub const fn new(nwk_addr_of_interest: ShortAddress) -> Self {
        Self {
            nwk_addr_of_interest,
        }
    }

    pub fn write_payload(self, seq: u8, buf: &mut [u8]) -> byte::Result<usize> {
        let offset = &mut 0;
        buf.write(offset, seq)?;
        buf.write_with(offset, self.nwk_addr_of_interest, ())?;
        Ok(*offset)
    }
}

/// 2.4.3.1.4 Power_Desc_req.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowerDescReq {
    pub nwk_addr_of_interest: ShortAddress,
}

/// 2.4.3.1.5 Simple_Desc_req.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimpleDescReq {
    pub nwk_addr_of_interest: ShortAddress,
    pub endpoint: u8,
}

impl SimpleDescReq {
    pub const CLUSTER_ID: u16 = SIMPLE_DESC_REQ_CLUSTER_ID;

    pub const fn new(nwk_addr_of_interest: ShortAddress, endpoint: u8) -> Self {
        Self {
            nwk_addr_of_interest,
            endpoint,
        }
    }

    pub fn write_payload(self, seq: u8, buf: &mut [u8]) -> byte::Result<usize> {
        let offset = &mut 0;
        buf.write(offset, seq)?;
        buf.write_with(offset, self.nwk_addr_of_interest, ())?;
        buf.write(offset, self.endpoint)?;
        Ok(*offset)
    }
}

/// 2.4.3.1.6 Active_EP_req.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveEpReq {
    pub nwk_addr_of_interest: ShortAddress,
}

pub type ActivePeReq = ActiveEpReq;

impl ActiveEpReq {
    pub const CLUSTER_ID: u16 = ACTIVE_EP_REQ_CLUSTER_ID;

    pub const fn new(nwk_addr_of_interest: ShortAddress) -> Self {
        Self {
            nwk_addr_of_interest,
        }
    }

    pub fn write_payload(self, seq: u8, buf: &mut [u8]) -> byte::Result<usize> {
        let offset = &mut 0;
        buf.write(offset, seq)?;
        buf.write_with(offset, self.nwk_addr_of_interest, ())?;
        Ok(*offset)
    }
}

/// 2.4.3.1.7 Match_Desc_req.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchDescReq {
    pub nwk_addr_of_interest: ShortAddress,
    pub profile_id: u16,
    pub in_cluster_list: Vec<u16, MATCH_DESC_CLUSTER_LIST_CAPACITY>,
    pub out_cluster_list: Vec<u16, MATCH_DESC_CLUSTER_LIST_CAPACITY>,
}

impl MatchDescReq {
    pub const CLUSTER_ID: u16 = MATCH_DESC_REQ_CLUSTER_ID;

    pub fn new(
        nwk_addr_of_interest: ShortAddress,
        profile_id: u16,
        in_clusters: &[u16],
        out_clusters: &[u16],
    ) -> Result<Self, DiscoveryRequestError> {
        let mut in_cluster_list = Vec::new();
        for cluster in in_clusters {
            in_cluster_list
                .push(*cluster)
                .map_err(|_| DiscoveryRequestError::TooManyClusters)?;
        }

        let mut out_cluster_list = Vec::new();
        for cluster in out_clusters {
            out_cluster_list
                .push(*cluster)
                .map_err(|_| DiscoveryRequestError::TooManyClusters)?;
        }

        Ok(Self {
            nwk_addr_of_interest,
            profile_id,
            in_cluster_list,
            out_cluster_list,
        })
    }

    #[allow(clippy::cast_possible_truncation)] // cluster list lengths are ZDP-bounded to u8
    pub fn write_payload(&self, seq: u8, buf: &mut [u8]) -> byte::Result<usize> {
        let offset = &mut 0;
        buf.write(offset, seq)?;
        buf.write_with(offset, self.nwk_addr_of_interest, ())?;
        buf.write_with(offset, self.profile_id, byte::LE)?;
        buf.write(offset, self.in_cluster_list.len() as u8)?;
        for cluster in &self.in_cluster_list {
            buf.write_with(offset, *cluster, byte::LE)?;
        }
        buf.write(offset, self.out_cluster_list.len() as u8)?;
        for cluster in &self.out_cluster_list {
            buf.write_with(offset, *cluster, byte::LE)?;
        }
        Ok(*offset)
    }
}

/// 2.4.3.1.8 Complex_Desc_req.
pub struct ComplexDescReq {
    pub nwk_addr_of_interest: ShortAddress,
}

/// 2.4.3.1.9 User_Desc_req.
pub struct UserDescReq {
    pub nwk_addr_of_interest: ShortAddress,
}

// 2.4.3.1.11 Device_annce — see crate::zdp::device_annce::DeviceAnnce.

/// 2.4.3.1.11 Parent_annce.
pub struct ChildInfo(pub IeeeAddress);

pub struct ParentAnnce {
    pub number_of_children: u8,
    pub children: Vec<ChildInfo, 32>,
}

/// 2.4.3.1.13 User_Desc_set.
pub struct UserDescSet<'a> {
    pub nwk_addr_of_interest: ShortAddress,
    pub length: u8,
    pub user_description: UserDescriptor<'a>,
}

/// 2.4.3.1.14 System_Server_Discovery_req.
pub struct SystemServerDiscoveryReq {
    pub server_mask: ServerMask,
}

/// 2.4.3.1.15 Discovery_store_req.
pub struct DiscoveryStoreReq {
    pub nwk_addr: ShortAddress,
    pub ieee_addr: IeeeAddress,
    pub node_desc_size: u8,
    pub power_desc_size: u8,
    pub active_ep_size: u8,
    pub simple_desc_count: u8,
    pub simple_desc_size_list: Vec<u8, 255>,
}

/// 2.4.3.1.16 Node_Desc_store_req.
pub struct NodeDescStoreReq {
    pub nwk_addr: ShortAddress,
    pub ieee_addr: IeeeAddress,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nwk_addr_req_payload_is_byte_exact() {
        let request = NWKAddrReq::new(
            IeeeAddress(0x0102_0304_0506_0708),
            AddressRequestType::Single,
            0,
        )
        .unwrap();
        let mut buf = [0u8; 16];

        let len = request.write_payload(0x2a, &mut buf).unwrap();

        assert_eq!(len, 11);
        assert_eq!(
            &buf[..len],
            &[
                0x2a, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x00
            ]
        );
    }

    #[test]
    fn ieee_addr_req_payload_is_byte_exact() {
        let request =
            IeeeAddrReq::new(ShortAddress(0x1234), AddressRequestType::Extended, 0x05).unwrap();
        let mut buf = [0u8; 8];

        let len = request.write_payload(0x2a, &mut buf).unwrap();

        assert_eq!(len, 5);
        assert_eq!(&buf[..len], &[0x2a, 0x34, 0x12, 0x01, 0x05]);
    }

    #[test]
    fn node_desc_req_payload_is_byte_exact() {
        let request = NodeDescReq::new(ShortAddress(0x1234));
        let mut buf = [0u8; 4];

        let len = request.write_payload(0x2a, &mut buf).unwrap();

        assert_eq!(len, 3);
        assert_eq!(&buf[..len], &[0x2a, 0x34, 0x12]);
    }

    #[test]
    fn simple_desc_req_payload_is_byte_exact() {
        let request = SimpleDescReq::new(ShortAddress(0x1234), 0x0b);
        let mut buf = [0u8; 4];

        let len = request.write_payload(0x2a, &mut buf).unwrap();

        assert_eq!(len, 4);
        assert_eq!(&buf[..len], &[0x2a, 0x34, 0x12, 0x0b]);
    }

    #[test]
    fn active_ep_req_payload_is_byte_exact() {
        let request = ActiveEpReq::new(ShortAddress(0x1234));
        let mut buf = [0u8; 4];

        let len = request.write_payload(0x2a, &mut buf).unwrap();

        assert_eq!(len, 3);
        assert_eq!(&buf[..len], &[0x2a, 0x34, 0x12]);
    }

    #[test]
    fn match_desc_req_payload_is_byte_exact() {
        let request =
            MatchDescReq::new(ShortAddress(0x1234), 0x0104, &[0x0006, 0x0008], &[0x0019]).unwrap();
        let mut buf = [0u8; 16];

        let len = request.write_payload(0x2a, &mut buf).unwrap();

        assert_eq!(len, 13);
        assert_eq!(
            &buf[..len],
            &[
                0x2a, 0x34, 0x12, 0x04, 0x01, 0x02, 0x06, 0x00, 0x08, 0x00, 0x01, 0x19, 0x00
            ]
        );
    }

    #[test]
    fn single_address_request_rejects_non_zero_start_index() {
        assert_eq!(
            NWKAddrReq::new(
                IeeeAddress(0x0102_0304_0506_0708),
                AddressRequestType::Single,
                1,
            ),
            Err(DiscoveryRequestError::InvalidStartIndex)
        );
    }

    #[test]
    fn match_desc_rejects_oversized_cluster_list() {
        let clusters = [0u16; MATCH_DESC_CLUSTER_LIST_CAPACITY + 1];

        assert_eq!(
            MatchDescReq::new(ShortAddress(0x1234), 0x0104, &clusters, &[]),
            Err(DiscoveryRequestError::TooManyClusters)
        );
    }
}
