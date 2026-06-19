//! Application Support Sub-Layer Data Entity
//!
//! The APSDE provides data transfer between application endpoints through the
//! NWK layer. This module intentionally implements only the un-fragmented data
//! path used by ZDO and ZCL dispatch; unsupported APS features return explicit
//! statuses rather than pretending success.

use byte::TryRead;
use zigbee_mac::mlme::Mlme;
use zigbee_types::ShortAddress;

use super::apsme::Apsme;
use super::frame::Frame;
use super::frame::frame_control::DeliveryMode;
use super::frame::frame_control::FrameType;
use super::frame::header::Header;
use super::types::Address;
use super::types::DstAddrMode;
use super::types::SrcAddrMode;
use super::types::SrcEndpoint;
use super::types::TxOptions;
use crate::aps::aib;
use crate::nwk::frame::DataFrame as NwkDataFrame;
use crate::nwk::nlme::NetworkError;
use crate::nwk::nlme::Nlme;

/// Maximum ASDU this implementation can place in its fixed APS data buffer.
pub const MAX_ASDU_LENGTH: usize = super::apsme::MAX_DATA_ASDU_LEN;

/// Application support sub-layer data entity – service access point.
///
/// 2.2.4.1.1.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Apsde;

impl Apsde {
    /// APSDE-DATA.request.
    pub(crate) async fn data_request<M: Mlme>(
        apsme: &mut Apsme,
        nlme: &mut Nlme<M>,
        request: ApsdeSapRequest<'_>,
    ) -> ApsdeSapConfirm {
        let status = data_request_status(apsme, nlme, &request).await;

        ApsdeSapConfirm {
            dst_addr_mode: request.dst_addr_mode,
            dst_address: request.dst_address,
            dst_endpoint: request.dst_endpoint,
            src_endpoint: request.src_endpoint,
            status,
            tx_time: 0,
        }
    }

    /// Poll one NWK data frame and parse the contained APS data frame.
    pub async fn poll_data_indication<'a, M: Mlme>(
        nlme: &mut Nlme<M>,
        buf: &'a mut [u8],
        retries: u8,
    ) -> Result<ApsdeSapIndication<'a>, NetworkError> {
        let buf_ptr = buf.as_mut_ptr();
        let nwk_data = nlme.poll_nwk_data(buf, retries).await?;
        let payload_range = nwk_data.payload_range();
        let source = nwk_data.header.source;
        let destination = nwk_data.header.destination;
        let nwk_secured = nwk_data.header.frame_control.security_flag();
        let aps_secured = Header::try_read(nwk_data.payload, ())?
            .0
            .frame_control
            .security_flag();
        if aps_secured {
            drop(nwk_data);
            // SAFETY: `payload_range` was produced by parsing `buf`, and `nwk_data`
            // is dropped before taking the mutable subslice for in-place APS decrypt.
            let aps_buf = unsafe {
                core::slice::from_raw_parts_mut(
                    buf_ptr.add(payload_range.start),
                    payload_range.len(),
                )
            };
            let aps_frame =
                crate::security::SecurityContext::get().decrypt_aps_frame_in_place(aps_buf)?;
            let Frame::Data(data) = aps_frame else {
                return Err(NetworkError::InvalidFrame);
            };
            data_frame_to_indication(source, destination, nwk_secured, data)
        } else {
            parse_data_indication_parts(source, destination, nwk_secured, nwk_data.payload)
        }
    }
}
async fn data_request_status<M: Mlme>(
    apsme: &mut Apsme,
    nlme: &mut Nlme<M>,
    request: &ApsdeSapRequest<'_>,
) -> ApsdeSapConfirmStatus {
    if request.asdu.len() > MAX_ASDU_LENGTH {
        return ApsdeSapConfirmStatus::AsduTooLong;
    }

    if request.tx_options.fragmentation_permitted() || request.use_alias {
        return ApsdeSapConfirmStatus::UnsupportedFeature;
    }

    let result = match (request.dst_addr_mode, request.dst_address) {
        (DstAddrMode::Network, Address::Network(destination)) if is_broadcast(destination) => {
            apsme
                .broadcast_data(
                    nlme,
                    ShortAddress(destination),
                    request.dst_endpoint,
                    request.cluster_id,
                    request.profile_id,
                    request.src_endpoint.value(),
                    request.asdu,
                )
                .await
        }
        (DstAddrMode::Network, Address::Network(destination)) => {
            apsme
                .unicast_data(
                    nlme,
                    ShortAddress(destination),
                    request.dst_endpoint,
                    request.cluster_id,
                    request.profile_id,
                    request.src_endpoint.value(),
                    request.asdu,
                    request.tx_options,
                )
                .await
        }
        (DstAddrMode::None, Address::None) => return ApsdeSapConfirmStatus::NoBoundDevice,
        (DstAddrMode::Group, Address::Group(_)) | (DstAddrMode::Extended, Address::Extended(_)) => {
            return ApsdeSapConfirmStatus::UnsupportedFeature;
        }
        _ => return ApsdeSapConfirmStatus::InvalidParameter,
    };

    match result {
        Ok(()) => ApsdeSapConfirmStatus::Success,
        Err(NetworkError::NotJoined) => ApsdeSapConfirmStatus::NoShortAddress,
        Err(NetworkError::MacError(zigbee_mac::mlme::MacError::NoAck)) => {
            ApsdeSapConfirmStatus::NoAck
        }
        Err(NetworkError::MacError(_)) => ApsdeSapConfirmStatus::NoAck,
        Err(NetworkError::SecurityError(_)) => ApsdeSapConfirmStatus::SecurityFail,
        Err(
            NetworkError::InvalidFrame
            | NetworkError::ParseError
            | NetworkError::NoTransportKey
            | NetworkError::MissingSecurityMaterial,
        ) => ApsdeSapConfirmStatus::InvalidParameter,
    }
}

pub(crate) fn is_broadcast(address: u16) -> bool {
    (0xfffc..=0xffff).contains(&address)
}

/// Parse an already-received NWK data frame as an APS data indication.
pub(crate) fn parse_data_indication<'a>(
    nwk_data: &NwkDataFrame<'a>,
) -> Result<ApsdeSapIndication<'a>, NetworkError> {
    parse_data_indication_parts(
        nwk_data.header.source,
        nwk_data.header.destination,
        nwk_data.header.frame_control.security_flag(),
        nwk_data.payload,
    )
}

pub(crate) fn parse_data_indication_parts<'a>(
    source: ShortAddress,
    destination: ShortAddress,
    nwk_secured: bool,
    payload: &'a [u8],
) -> Result<ApsdeSapIndication<'a>, NetworkError> {
    let (header, header_len) = Header::try_read(payload, ())?;
    if header.frame_control.frame_type() != FrameType::Data {
        return Err(NetworkError::InvalidFrame);
    }

    let asdu = &payload[header_len..];
    let Frame::Data(data) = Frame::from_payload(header, asdu)? else {
        return Err(NetworkError::InvalidFrame);
    };

    data_frame_to_indication(source, destination, nwk_secured, data)
}

pub(crate) fn data_frame_to_indication<'a>(
    source: ShortAddress,
    destination: ShortAddress,
    nwk_secured: bool,
    data: super::frame::DataFrame<'a>,
) -> Result<ApsdeSapIndication<'a>, NetworkError> {
    let delivery = match data.header.frame_control.delivery_mode() {
        DeliveryMode::Unicast => ApsDeliveryMode::Unicast,
        DeliveryMode::Broadcast => ApsDeliveryMode::Broadcast,
        DeliveryMode::GroupAddressing => ApsDeliveryMode::Group,
        DeliveryMode::Reserved => return Err(NetworkError::InvalidFrame),
    };

    let (dst_addr_mode, dst_address, dst_endpoint) = match delivery {
        ApsDeliveryMode::Group => {
            let group = data
                .header
                .group_address
                .ok_or(NetworkError::InvalidFrame)?;
            let group_table = aib::get_ref().group_table();
            let entry = group_table
                .iter()
                .find(|entry| entry.group_address == group.0)
                .ok_or(NetworkError::InvalidFrame)?;
            (DstAddrMode::Group, Address::Group(group.0), entry.endpoint)
        }
        ApsDeliveryMode::Unicast | ApsDeliveryMode::Broadcast => {
            let dst_endpoint = data
                .header
                .destination_endpoint
                .ok_or(NetworkError::InvalidFrame)?;
            (
                DstAddrMode::Network,
                Address::Network(destination.0),
                dst_endpoint,
            )
        }
    };

    let cluster_id = data.header.cluster_id.ok_or(NetworkError::InvalidFrame)?;
    let profile_id = data.header.profile_id.ok_or(NetworkError::InvalidFrame)?;
    let src_endpoint = data
        .header
        .source_endpoint
        .ok_or(NetworkError::InvalidFrame)?;

    Ok(ApsdeSapIndication {
        dst_addr_mode,
        dst_address,
        dst_endpoint,
        src_addr_mode: SrcAddrMode::Short,
        src_address: Address::Network(source.0),
        src_endpoint,
        profile_id,
        cluster_id,
        asdu: data.payload,
        delivery,
        status: ApsdeSapIndicationStatus::Success,
        security_status: if data.header.frame_control.security_flag() {
            SecurityStatus::SecuredLinkKey
        } else if nwk_secured {
            SecurityStatus::SecuredNwkKey
        } else {
            SecurityStatus::Unsecured
        },
        link_quality: 0,
        rx_time: 0,
    })
}

// 2.2.4.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApsdeSapRequest<'a> {
    pub dst_addr_mode: DstAddrMode,
    pub dst_address: Address,
    pub dst_endpoint: u8,
    pub profile_id: u16,
    pub cluster_id: u16,
    pub src_endpoint: SrcEndpoint,
    pub asdu: &'a [u8],
    pub tx_options: TxOptions,
    pub use_alias: bool,
    pub alias_src_addr: u16,
    pub alias_seq_number: u8,
    pub radius_counter: u8,
}

impl<'a> ApsdeSapRequest<'a> {
    pub const fn new_unicast(
        destination: ShortAddress,
        dst_endpoint: u8,
        profile_id: u16,
        cluster_id: u16,
        src_endpoint: SrcEndpoint,
        asdu: &'a [u8],
    ) -> Self {
        Self {
            dst_addr_mode: DstAddrMode::Network,
            dst_address: Address::Network(destination.0),
            dst_endpoint,
            profile_id,
            cluster_id,
            src_endpoint,
            asdu,
            tx_options: TxOptions(0),
            use_alias: false,
            alias_src_addr: 0,
            alias_seq_number: 0,
            radius_counter: 0,
        }
    }
}

/// The status of the corresponding request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ApsdeSapConfirmStatus {
    /// The request to transmit was successful.
    #[default]
    Success,
    /// No corresponding 16-bit NWK address found.
    NoShortAddress,
    /// No binding table entries found with the requested source endpoint and
    /// cluster.
    NoBoundDevice,
    /// Security processing failed.
    SecurityFail,
    /// One or more APS acknowledgements were not received, or APS ACK is
    /// unsupported.
    NoAck,
    /// ASDU is too large for a single un-fragmented APS frame.
    AsduTooLong,
    /// Requested APS feature is not implemented by this stack path.
    UnsupportedFeature,
    /// Request fields are inconsistent.
    InvalidParameter,
}

// 2.2.4.1.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApsdeSapConfirm {
    pub dst_addr_mode: DstAddrMode,
    pub dst_address: Address,
    pub dst_endpoint: u8,
    pub src_endpoint: SrcEndpoint,
    pub status: ApsdeSapConfirmStatus,
    pub tx_time: u8,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ApsdeSapIndicationStatus {
    #[default]
    Success,
    DefragUnsupported,
    DefragDeferred,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SecurityStatus {
    #[default]
    Unsecured,
    SecuredNwkKey,
    SecuredLinkKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApsDeliveryMode {
    Unicast,
    Broadcast,
    Group,
}

// 2.2.4.1.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApsdeSapIndication<'a> {
    pub dst_addr_mode: DstAddrMode,
    pub dst_address: Address,
    pub dst_endpoint: u8,
    pub src_addr_mode: SrcAddrMode,
    pub src_address: Address,
    pub src_endpoint: u8,
    pub profile_id: u16,
    pub cluster_id: u16,
    pub asdu: &'a [u8],
    pub delivery: ApsDeliveryMode,
    pub status: ApsdeSapIndicationStatus,
    pub security_status: SecurityStatus,
    pub link_quality: u8,
    pub rx_time: u8,
}

#[cfg(test)]
mod tests {
    use core::future::Future;

    use byte::TryRead;
    use zigbee_mac::Address as MacAddress;
    use zigbee_mac::MacShortAddress;
    use zigbee_mac::PanId;
    use zigbee_mac::mlme::AssociationResponse;
    use zigbee_mac::mlme::MacError;
    use zigbee_mac::mlme::ScanResult;
    use zigbee_mac::mlme::ScanType;
    use zigbee_types::IeeeAddress;
    use zigbee_types::StorageVec;

    use super::*;
    use crate::aps::aib;
    use crate::aps::aib::AibStorage;
    use crate::nwk::frame::header::Header as NwkHeader;
    use crate::nwk::nib;
    use crate::nwk::nib::DeviceType;
    use crate::nwk::nib::NibStorage;
    use crate::nwk::nib::NwkNeighbor;
    use crate::nwk::nib::relationship;

    #[allow(clippy::panic)]
    fn block_on<F: Future>(f: F) -> F::Output {
        use core::pin::pin;
        use core::task::Context;
        use core::task::Poll;
        use core::task::RawWaker;
        use core::task::RawWakerVTable;
        use core::task::Waker;

        fn noop(_: *const ()) {}
        fn clone(p: *const ()) -> RawWaker {
            RawWaker::new(p, &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);

        let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
        let mut cx = Context::from_waker(&waker);
        let mut f = pin!(f);

        match f.as_mut().poll(&mut cx) {
            Poll::Ready(val) => val,
            Poll::Pending => panic!("block_on: future returned Pending"),
        }
    }

    mockall::mock! {
        Mlme {}
        impl Mlme for Mlme {
            async fn scan_network(
                &mut self,
                ty: ScanType,
                channels: core::ops::Range<u8>,
                duration: u8,
            ) -> Result<ScanResult, MacError>;
            async fn associate(
                &mut self,
                channel: u8,
                dest: MacAddress,
                capabilities: zigbee_mac::CapabilityInformation,
            ) -> Result<AssociationResponse, MacError>;
            async fn poll_data(
                &mut self,
                coord_address: MacAddress,
                buf: &mut [u8],
            ) -> Result<(usize, u8), MacError>;
            async fn transmit_data(
                &mut self,
                dest: MacAddress,
                payload: &[u8],
            ) -> Result<(), MacError>;
        }
    }

    fn make_parent() -> NwkNeighbor {
        NwkNeighbor {
            network_address: ShortAddress(0x0000),
            extended_address: IeeeAddress(0),
            device_type: DeviceType::Coordinator,
            rx_on_when_idle: true,
            end_device_configuration: 0,
            relationship: relationship::PARENT,
            transmit_failure: 0,
            lqi: 255,
            outgoing_cost: 0,
            age: 0,
            keepalive_received: false,
            extended_pan_id: IeeeAddress(0),
            logical_channel: 11,
            depth: 0,
            permit_joining: false,
            potential_parent: 0,
            router_capacity: true,
            end_device_capacity: true,
            update_id: 0,
            pan_id: 0xabcd,
        }
    }

    fn make_nlme(mac: MockMlme) -> (std::sync::MutexGuard<'static, ()>, Nlme<MockMlme>) {
        let guard = nib::TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        nib::try_init(NibStorage::default());
        nib::reset();
        aib::try_init(AibStorage::default());
        aib::reset();
        let nlme = Nlme::new(mac);
        nlme.nib().set_network_address(0x5678);
        nlme.nib().set_panid(0xabcd);
        let mut neighbors = StorageVec::new();
        neighbors.push(make_parent()).unwrap();
        nlme.nib().set_neighbor_table(neighbors);
        (guard, nlme)
    }

    fn aps_payload_from_nwk(payload: &[u8]) -> &[u8] {
        let (_, header_len) = NwkHeader::try_read(payload, ()).unwrap();
        &payload[header_len..]
    }

    #[test]
    fn data_request_unicast_writes_expected_aps_payload() {
        let mut mac = MockMlme::new();
        mac.expect_transmit_data()
            .withf(|dest, payload| {
                assert_eq!(
                    *dest,
                    MacAddress::Short(PanId(0xabcd), MacShortAddress(0x0000))
                );
                let aps = aps_payload_from_nwk(payload);
                aps == [0x00, 0x0b, 0x06, 0x00, 0x04, 0x01, 0x01, 0x01, 0xaa, 0xbb]
            })
            .returning(|_, _| Ok(()));

        let (_guard, mut nlme) = make_nlme(mac);
        let mut apsme = Apsme::new();
        let request = ApsdeSapRequest::new_unicast(
            ShortAddress(0x1234),
            0x0b,
            0x0104,
            0x0006,
            SrcEndpoint::new(0x01).unwrap(),
            &[0xaa, 0xbb],
        );

        let confirm = block_on(Apsde::data_request(&mut apsme, &mut nlme, request));

        assert_eq!(confirm.status, ApsdeSapConfirmStatus::Success);
    }

    #[test]
    fn data_request_broadcast_writes_expected_aps_payload() {
        let mut mac = MockMlme::new();
        mac.expect_transmit_data()
            .withf(|dest, payload| {
                assert_eq!(
                    *dest,
                    MacAddress::Short(PanId(0xabcd), MacShortAddress(0xfffd))
                );
                let aps = aps_payload_from_nwk(payload);
                aps == [0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xaa]
            })
            .returning(|_, _| Ok(()));

        let (_guard, mut nlme) = make_nlme(mac);
        let mut apsme = Apsme::new();
        let request = ApsdeSapRequest::new_unicast(
            ShortAddress(0xfffd),
            0x00,
            0x0000,
            0x0000,
            SrcEndpoint::new(0x00).unwrap(),
            &[0xaa],
        );

        let confirm = block_on(Apsde::data_request(&mut apsme, &mut nlme, request));

        assert_eq!(confirm.status, ApsdeSapConfirmStatus::Success);
    }

    #[test]
    fn data_request_oversized_asdu_returns_asdu_too_long() {
        let (_guard, mut nlme) = make_nlme(MockMlme::new());
        let mut apsme = Apsme::new();
        let payload = [0u8; MAX_ASDU_LENGTH + 1];
        let request = ApsdeSapRequest::new_unicast(
            ShortAddress(0x1234),
            0x0b,
            0x0104,
            0x0006,
            SrcEndpoint::new(0x01).unwrap(),
            &payload,
        );

        let confirm = block_on(Apsde::data_request(&mut apsme, &mut nlme, request));

        assert_eq!(confirm.status, ApsdeSapConfirmStatus::AsduTooLong);
    }

    #[test]
    fn data_request_ack_option_sets_ack_request_and_transmits() {
        let mut mac = MockMlme::new();
        mac.expect_transmit_data()
            .withf(|_, payload| {
                aps_payload_from_nwk(payload)
                    == [0x40, 0x0b, 0x06, 0x00, 0x04, 0x01, 0x01, 0x01, 0xaa]
            })
            .returning(|_, _| Ok(()));
        let (_guard, mut nlme) = make_nlme(mac);
        let mut apsme = Apsme::new();
        let mut request = ApsdeSapRequest::new_unicast(
            ShortAddress(0x1234),
            0x0b,
            0x0104,
            0x0006,
            SrcEndpoint::new(0x01).unwrap(),
            &[0xaa],
        );
        request.tx_options = TxOptions::ACKNOWLEDGED;

        let confirm = block_on(Apsde::data_request(&mut apsme, &mut nlme, request));

        assert_eq!(confirm.status, ApsdeSapConfirmStatus::Success);
    }

    #[test]
    fn poll_data_indication_parses_aps_data_header() {
        #[rustfmt::skip]
        const NWK_APS_DATA: &[u8] = &[
            0x08, 0x00, 0x78, 0x56, 0x34, 0x12, 30, 0xaa,
            0x00, 0x01, 0x06, 0x00, 0x04, 0x01, 0x02, 0x55, 0x09, 0x08,
        ];

        let mut mac = MockMlme::new();
        mac.expect_poll_data()
            .withf(|coord_address, _| {
                *coord_address == MacAddress::Short(PanId(0xabcd), MacShortAddress(0x0000))
            })
            .returning(|_, buf| {
                buf[..NWK_APS_DATA.len()].copy_from_slice(NWK_APS_DATA);
                Ok((NWK_APS_DATA.len(), 200))
            });

        let (_guard, mut nlme) = make_nlme(mac);
        let mut buf = [0u8; 64];

        let indication = block_on(Apsde::poll_data_indication(&mut nlme, &mut buf, 1)).unwrap();

        assert_eq!(indication.dst_addr_mode, DstAddrMode::Network);
        assert_eq!(indication.dst_address, Address::Network(0x5678));
        assert_eq!(indication.dst_endpoint, 0x01);
        assert_eq!(indication.src_addr_mode, SrcAddrMode::Short);
        assert_eq!(indication.src_address, Address::Network(0x1234));
        assert_eq!(indication.src_endpoint, 0x02);
        assert_eq!(indication.profile_id, 0x0104);
        assert_eq!(indication.cluster_id, 0x0006);
        assert_eq!(indication.delivery, ApsDeliveryMode::Unicast);
        assert_eq!(indication.asdu, &[0x09, 0x08]);
    }
}
