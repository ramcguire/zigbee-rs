//! ZDO discovery request send helpers (§2.4.3.1, §2.5.2).

use zigbee_mac::mlme::Mlme;
use zigbee_types::ShortAddress;

use crate::aps::apsde::Apsde;
use crate::aps::apsde::ApsdeSapConfirmStatus;
use crate::aps::apsde::ApsdeSapRequest;
use crate::aps::apsme::Apsme;
use crate::aps::types::SrcEndpoint;
use crate::nwk::nlme::NetworkError;
use crate::nwk::nlme::Nlme;
use crate::zdp::client_services::discovery::ACTIVE_EP_REQ_CLUSTER_ID;
use crate::zdp::client_services::discovery::ActiveEpReq;
use crate::zdp::client_services::discovery::IEEE_ADDR_REQ_CLUSTER_ID;
use crate::zdp::client_services::discovery::IeeeAddrReq;
use crate::zdp::client_services::discovery::MATCH_DESC_REQ_CLUSTER_ID;
use crate::zdp::client_services::discovery::MatchDescReq;
use crate::zdp::client_services::discovery::NODE_DESC_REQ_CLUSTER_ID;
use crate::zdp::client_services::discovery::NWK_ADDR_REQ_CLUSTER_ID;
use crate::zdp::client_services::discovery::NWKAddrReq;
use crate::zdp::client_services::discovery::NodeDescReq;
use crate::zdp::client_services::discovery::SIMPLE_DESC_REQ_CLUSTER_ID;
use crate::zdp::client_services::discovery::SimpleDescReq;

pub const ZDP_PROFILE_ID: u16 = 0x0000;
pub const ZDO_ENDPOINT: u8 = 0x00;
pub const RX_ON_WHEN_IDLE_BROADCAST: ShortAddress = ShortAddress(0xfffd);

const ZDP_BUF_LEN: usize = 80;

pub(crate) async fn send_nwk_addr_req<M: Mlme>(
    nlme: &mut Nlme<M>,
    apsme: &mut Apsme,
    zdp_seq: u8,
    request: NWKAddrReq,
) -> Result<(), NetworkError> {
    let mut buf = [0u8; ZDP_BUF_LEN];
    let len = request.write_payload(zdp_seq, &mut buf)?;
    send_zdp_request(
        nlme,
        apsme,
        RX_ON_WHEN_IDLE_BROADCAST,
        NWK_ADDR_REQ_CLUSTER_ID,
        &buf[..len],
    )
    .await
}

pub(crate) async fn send_ieee_addr_req<M: Mlme>(
    nlme: &mut Nlme<M>,
    apsme: &mut Apsme,
    zdp_seq: u8,
    destination: ShortAddress,
    request: IeeeAddrReq,
) -> Result<(), NetworkError> {
    let mut buf = [0u8; ZDP_BUF_LEN];
    let len = request.write_payload(zdp_seq, &mut buf)?;
    send_zdp_request(
        nlme,
        apsme,
        destination,
        IEEE_ADDR_REQ_CLUSTER_ID,
        &buf[..len],
    )
    .await
}

pub(crate) async fn send_node_desc_req<M: Mlme>(
    nlme: &mut Nlme<M>,
    apsme: &mut Apsme,
    zdp_seq: u8,
    destination: ShortAddress,
    request: NodeDescReq,
) -> Result<(), NetworkError> {
    let mut buf = [0u8; ZDP_BUF_LEN];
    let len = request.write_payload(zdp_seq, &mut buf)?;
    send_zdp_request(
        nlme,
        apsme,
        destination,
        NODE_DESC_REQ_CLUSTER_ID,
        &buf[..len],
    )
    .await
}

pub(crate) async fn send_simple_desc_req<M: Mlme>(
    nlme: &mut Nlme<M>,
    apsme: &mut Apsme,
    zdp_seq: u8,
    destination: ShortAddress,
    request: SimpleDescReq,
) -> Result<(), NetworkError> {
    let mut buf = [0u8; ZDP_BUF_LEN];
    let len = request.write_payload(zdp_seq, &mut buf)?;
    send_zdp_request(
        nlme,
        apsme,
        destination,
        SIMPLE_DESC_REQ_CLUSTER_ID,
        &buf[..len],
    )
    .await
}

pub(crate) async fn send_active_ep_req<M: Mlme>(
    nlme: &mut Nlme<M>,
    apsme: &mut Apsme,
    zdp_seq: u8,
    destination: ShortAddress,
    request: ActiveEpReq,
) -> Result<(), NetworkError> {
    let mut buf = [0u8; ZDP_BUF_LEN];
    let len = request.write_payload(zdp_seq, &mut buf)?;
    send_zdp_request(
        nlme,
        apsme,
        destination,
        ACTIVE_EP_REQ_CLUSTER_ID,
        &buf[..len],
    )
    .await
}

pub(crate) async fn send_match_desc_req<M: Mlme>(
    nlme: &mut Nlme<M>,
    apsme: &mut Apsme,
    zdp_seq: u8,
    destination: ShortAddress,
    request: &MatchDescReq,
) -> Result<(), NetworkError> {
    let mut buf = [0u8; ZDP_BUF_LEN];
    let len = request.write_payload(zdp_seq, &mut buf)?;
    send_zdp_request(
        nlme,
        apsme,
        destination,
        MATCH_DESC_REQ_CLUSTER_ID,
        &buf[..len],
    )
    .await
}

async fn send_zdp_request<M: Mlme>(
    nlme: &mut Nlme<M>,
    apsme: &mut Apsme,
    destination: ShortAddress,
    cluster_id: u16,
    payload: &[u8],
) -> Result<(), NetworkError> {
    let src_endpoint = SrcEndpoint::new(ZDO_ENDPOINT).map_err(|_| NetworkError::InvalidFrame)?;
    let request = ApsdeSapRequest::new_unicast(
        destination,
        ZDO_ENDPOINT,
        ZDP_PROFILE_ID,
        cluster_id,
        src_endpoint,
        payload,
    );
    let confirm = Apsde::data_request(apsme, nlme, request).await;
    match confirm.status {
        ApsdeSapConfirmStatus::Success => Ok(()),
        ApsdeSapConfirmStatus::NoShortAddress => Err(NetworkError::NotJoined),
        ApsdeSapConfirmStatus::SecurityFail => Err(NetworkError::SecurityError(
            crate::security::SecurityError::Unspecified,
        )),
        ApsdeSapConfirmStatus::NoAck
        | ApsdeSapConfirmStatus::NoBoundDevice
        | ApsdeSapConfirmStatus::AsduTooLong
        | ApsdeSapConfirmStatus::UnsupportedFeature
        | ApsdeSapConfirmStatus::InvalidParameter => Err(NetworkError::InvalidFrame),
    }
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
    use crate::zdo::ZigbeeDevice;
    use crate::zdo::config::Config;
    use crate::zdp::client_services::discovery::AddressRequestType;

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

    fn nwk_payload(payload: &[u8]) -> (NwkHeader<'_>, &[u8]) {
        let (header, header_len) = NwkHeader::try_read(payload, ()).unwrap();
        (header, &payload[header_len..])
    }

    #[test]
    fn nwk_addr_req_sends_to_broadcast_with_zdo_aps_header() {
        let mut mac = MockMlme::new();
        mac.expect_transmit_data()
            .withf(|dest, payload| {
                assert_eq!(
                    *dest,
                    MacAddress::Short(PanId(0xabcd), MacShortAddress(0xfffd))
                );
                let (nwk, aps) = nwk_payload(payload);
                assert_eq!(nwk.destination, ShortAddress(0xfffd));
                aps == [
                    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x08, 0x07, 0x06, 0x05,
                    0x04, 0x03, 0x02, 0x01, 0x00, 0x00,
                ]
            })
            .returning(|_, _| Ok(()));

        let (_guard, mut nlme) = make_nlme(mac);
        let mut device = ZigbeeDevice::new(Config::default());
        let request = NWKAddrReq::new(
            IeeeAddress(0x0102_0304_0506_0708),
            AddressRequestType::Single,
            0,
        )
        .unwrap();

        block_on(device.send_nwk_addr_req(&mut nlme, request)).unwrap();
    }

    #[test]
    fn ieee_addr_req_sends_unicast_destination_with_zdo_aps_header() {
        let mut mac = MockMlme::new();
        mac.expect_transmit_data()
            .withf(|dest, payload| {
                assert_eq!(
                    *dest,
                    MacAddress::Short(PanId(0xabcd), MacShortAddress(0x0000))
                );
                let (nwk, aps) = nwk_payload(payload);
                assert_eq!(nwk.destination, ShortAddress(0x1234));
                aps == [
                    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x34, 0x12, 0x00, 0x00,
                ]
            })
            .returning(|_, _| Ok(()));

        let (_guard, mut nlme) = make_nlme(mac);
        let mut device = ZigbeeDevice::new(Config::default());
        let request =
            IeeeAddrReq::new(ShortAddress(0x1234), AddressRequestType::Single, 0).unwrap();

        block_on(device.send_ieee_addr_req(&mut nlme, ShortAddress(0x1234), request)).unwrap();
    }
}
