//! Implements the Zigbee Base Device Behavior (BDB) in `no-std` based on the
//! [ZigBee Base Device Behavior Specification Rev. 13].
//!
//! [ZigBee Base Device Behavior Specification Rev. 13]: https://csa-iot.org/wp-content/uploads/2022/12/16-02828-012-PRO-BDB-v3.0.1-Specification.pdf
//!
//! This crate defines the standard commissioning procedures all devices must
//! support. It provides a high-level abstraction over the zigbee stack.
#![no_std]
#![allow(unused)]

use byte::TryRead;
use heapless::Vec;
use thiserror::Error;

pub mod types;

// BDB 5.1 | Table 1
const BDBC_MAX_SAME_NETWORK_RETRY_ATTEMPTS: u8 = 10;
const BDBC_MIN_COMMISSIONING_TIME: u8 = 0xb4;
const BDBC_REC_SAME_NETWORK_RETRY_ATTEMPTS: u8 = 3;
const BDBC_TC_LINK_KEY_EXCHANGE_POLL_RETRIES: u8 = 1;

use types::BdbCommissioningStatus;
use types::BdbEvent;
use types::CommissioningMode;
use types::ZDO_RESPONSE_PAYLOAD_CAPACITY;
use zigbee::Config;
use zigbee::LogicalType;
use zigbee::aps::aib;
use zigbee::aps::aib::DeviceKeyPairDescriptor;
use zigbee::aps::aib::KeyAttribute;
use zigbee::aps::aib::LinkKeyType;
use zigbee::aps::apsde::ApsDeliveryMode;
use zigbee::aps::frame::command::Command;
use zigbee::aps::frame::command::ConfirmKey;
use zigbee::aps::frame::command::RequestKey;
use zigbee::aps::frame::command::TransportKey;
use zigbee::aps::frame::command::VerifyKey;
use zigbee::aps::types::Address;
use zigbee::nwk::nib;
use zigbee::nwk::nib::CapabilityInformation;
use zigbee::nwk::nib::NetworkSecurityMaterialDescriptor;
use zigbee::nwk::nib::Nib;
use zigbee::nwk::nib::NibStorage;
use zigbee::nwk::nlme::NetworkError;
use zigbee::nwk::nlme::Nlme;
use zigbee::nwk::nlme::management::NlmeJoinConfirm;
use zigbee::nwk::nlme::management::NlmeJoinRequest;
use zigbee::nwk::nlme::management::NlmeJoinStatus;
use zigbee::nwk::nlme::management::NlmeNetworkFormationRequest;
use zigbee::nwk::nlme::management::NlmePermitJoiningRequest;
use zigbee::nwk::nlme::management::RejoinNetwork;
use zigbee::security::primitives::HmacAes128Mmo;
use zigbee::zdo::ZigbeeDevice;
use zigbee::zdo::ZigbeeDevicePoll;
use zigbee::zdo::install_transport_key as zdo_install_transport_key;
use zigbee::zdp::device_annce::DeviceAnnce;
use zigbee_cluster_library::cluster_server::DeliveryMode as ZclDeliveryMode;
use zigbee_cluster_library::cluster_server::Device;
use zigbee_cluster_library::cluster_server::DispatchContext;
use zigbee_cluster_library::cluster_server::DispatchError;
use zigbee_cluster_library::cluster_server::build_default_response_for_frame;
use zigbee_cluster_library::cluster_server::should_send_default_response;
use zigbee_cluster_library::frame::IncomingZclFrame;
use zigbee_cluster_library::frame::Status;
use zigbee_cluster_library::types::error::ZclError;
use zigbee_cluster_library::types::ids::ClusterId;
use zigbee_mac::mlme::Mlme;
use zigbee_types::ByteArray;
use zigbee_types::IeeeAddress;
use zigbee_types::ShortAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelMask(u32);

impl ChannelMask {
    pub const fn new(mask: u32) -> Option<Self> {
        if mask & !0x07ff_f800 == 0 && mask != 0 {
            Some(Self(mask))
        } else {
            None
        }
    }

    pub fn from_range(channels: core::ops::Range<u8>) -> Option<Self> {
        let mut mask = 0u32;
        for channel in channels {
            if !(11..=26).contains(&channel) {
                return None;
            }
            mask |= 1u32 << channel;
        }
        Self::new(mask)
    }

    fn contains(self, channel: u8) -> bool {
        self.0 & (1u32 << channel) != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanDuration(u8);

impl ScanDuration {
    pub const fn new(exponent: u8) -> Option<Self> {
        if exponent <= 14 {
            Some(Self(exponent))
        } else {
            None
        }
    }

    pub const fn exponent(self) -> u8 {
        self.0
    }
}

/// Base Device Behavior (BDB) commissioning manager.
///
/// Orchestrates the standard commissioning procedures defined in the
/// BDB specification: initialization, network steering, network
/// formation, finding & binding, and touchlink.
pub struct BaseDeviceBehavior<M: Mlme> {
    device: ZigbeeDevice,
    nlme: Nlme<M>,
    bdb_node_is_on_a_network: bool,
    bdb_commissioning_mode: CommissioningMode,
    bdb_commissioning_status: BdbCommissioningStatus,
}

impl<M: Mlme> BaseDeviceBehavior<M> {
    pub fn new(nlme: Nlme<M>, config: Config) -> Self {
        let device = ZigbeeDevice::new(config);

        Self {
            device,
            nlme,
            bdb_node_is_on_a_network: false,
            bdb_commissioning_mode: CommissioningMode::NetworkSteering,
            bdb_commissioning_status: BdbCommissioningStatus::Success,
        }
    }

    /// Returns a reference to the global NIB singleton.
    pub fn nib(&self) -> &'static Nib<NibStorage> {
        nib::get_ref()
    }

    pub fn is_on_network(&self) -> bool {
        self.bdb_node_is_on_a_network
    }

    pub async fn rejoin_network(&mut self) -> Result<NlmeJoinConfirm, NetworkError> {
        let confirm = self.nlme.rejoin().await;
        if confirm.status == NlmeJoinStatus::Success {
            self.bdb_node_is_on_a_network = true;
        }
        Ok(confirm)
    }

    pub async fn leave_network(&mut self) {
        let _ = self.nlme.leave().await;
        self.bdb_node_is_on_a_network = false;
        self.bdb_commissioning_status = BdbCommissioningStatus::NotOnANetwork;
    }

    /// Initialization procedure (BDB §7.1).
    ///
    /// Restores persistent state and, if the node is already on a network,
    /// attempts to rejoin it. Returns without error if the node is not on
    /// a network — the caller should then invoke [`network_steering`].
    pub async fn start_initialization_procedure(&mut self) -> Result<(), NetworkError> {
        // §7.1 step 1: restore persistent state (NIB/AIB backed by storage)
        let nib = nib::get_ref();

        // §7.1 steps 2-8: check if the device is already on a network.
        if nib.network_address() != 0xffff {
            if !nib.security_material_set().is_empty() {
                // Joined with valid security material — mark on-network.
                // Full NWK rejoin deferred; application can call poll_once immediately.
                self.bdb_node_is_on_a_network = true;
            } else {
                // Joined but no network key installed — incomplete commission state.
                return Err(NetworkError::MissingSecurityMaterial);
            }
        }
        // Not on a network — caller should invoke network_steering or
        // network_steering_any.
        Ok(())
    }

    async fn network_discovery_mask(
        &mut self,
        channels: ChannelMask,
        scan_duration: ScanDuration,
    ) -> Result<(), NetworkError> {
        for channel in 11..=26 {
            if channels.contains(channel) {
                self.nlme
                    .network_discovery(channel..channel + 1, scan_duration.exponent())
                    .await?;
            }
        }
        Ok(())
    }
    /// Network steering procedure for a node NOT on a network
    /// (BDB §8.2).
    ///
    /// Performs NLME-NETWORK-DISCOVERY on the given channels, then
    /// NLME-JOIN for the specified extended PAN ID, and finally the
    /// APS transport key exchange to obtain the network key from the
    /// Trust Center.
    pub async fn network_steering(
        &mut self,
        extended_pan_id: IeeeAddress,
        channels: core::ops::Range<u8>,
        scan_duration: u8,
        capability_information: CapabilityInformation,
    ) -> Result<NlmeJoinConfirm, BdbError> {
        log::debug!(
            "[BDB] start network steering, EPID={extended_pan_id:?}, channels={channels:?}"
        );
        self.bdb_commissioning_status = BdbCommissioningStatus::InProgress;

        // §8.2 step 1
        self.nlme.network_discovery(channels, scan_duration).await?;

        // §8.2 step 5
        let request = NlmeJoinRequest {
            extended_pan_id,
            rejoin_network: RejoinNetwork::Association,
            capability_information,
            security_enabled: false,
        };
        let confirm = self.nlme.join(request).await;
        if confirm.status != NlmeJoinStatus::Success {
            self.bdb_commissioning_status = BdbCommissioningStatus::NoNetwork;
            return Err(BdbError::JoinFailed(confirm.status));
        }

        // §8.2 step 9
        self.device.poll_transport_key(&mut self.nlme).await?;

        // Complete Trust Center link key exchange before announcing the device.
        self.tc_link_key_exchange().await?;

        self.device_annce(capability_information).await?;

        self.bdb_node_is_on_a_network = true;
        self.bdb_commissioning_status = BdbCommissioningStatus::Success;
        Ok(confirm)
    }

    pub async fn network_steering_with_mask(
        &mut self,
        extended_pan_id: IeeeAddress,
        channels: ChannelMask,
        scan_duration: ScanDuration,
        capability_information: CapabilityInformation,
    ) -> Result<NlmeJoinConfirm, BdbError> {
        log::debug!("[BDB] start network steering, EPID={extended_pan_id:?}");
        self.bdb_commissioning_status = BdbCommissioningStatus::InProgress;
        self.network_discovery_mask(channels, scan_duration).await?;

        let request = NlmeJoinRequest {
            extended_pan_id,
            rejoin_network: RejoinNetwork::Association,
            capability_information,
            security_enabled: false,
        };
        let confirm = self.nlme.join(request).await;
        if confirm.status != NlmeJoinStatus::Success {
            self.bdb_commissioning_status = BdbCommissioningStatus::NoNetwork;
            return Err(BdbError::JoinFailed(confirm.status));
        }

        self.device.poll_transport_key(&mut self.nlme).await?;
        self.tc_link_key_exchange().await?;
        self.device_annce(capability_information).await?;

        self.bdb_node_is_on_a_network = true;
        self.bdb_commissioning_status = BdbCommissioningStatus::Success;
        Ok(confirm)
    }

    /// Network steering procedure that selects a joinable network automatically
    /// (BDB §8.2).
    ///
    /// Identical to [`network_steering`] except the extended PAN ID is chosen
    /// from the first network discovered that is accepting associations.  Use
    /// [`network_steering`] when a specific EPID is required (e.g. in tests or
    /// deterministic join scenarios).
    pub async fn network_steering_any(
        &mut self,
        channels: core::ops::Range<u8>,
        scan_duration: u8,
        capability_information: CapabilityInformation,
    ) -> Result<NlmeJoinConfirm, BdbError> {
        log::debug!("[BDB] start network_steering_any, channels={channels:?}");
        self.bdb_commissioning_status = BdbCommissioningStatus::InProgress;

        // §8.2 step 1
        self.nlme.network_discovery(channels, scan_duration).await?;

        // Select any joinable network from the discovered neighbor table.
        let extended_pan_id = {
            let table = self.nlme.nib().neighbor_table();
            table
                .iter()
                .find(|n| n.permit_joining && n.potential_parent == 1)
                .map(|n| n.extended_pan_id)
        }
        .ok_or(BdbError::NoNetwork)?;

        // §8.2 step 5
        let request = NlmeJoinRequest {
            extended_pan_id,
            rejoin_network: RejoinNetwork::Association,
            capability_information,
            security_enabled: false,
        };
        let confirm = self.nlme.join(request).await;
        if confirm.status != NlmeJoinStatus::Success {
            self.bdb_commissioning_status = BdbCommissioningStatus::NoNetwork;
            return Err(BdbError::JoinFailed(confirm.status));
        }

        // §8.2 step 9
        self.device.poll_transport_key(&mut self.nlme).await?;

        // Complete Trust Center link key exchange before announcing the device.
        self.tc_link_key_exchange().await?;

        self.device_annce(capability_information).await?;

        self.bdb_node_is_on_a_network = true;
        self.bdb_commissioning_status = BdbCommissioningStatus::Success;
        Ok(confirm)
    }

    /// Poll one incoming APS frame and dispatch it to ZDO, APS security, or
    /// ZCL.
    pub async fn poll_once<D: Device>(&mut self, app: &mut D) -> Result<BdbEvent, BdbError> {
        let mut rx_buf = [0u8; 256];
        let mut tx_buf = [0u8; 256];
        self.poll_once_with_buffers(app, &mut rx_buf, &mut tx_buf)
            .await
    }

    pub async fn poll_once_with_buffers<'a, D: Device>(
        &mut self,
        app: &mut D,
        rx_buf: &'a mut [u8],
        tx_buf: &mut [u8],
    ) -> Result<BdbEvent, BdbError> {
        match self.device.poll_aps(&mut self.nlme, rx_buf, 1).await? {
            ZigbeeDevicePoll::Command(command) => self.handle_polled_aps_command(command),
            ZigbeeDevicePoll::Data(indication) => {
                self.handle_polled_aps_data(app, indication, tx_buf).await
            }
        }
    }

    fn handle_polled_aps_command(&mut self, command: Command) -> Result<BdbEvent, BdbError> {
        match command {
            Command::TransportKey(transport_key) => {
                self.install_transport_key(transport_key)?;
                Ok(BdbEvent::TransportKeyInstalled)
            }
            Command::ConfirmKey(_confirm) => Ok(BdbEvent::UnsupportedFrame),
            Command::RequestKey(_) | Command::VerifyKey(_) | Command::Reserved(_) => {
                Ok(BdbEvent::UnsupportedFrame)
            }
        }
    }

    async fn handle_polled_aps_data<D: Device>(
        &mut self,
        app: &mut D,
        indication: zigbee::aps::apsde::ApsdeSapIndication<'_>,
        tx_buf: &mut [u8],
    ) -> Result<BdbEvent, BdbError> {
        if indication.dst_endpoint == 0 && indication.profile_id == 0x0000 {
            return self.handle_zdo_data(indication);
        }

        self.handle_zcl_data(app, indication, tx_buf).await
    }

    fn source_short_address(
        indication: &zigbee::aps::apsde::ApsdeSapIndication<'_>,
    ) -> Option<ShortAddress> {
        match indication.src_address {
            Address::Network(address) => Some(ShortAddress(address)),
            Address::None | Address::Group(_) | Address::Extended(_) => None,
        }
    }

    fn handle_zdo_data(
        &mut self,
        indication: zigbee::aps::apsde::ApsdeSapIndication<'_>,
    ) -> Result<BdbEvent, BdbError> {
        let Some(source) = Self::source_short_address(&indication) else {
            return Ok(BdbEvent::UnsupportedFrame);
        };
        let Some((&sequence, payload)) = indication.asdu.split_first() else {
            return Ok(BdbEvent::UnsupportedFrame);
        };

        if indication.cluster_id == zigbee::zdp::device_annce::CLUSTER_ID {
            let Ok((annce, used)) = DeviceAnnce::try_read(payload, ()) else {
                return Ok(BdbEvent::UnsupportedFrame);
            };
            if used != payload.len() {
                return Ok(BdbEvent::UnsupportedFrame);
            }
            return Ok(BdbEvent::DeviceAnnounced(annce));
        }

        // TODO(spec): ZDP — verify the exact upper bound for response cluster IDs
        // against the target ZDP spec revision. 0x8038
        // (Mgmt_NWK_IEEE_Joining_List_rsp) only exists in newer ZDP revisions,
        // and there are gaps in 0x8000..=0x8038. Consider switching
        // to an explicit allowlist of known response cluster IDs if interop with strict
        // coordinators is required.
        if (0x8000..=0x8038).contains(&indication.cluster_id) {
            let mut response_payload = Vec::<u8, ZDO_RESPONSE_PAYLOAD_CAPACITY>::new();
            response_payload
                .extend_from_slice(payload)
                .map_err(|_| BdbError::UnsupportedFrame)?;
            return Ok(BdbEvent::ZdoResponse {
                source,
                cluster_id: indication.cluster_id,
                sequence,
                payload: response_payload,
            });
        }

        Ok(BdbEvent::UnsupportedFrame)
    }

    async fn handle_zcl_data<D: Device>(
        &mut self,
        app: &mut D,
        indication: zigbee::aps::apsde::ApsdeSapIndication<'_>,
        tx_buf: &mut [u8],
    ) -> Result<BdbEvent, BdbError> {
        let Some(source) = Self::source_short_address(&indication) else {
            return Ok(BdbEvent::UnsupportedFrame);
        };
        let (frame, used) = match IncomingZclFrame::decode(indication.asdu) {
            Ok(parsed) => parsed,
            Err(_) => return Ok(BdbEvent::UnsupportedFrame),
        };
        if used != indication.asdu.len() {
            return Ok(BdbEvent::UnsupportedFrame);
        }

        let ctx = DispatchContext {
            delivery: match indication.delivery {
                ApsDeliveryMode::Unicast => ZclDeliveryMode::Unicast,
                ApsDeliveryMode::Broadcast | ApsDeliveryMode::Group => {
                    ZclDeliveryMode::BroadcastOrMulticast
                }
            },
        };

        let cluster_id = ClusterId::new(indication.cluster_id);
        let event = |response_sent| BdbEvent::ZclHandled {
            source,
            endpoint: indication.dst_endpoint,
            cluster_id: indication.cluster_id,
            response_sent,
        };

        match app.dispatch_cluster(cluster_id, frame.manufacturer_code(), ctx, &frame, tx_buf) {
            Ok(n) if n > 0 => {
                self.send_zcl_response(&indication, source, &tx_buf[..n])
                    .await?;
                Ok(event(true))
            }
            Ok(_) => Ok(event(false)),
            Err(DispatchError::UnsupportedCluster)
                if should_send_default_response(&frame, ctx, Status::UnsupportedCluster) =>
            {
                let n =
                    build_default_response_for_frame(&frame, Status::UnsupportedCluster, tx_buf)
                        .map_err(BdbError::ZclCodec)?;
                self.send_zcl_response(&indication, source, &tx_buf[..n])
                    .await?;
                Ok(event(true))
            }
            Err(DispatchError::UnsupportedCluster) | Err(DispatchError::Codec(_)) => {
                Ok(event(false))
            }
        }
    }

    async fn send_zcl_response(
        &mut self,
        indication: &zigbee::aps::apsde::ApsdeSapIndication<'_>,
        destination: ShortAddress,
        asdu: &[u8],
    ) -> Result<(), BdbError> {
        self.device
            .send_aps_data(
                &mut self.nlme,
                destination,
                indication.src_endpoint,
                indication.profile_id,
                indication.cluster_id,
                indication.dst_endpoint,
                asdu,
            )
            .await?;
        Ok(())
    }

    fn install_transport_key(&mut self, transport_key: TransportKey) -> Result<(), NetworkError> {
        zdo_install_transport_key(transport_key)
    }

    /// Broadcast a ZDO Device_annce (§2.4.3.1.11, BDB §8.2 step 11).
    async fn device_annce(
        &mut self,
        capability_information: CapabilityInformation,
    ) -> Result<(), NetworkError> {
        let nib = nib::get_ref();
        let annce = DeviceAnnce {
            nwk_addr: ShortAddress(nib.network_address()),
            ieee_addr: nib.ieee_address(),
            capability: capability_information,
        };
        self.device.device_annce(&mut self.nlme, annce).await
    }

    /// Trust Center link key exchange procedure (BDB §10.2.5).
    ///
    /// Replaces the default TC link key (key A) with a unique key (key B)
    /// through a three-phase exchange: REQUEST-KEY → TRANSPORT-KEY →
    /// VERIFY-KEY → CONFIRM-KEY.
    async fn tc_link_key_exchange(&mut self) -> Result<(), NetworkError> {
        let tc_short = ShortAddress(0x0000);
        let tc_ieee = aib::get_ref().trust_center_address();

        log::debug!("[BDB] start TC link key exchange, TC={tc_ieee:?}");

        // §10.2.5 steps 6-9
        let mut attempts = 0u8;
        let new_key = loop {
            log::debug!("[BDB] send_aps_command");
            self.device
                .send_aps_command(
                    &mut self.nlme,
                    tc_short,
                    tc_ieee,
                    Command::RequestKey(RequestKey::TrustCenterLinkKey),
                    true,
                )
                .await?;
            attempts += 1;
            log::debug!("[BDB] send_aps_command ok");

            match self
                .device
                .poll_aps_command(&mut self.nlme, BDBC_TC_LINK_KEY_EXCHANGE_POLL_RETRIES)
                .await
            {
                Ok(Command::TransportKey(TransportKey::TrustCenterLinkKey(key_desc))) => {
                    log::debug!("[BDB] received new TC link key");
                    break key_desc.key;
                }
                _ if attempts >= BDBC_MAX_SAME_NETWORK_RETRY_ATTEMPTS => {
                    log::warn!("[BDB] TC link key exchange failed: no TRANSPORT-KEY");
                    self.bdb_commissioning_status = BdbCommissioningStatus::TclkExFailure;
                    return Err(NetworkError::NoTransportKey);
                }
                _ => continue,
            }
        };

        // §10.2.5 step 9
        let aib = aib::get_ref();
        let mut key_set = aib.device_key_pair_set();
        if let Some(entry) = key_set.iter_mut().find(|k| k.device_address == tc_ieee) {
            entry.link_key = new_key;
            entry.key_attributes = KeyAttribute::UnverifiedKey;
            entry.outgoing_frame_counter = 0;
            entry.incoming_frame_counter = 0;
        } else {
            key_set
                .push(DeviceKeyPairDescriptor {
                    device_address: tc_ieee,
                    key_attributes: KeyAttribute::UnverifiedKey,
                    link_key: new_key,
                    outgoing_frame_counter: 0,
                    incoming_frame_counter: 0,
                    link_key_type: LinkKeyType::UniqueLinkKey,
                })
                .map_err(|_| NetworkError::InvalidFrame)?;
        }
        aib.set_device_key_pair_set(key_set);

        let device_addr = nib::get_ref().ieee_address();
        let mut hash_input = [0u8; 9];
        hash_input[0] = 0x03;
        hash_input[1..].copy_from_slice(&device_addr.0.to_le_bytes());
        let hash = HmacAes128Mmo::hmac(new_key.as_slice(), &hash_input).map_err(|_| {
            NetworkError::SecurityError(zigbee::security::SecurityError::Unspecified)
        })?;

        let mut attempts = 0u8;
        loop {
            self.device
                .send_aps_command(
                    &mut self.nlme,
                    tc_short,
                    tc_ieee,
                    Command::VerifyKey(VerifyKey {
                        key_type: 0x04,
                        source_address: device_addr,
                        hash: ByteArray(hash),
                    }),
                    true,
                )
                .await?;
            attempts += 1;

            match self
                .device
                .poll_aps_command(&mut self.nlme, BDBC_TC_LINK_KEY_EXCHANGE_POLL_RETRIES)
                .await
            {
                Ok(Command::ConfirmKey(confirm)) if confirm.status == 0x00 => {
                    log::debug!("[BDB] TC link key verified successfully");
                    // mark key as verified
                    let mut key_set = aib.device_key_pair_set();
                    if let Some(entry) = key_set.iter_mut().find(|k| k.device_address == tc_ieee) {
                        entry.key_attributes = KeyAttribute::VerifiedKey;
                    }
                    aib.set_device_key_pair_set(key_set);
                    return Ok(());
                }
                _ if attempts >= BDBC_MAX_SAME_NETWORK_RETRY_ATTEMPTS => {
                    log::warn!("[BDB] TC link key exchange failed: no CONFIRM-KEY");
                    self.bdb_commissioning_status = BdbCommissioningStatus::TclkExFailure;
                    return Err(NetworkError::NoTransportKey);
                }
                _ => continue,
            }
        }
    }

    fn is_end_device(&self) -> bool {
        self.device.logical_type() == LogicalType::EndDevice
    }

    fn is_router(&self) -> bool {
        self.device.logical_type() == LogicalType::Router
    }
}

#[derive(Debug, Error)]
pub enum BdbError {
    #[error("network error")]
    NetworkError(#[from] NetworkError),

    #[error("no open network discovered to join")]
    NoNetwork,

    #[error("unsupported frame")]
    UnsupportedFrame,

    #[error("join failed: {0:?}")]
    JoinFailed(NlmeJoinStatus),
    #[error("ZCL codec error: {0:?}")]
    ZclCodec(ZclError),
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use core::future::Future;
    use std::sync::Mutex;
    use std::sync::MutexGuard;
    use std::sync::Once;

    use byte::TryRead;
    use zigbee::Config;
    use zigbee::aps::aib;
    use zigbee::aps::aib::AibStorage;
    use zigbee::nwk::frame::header::Header as NwkHeader;
    use zigbee::nwk::nib;
    use zigbee::nwk::nib::DeviceType;
    use zigbee::nwk::nib::NetworkSecurityMaterialDescriptor;
    use zigbee::nwk::nib::NibStorage;
    use zigbee::nwk::nib::NwkNeighbor;
    use zigbee::nwk::nib::relationship;
    use zigbee::nwk::nlme::NetworkError;
    use zigbee::nwk::nlme::Nlme;
    use zigbee_cluster_library::cluster_server::ClusterServer;
    use zigbee_cluster_library::cluster_server::DispatchError;
    use zigbee_cluster_library::cluster_server::zcl_cluster_dispatch;
    use zigbee_cluster_library::common::BasicConfig;
    use zigbee_cluster_library::common::BasicServer;
    use zigbee_cluster_library::types::descriptors::ClusterKey;
    use zigbee_cluster_library::types::error::ZclError;
    use zigbee_cluster_library::types::ids::AttributeId;
    use zigbee_cluster_library::types::ids::ClusterId;
    use zigbee_cluster_library::types::ids::ManufacturerCode;
    use zigbee_cluster_library::types::ids::TypeId;
    use zigbee_mac::Address as MacAddress;
    use zigbee_mac::AssociationStatus;
    use zigbee_mac::MacShortAddress;
    use zigbee_mac::PanId;
    use zigbee_mac::mlme::AssociationResponse;
    use zigbee_mac::mlme::MacError;
    use zigbee_mac::mlme::PanDescriptor;
    use zigbee_mac::mlme::ScanResult;
    use zigbee_mac::mlme::ScanType;
    use zigbee_types::ByteArray;
    use zigbee_types::IeeeAddress;
    use zigbee_types::ShortAddress;
    use zigbee_types::StorageVec;

    use super::*;

    static TEST_MUTEX: Mutex<()> = Mutex::new(());
    static INIT: Once = Once::new();

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
        impl zigbee_mac::mlme::Mlme for Mlme {
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

    struct AppDevice {
        basic: BasicServer,
        codec_error: bool,
    }

    impl AppDevice {
        fn new() -> Self {
            Self {
                basic: BasicServer::new(BasicConfig::new(3, "ACME", "Sensor-1", 0x01, true)),
                codec_error: false,
            }
        }

        fn codec_error() -> Self {
            Self {
                basic: BasicServer::new(BasicConfig::new(3, "ACME", "Sensor-1", 0x01, true)),
                codec_error: true,
            }
        }
    }

    impl Device for AppDevice {
        fn dispatch_cluster(
            &mut self,
            cluster_id: ClusterId,
            manufacturer_code: Option<ManufacturerCode>,
            ctx: DispatchContext,
            frame: &IncomingZclFrame<'_>,
            buf: &mut [u8],
        ) -> Result<usize, DispatchError> {
            if manufacturer_code.is_some() || cluster_id != BasicServer::CLUSTER_ID {
                return Err(DispatchError::UnsupportedCluster);
            }
            if self.codec_error {
                return Err(DispatchError::Codec(ZclError::BufferTooSmall));
            }
            zcl_cluster_dispatch(&mut self.basic, frame, ctx, buf).map_err(DispatchError::from)
        }

        fn server_cluster_ids(&self) -> &'static [ClusterKey] {
            &[]
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

    fn make_bdb(mac: MockMlme) -> (MutexGuard<'static, ()>, BaseDeviceBehavior<MockMlme>) {
        let guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        INIT.call_once(|| {
            nib::init(NibStorage::default());
            aib::init(AibStorage::default());
        });

        let nlme = Nlme::new(mac);
        nlme.nib().set_network_address(0x5678);
        nlme.nib().set_panid(0xabcd);
        let mut neighbors = StorageVec::new();
        neighbors.push(make_parent()).unwrap();
        nlme.nib().set_neighbor_table(neighbors);

        (guard, BaseDeviceBehavior::new(nlme, Config::default()))
    }

    fn expect_poll_data(mac: &mut MockMlme, frame: &'static [u8]) {
        mac.expect_poll_data()
            .withf(|coord_address, _| {
                *coord_address == MacAddress::Short(PanId(0xabcd), MacShortAddress(0x0000))
            })
            .returning(move |_, buf| {
                buf[..frame.len()].copy_from_slice(frame);
                Ok((frame.len(), 200))
            });
    }

    fn aps_payload_from_nwk(payload: &[u8]) -> &[u8] {
        let (_, header_len) = NwkHeader::try_read(payload, ()).unwrap();
        &payload[header_len..]
    }

    fn expect_zcl_response(mac: &mut MockMlme, expected_aps: &'static [u8]) {
        mac.expect_transmit_data()
            .withf(move |dest, payload| {
                *dest == MacAddress::Short(PanId(0xabcd), MacShortAddress(0x0000))
                    && aps_payload_from_nwk(payload) == expected_aps
            })
            .returning(|_, _| Ok(()));
    }

    const IN_READ_BASIC: &[u8] = &[
        0x08, 0x00, 0x78, 0x56, 0x34, 0x12, 0x1e, 0xaa, 0x00, 0x01, 0x00, 0x00, 0x04, 0x01, 0x02,
        0x55, 0x00, 0x11, 0x00, 0x00, 0x00,
    ];
    const OUT_READ_BASIC: &[u8] = &[
        0x00, 0x02, 0x00, 0x00, 0x04, 0x01, 0x01, 0x01, 0x18, 0x11, 0x01, 0x00, 0x00, 0x00, 0x20,
        0x03,
    ];

    const IN_WRITE_READ_ONLY: &[u8] = &[
        0x08, 0x00, 0x78, 0x56, 0x34, 0x12, 0x1e, 0xaa, 0x00, 0x01, 0x00, 0x00, 0x04, 0x01, 0x02,
        0x56, 0x00, 0x22, 0x02, 0x00, 0x00, 0x20, 0x04,
    ];
    const OUT_WRITE_READ_ONLY: &[u8] = &[
        0x00, 0x02, 0x00, 0x00, 0x04, 0x01, 0x01, 0x01, 0x18, 0x22, 0x04, 0x88, 0x00, 0x00,
    ];

    const IN_UNSUPPORTED_CLUSTER: &[u8] = &[
        0x08, 0x00, 0x78, 0x56, 0x34, 0x12, 0x1e, 0xaa, 0x00, 0x01, 0x06, 0x00, 0x04, 0x01, 0x02,
        0x57, 0x00, 0x33, 0x00, 0x00, 0x00,
    ];
    const OUT_UNSUPPORTED_CLUSTER: &[u8] = &[
        0x00, 0x02, 0x06, 0x00, 0x04, 0x01, 0x01, 0x01, 0x18, 0x33, 0x0b, 0x00, 0xc3,
    ];

    const IN_BROADCAST_UNSUPPORTED_CLUSTER: &[u8] = &[
        0x08, 0x00, 0xfd, 0xff, 0x34, 0x12, 0x1e, 0xaa, 0x08, 0x01, 0x06, 0x00, 0x04, 0x01, 0x02,
        0x58, 0x00, 0x44, 0x00, 0x00, 0x00,
    ];

    const IN_CODEC_ERROR: &[u8] = &[
        0x08, 0x00, 0x78, 0x56, 0x34, 0x12, 0x1e, 0xaa, 0x00, 0x01, 0x00, 0x00, 0x04, 0x01, 0x02,
        0x59, 0x00, 0x55, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn poll_once_read_attributes_sends_cluster_response() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_READ_BASIC);
        expect_zcl_response(&mut mac, OUT_READ_BASIC);
        let (_guard, mut bdb) = make_bdb(mac);
        let mut app = AppDevice::new();

        let event = block_on(bdb.poll_once(&mut app)).unwrap();

        assert_eq!(
            event,
            BdbEvent::ZclHandled {
                source: ShortAddress(0x1234),
                endpoint: 0x01,
                cluster_id: 0x0000,
                response_sent: true,
            }
        );
    }

    #[test]
    fn poll_once_write_read_only_attr_reports_read_only_and_preserves_value() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_WRITE_READ_ONLY);
        expect_zcl_response(&mut mac, OUT_WRITE_READ_ONLY);
        let (_guard, mut bdb) = make_bdb(mac);
        let mut app = AppDevice::new();

        let event = block_on(bdb.poll_once(&mut app)).unwrap();

        assert_eq!(
            event,
            BdbEvent::ZclHandled {
                source: ShortAddress(0x1234),
                endpoint: 0x01,
                cluster_id: 0x0000,
                response_sent: true,
            }
        );
        let mut buf = [0u8; 1];
        let (type_id, len) = app
            .basic
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(type_id, TypeId::Uint8);
        assert_eq!(len, 1);
        assert_eq!(buf[0], 3);
    }

    #[test]
    fn poll_once_unsupported_unicast_cluster_sends_default_response() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_UNSUPPORTED_CLUSTER);
        expect_zcl_response(&mut mac, OUT_UNSUPPORTED_CLUSTER);
        let (_guard, mut bdb) = make_bdb(mac);
        let mut app = AppDevice::new();

        let event = block_on(bdb.poll_once(&mut app)).unwrap();

        assert_eq!(
            event,
            BdbEvent::ZclHandled {
                source: ShortAddress(0x1234),
                endpoint: 0x01,
                cluster_id: 0x0006,
                response_sent: true,
            }
        );
    }

    #[test]
    fn poll_once_unsupported_broadcast_cluster_sends_no_response() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_BROADCAST_UNSUPPORTED_CLUSTER);
        let (_guard, mut bdb) = make_bdb(mac);
        let mut app = AppDevice::new();

        let event = block_on(bdb.poll_once(&mut app)).unwrap();

        assert_eq!(
            event,
            BdbEvent::ZclHandled {
                source: ShortAddress(0x1234),
                endpoint: 0x01,
                cluster_id: 0x0006,
                response_sent: false,
            }
        );
    }

    #[test]
    fn poll_once_codec_error_sends_no_partial_response() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_CODEC_ERROR);
        let (_guard, mut bdb) = make_bdb(mac);
        let mut app = AppDevice::codec_error();

        let event = block_on(bdb.poll_once(&mut app)).unwrap();

        assert_eq!(
            event,
            BdbEvent::ZclHandled {
                source: ShortAddress(0x1234),
                endpoint: 0x01,
                cluster_id: 0x0000,
                response_sent: false,
            }
        );
    }

    // ------------------------------------------------------------------
    // Helpers for network_steering_any and start_initialization tests
    // ------------------------------------------------------------------

    fn make_pan_descriptor(epid: u64, permit: bool, channel: u8) -> PanDescriptor {
        PanDescriptor::new(channel, 0xAAAA, 0x0000, permit, IeeeAddress(epid), 200)
    }

    fn make_scan_result(descriptors: std::vec::Vec<PanDescriptor>) -> ScanResult {
        let mut pan_descriptor: zigbee_mac::mlme::PanDescriptorList = heapless::Vec::new();
        for d in descriptors {
            let _ = pan_descriptor.push(d);
        }
        ScanResult {
            scan_type: ScanType::Active,
            pan_descriptor,
        }
    }

    // ------------------------------------------------------------------
    // start_initialization_procedure tests
    // ------------------------------------------------------------------

    #[test]
    fn init_not_joined_returns_ok_not_on_network() {
        let mac = MockMlme::new();
        let (_guard, mut bdb) = make_bdb(mac);
        // Default NIB has network_address = 0xffff (not joined).
        bdb.nlme.nib().set_network_address(0xffff);

        block_on(bdb.start_initialization_procedure()).unwrap();
        assert!(!bdb.bdb_node_is_on_a_network);
    }

    #[test]
    fn init_joined_with_security_marks_on_network() {
        let mac = MockMlme::new();
        let (_guard, mut bdb) = make_bdb(mac);
        bdb.nlme.nib().set_network_address(0x1234);
        let mut sec = StorageVec::new();
        sec.push(NetworkSecurityMaterialDescriptor {
            key_seq_number: 0,
            outgoing_frame_counter: 0,
            incoming_frame_counter_set: StorageVec::new(),
            key: ByteArray([0xABu8; 16]),
            network_key_type: 0x01,
        })
        .unwrap();
        bdb.nlme.nib().set_security_material_set(sec);

        block_on(bdb.start_initialization_procedure()).unwrap();
        assert!(bdb.bdb_node_is_on_a_network);
    }

    #[test]
    fn init_joined_without_security_returns_error() {
        let mac = MockMlme::new();
        let (_guard, mut bdb) = make_bdb(mac);
        bdb.nlme.nib().set_network_address(0x1234);
        // Security material set is empty (default).
        bdb.nlme.nib().set_security_material_set(StorageVec::new());

        let result = block_on(bdb.start_initialization_procedure());
        assert!(
            matches!(result, Err(NetworkError::MissingSecurityMaterial)),
            "expected MissingSecurityMaterial, got {result:?}"
        );
        assert!(!bdb.bdb_node_is_on_a_network);
    }

    // ------------------------------------------------------------------
    // network_steering_any tests
    // ------------------------------------------------------------------

    #[test]
    fn network_steering_any_no_networks_returns_no_network() {
        let mut mac = MockMlme::new();
        mac.expect_scan_network()
            .returning(|_, _, _| Ok(make_scan_result(std::vec![])));
        let (_guard, mut bdb) = make_bdb(mac);
        // Reset to unjoined state.
        bdb.nlme.nib().set_network_address(0xffff);

        let result = block_on(bdb.network_steering_any(11..26, 3, CapabilityInformation(0x80)));
        assert!(
            matches!(result, Err(BdbError::NoNetwork)),
            "expected NoNetwork, got {result:?}"
        );
    }

    #[test]
    fn network_steering_any_no_permit_join_returns_no_network() {
        let mut mac = MockMlme::new();
        mac.expect_scan_network().returning(|_, _, _| {
            Ok(make_scan_result(std::vec![make_pan_descriptor(
                0xDEAD, false, 11,
            )]))
        });
        let (_guard, mut bdb) = make_bdb(mac);
        bdb.nlme.nib().set_network_address(0xffff);

        let result = block_on(bdb.network_steering_any(11..26, 3, CapabilityInformation(0x80)));
        assert!(
            matches!(result, Err(BdbError::NoNetwork)),
            "expected NoNetwork, got {result:?}"
        );
    }

    #[test]
    fn network_steering_any_selects_joinable_network_and_attempts_join() {
        let mut mac = MockMlme::new();
        // Scan returns one non-joinable and one joinable network (EPID 0xBEEF).
        mac.expect_scan_network().returning(|_, _, _| {
            Ok(make_scan_result(std::vec![
                make_pan_descriptor(0xDEAD, false, 11),
                make_pan_descriptor(0xBEEF, true, 15),
            ]))
        });
        // Association succeeds for EPID 0xBEEF.
        mac.expect_associate().returning(|_, _, _| {
            Ok(AssociationResponse {
                device_address: IeeeAddress(0xAABBCCDD),
                association_address: ShortAddress(0x5678),
                status: AssociationStatus::Successful,
            })
        });
        // poll_data fails immediately (ends after join step, before TC key exchange).
        mac.expect_poll_data()
            .returning(|_, _| Err(zigbee_mac::mlme::MacError::NoData));

        let (_guard, mut bdb) = make_bdb(mac);
        bdb.nlme.nib().set_network_address(0xffff);

        let result = block_on(bdb.network_steering_any(11..26, 3, CapabilityInformation(0x80)));
        // Should have reached poll_transport_key, which fails with MacError — not
        // NoNetwork.
        assert!(
            !matches!(result, Err(BdbError::NoNetwork)),
            "should have passed network selection and join"
        );
        // NIB should reflect the successful association.
        assert_eq!(bdb.nlme.nib().network_address(), 0x5678);
        assert_eq!(bdb.nlme.nib().extended_panid(), 0xBEEF);
    }
}
