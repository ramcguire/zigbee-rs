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
const BDBC_TC_LINK_KEY_EXCHANGE_ATTEMPTS_MAX: u8 = 3;
const BDBC_TC_LINK_KEY_EXCHANGE_POLL_RETRIES: u8 = 15;

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
use zigbee::aps::apsde::ApsdeSapIndication;
use zigbee::aps::frame::command::Command;
use zigbee::aps::frame::command::ConfirmKey;
use zigbee::aps::frame::command::RequestKey;
use zigbee::aps::frame::command::SwitchKey;
use zigbee::aps::frame::command::TransportKey;
use zigbee::aps::frame::command::VerifyKey;
use zigbee::aps::types::Address;
use zigbee::aps::types::DstAddrMode;
use zigbee::aps::types::SrcAddrMode;
use zigbee::nwk::nib;
use zigbee::nwk::nib::CapabilityInformation;
use zigbee::nwk::nib::NetworkSecurityMaterialDescriptor;
use zigbee::nwk::nib::Nib;
use zigbee::nwk::nib::NibStorage;
use zigbee::nwk::nlme::NetworkError;
use zigbee::nwk::nlme::Nlme;
use zigbee::nwk::nlme::management::LeaveSource;
use zigbee::nwk::nlme::management::NlmeJoinConfirm;
use zigbee::nwk::nlme::management::NlmeJoinRequest;
use zigbee::nwk::nlme::management::NlmeJoinStatus;
use zigbee::nwk::nlme::management::NlmeLeaveRequest;
use zigbee::nwk::nlme::management::NlmeNetworkFormationRequest;
use zigbee::nwk::nlme::management::NlmePermitJoiningRequest;
use zigbee::nwk::nlme::management::NlmeRejoinRequest;
use zigbee::nwk::nlme::management::RejoinNetwork;
use zigbee::nwk::nlme::management::RejoinScan;
use zigbee::security::primitives::HmacAes128Mmo;
use zigbee::zdo::ZigbeeDevice;
use zigbee::zdo::ZigbeeDevicePoll;
use zigbee::zdo::install_transport_key as zdo_install_transport_key;
use zigbee::zdp::client_services::discovery::MATCH_DESC_REQ_CLUSTER_ID;
use zigbee::zdp::client_services::discovery::MatchDescReq;
use zigbee::zdp::device_annce::DeviceAnnce;
use zigbee_cluster_library::cluster_server::ApsPeer;
use zigbee_cluster_library::cluster_server::ClusterRequest;
use zigbee_cluster_library::cluster_server::Device;
use zigbee_cluster_library::cluster_server::DeviceTick;
use zigbee_cluster_library::cluster_server::DispatchContext;
use zigbee_cluster_library::cluster_server::DispatchError;
use zigbee_cluster_library::cluster_server::EndpointDescriptor;
use zigbee_cluster_library::cluster_server::GroupEffect;
use zigbee_cluster_library::cluster_server::ReportDeliveryResult;
use zigbee_cluster_library::cluster_server::ReportDestination;
use zigbee_cluster_library::cluster_server::ReportReady;
use zigbee_cluster_library::cluster_server::build_default_response_for_frame;
use zigbee_cluster_library::cluster_server::should_send_default_response;
use zigbee_cluster_library::frame::IncomingZclFrame;
use zigbee_cluster_library::frame::Status;
use zigbee_cluster_library::types::descriptors::ClusterKey;
use zigbee_cluster_library::types::error::ZclError;
use zigbee_cluster_library::types::ids::ClusterId;
use zigbee_mac::mlme::Mlme;
use zigbee_types::BindingEntry;
use zigbee_types::ByteArray;
use zigbee_types::IeeeAddress;
use zigbee_types::MAX_BINDING_TABLE_ENTRIES;
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
    last_device_tick: DeviceTick,
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
            last_device_tick: DeviceTick::default(),
        }
    }

    /// Add a binding table entry.
    ///
    /// Returns `Err(())` when the table is full.
    #[allow(clippy::result_unit_err)]
    pub fn bind(&mut self, entry: BindingEntry) -> Result<(), ()> {
        let aib = aib::get_ref();
        let mut table = aib.binding_table();
        if table.iter().any(|e| e == &entry) {
            return Ok(());
        }
        table.push(entry).map_err(|_| ())?;
        aib.set_binding_table(table);
        Ok(())
    }

    /// Remove a binding table entry. No-op if the entry does not exist.
    pub fn unbind(&mut self, entry: &BindingEntry) {
        let aib = aib::get_ref();
        let mut table = aib.binding_table();
        table.retain(|e| e != entry);
        aib.set_binding_table(table);
    }

    /// Returns a copy of the current binding table.
    pub fn bindings(&self) -> heapless::Vec<BindingEntry, MAX_BINDING_TABLE_ENTRIES> {
        aib::get_ref().binding_table().0
    }

    /// Register `(group_id, endpoint)` in the APS group table so that
    /// group-addressed frames for `group_id` are delivered to `endpoint`.
    /// No-op if the entry already exists. Silently drops if the table is full.
    fn add_aps_group(&self, group_id: u16, endpoint: u8) {
        let aib = aib::get_ref();
        let mut table = aib.group_table();
        if table
            .iter()
            .any(|e| e.group_address == group_id && e.endpoint == endpoint)
        {
            return;
        }
        let _ = table.push(zigbee::aps::aib::ApsGroup {
            group_address: group_id,
            endpoint,
        });
        aib.set_group_table(table);
    }

    /// Remove `(group_id, endpoint)` from the APS group table. No-op if not
    /// present.
    fn remove_aps_group(&self, group_id: u16, endpoint: u8) {
        let aib = aib::get_ref();
        let mut table = aib.group_table();
        table.retain(|e| !(e.group_address == group_id && e.endpoint == endpoint));
        aib.set_group_table(table);
    }

    /// Remove all APS group table entries for `endpoint`.
    fn remove_all_aps_groups(&self, endpoint: u8) {
        let aib = aib::get_ref();
        let mut table = aib.group_table();
        table.retain(|e| e.endpoint != endpoint);
        aib.set_group_table(table);
    }

    /// Returns a reference to the global NIB singleton.
    pub fn nib(&self) -> &'static Nib<NibStorage> {
        nib::get_ref()
    }

    /// Result returned by the most recent device tick driven by `poll_once`.
    pub const fn last_device_tick(&self) -> DeviceTick {
        self.last_device_tick
    }

    pub fn is_on_network(&self) -> bool {
        self.bdb_node_is_on_a_network
    }

    fn same_channel_rejoin_request(&self) -> NlmeRejoinRequest {
        let nib = self.nib();
        NlmeRejoinRequest {
            extended_pan_id: IeeeAddress(nib.extended_panid()),
            capability_information: nib.capability_information(),
            secure: true,
            scan: RejoinScan::SameChannel,
        }
    }

    async fn rejoin_after_network_leave(&mut self) -> Result<NlmeJoinConfirm, BdbError> {
        let confirm = self.nlme.rejoin(self.same_channel_rejoin_request()).await;
        if confirm.status != NlmeJoinStatus::Success {
            self.bdb_node_is_on_a_network = false;
            self.bdb_commissioning_status = BdbCommissioningStatus::NotOnANetwork;
            return Err(BdbError::JoinFailed(confirm.status));
        }

        self.bdb_node_is_on_a_network = true;
        self.bdb_commissioning_status = BdbCommissioningStatus::Success;
        self.device_annce(self.nib().capability_information())
            .await?;
        Ok(confirm)
    }

    fn mark_network_leave_without_rejoin(&mut self) {
        self.bdb_node_is_on_a_network = false;
        self.bdb_commissioning_status = BdbCommissioningStatus::NotOnANetwork;
    }

    pub async fn rejoin_network(&mut self) -> Result<NlmeJoinConfirm, BdbError> {
        self.rejoin_after_network_leave().await
    }

    pub async fn leave_network(&mut self) {
        let _ = self
            .nlme
            .leave(&NlmeLeaveRequest {
                rejoin: false,
                remove_children: false,
                source: LeaveSource::Local,
            })
            .await;
        self.mark_network_leave_without_rejoin();
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

        // BDB §8.3 step 10: after authenticating the network key, mark the
        // node on-network and broadcast Device_annce before the TC link-key
        // update procedure (§8.3 step 11 / §10.2.5). HA/ZHA starts interview
        // from this announcement/join indication, so delaying it behind TCLK
        // exchange makes the node unable to answer early ZDO requests.
        self.bdb_node_is_on_a_network = true;
        self.device_annce(capability_information).await?;

        match self.tc_link_key_exchange().await {
            Ok(()) => {}
            Err(NetworkError::NoTransportKey) => {
                log::warn!("[BDB] TC link key exchange failed; continuing with global TC link key");
            }
            Err(NetworkError::LeaveRequested { rejoin: true }) => {
                return self.rejoin_after_network_leave().await;
            }
            Err(NetworkError::LeaveRequested { rejoin: false }) => {
                self.mark_network_leave_without_rejoin();
                return Err(NetworkError::LeaveRequested { rejoin: false }.into());
            }
            Err(e) => return Err(e.into()),
        }

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
        self.bdb_node_is_on_a_network = true;
        self.device_annce(capability_information).await?;

        match self.tc_link_key_exchange().await {
            Ok(()) => {}
            Err(NetworkError::NoTransportKey) => {
                log::warn!("[BDB] TC link key exchange failed; continuing with global TC link key");
            }
            Err(NetworkError::LeaveRequested { rejoin: true }) => {
                return self.rejoin_after_network_leave().await;
            }
            Err(NetworkError::LeaveRequested { rejoin: false }) => {
                self.mark_network_leave_without_rejoin();
                return Err(NetworkError::LeaveRequested { rejoin: false }.into());
            }
            Err(e) => return Err(e.into()),
        }

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
        // Use the same capacity check as select_parent_candidates so we only
        // attempt a join when there is actually an eligible parent.
        let join_as_router = capability_information.device_type();
        let extended_pan_id = {
            let table = self.nlme.nib().neighbor_table();
            table
                .iter()
                .find(|n| {
                    n.permit_joining
                        && n.potential_parent == 1
                        && if join_as_router {
                            n.router_capacity
                        } else {
                            n.end_device_capacity
                        }
                })
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

        self.bdb_node_is_on_a_network = true;
        self.device_annce(capability_information).await?;

        match self.tc_link_key_exchange().await {
            Ok(()) => {}
            Err(NetworkError::NoTransportKey) => {
                log::warn!("[BDB] TC link key exchange failed; continuing with global TC link key");
            }
            Err(NetworkError::LeaveRequested { rejoin: true }) => {
                return self.rejoin_after_network_leave().await;
            }
            Err(NetworkError::LeaveRequested { rejoin: false }) => {
                self.mark_network_leave_without_rejoin();
                return Err(NetworkError::LeaveRequested { rejoin: false }.into());
            }
            Err(e) => return Err(e.into()),
        }

        self.bdb_commissioning_status = BdbCommissioningStatus::Success;
        Ok(confirm)
    }

    /// Poll one incoming APS frame and dispatch it to ZDO, APS security, or
    /// ZCL.
    pub async fn poll_once<D: Device>(
        &mut self,
        app: &mut D,
        now_ms: u32,
    ) -> Result<BdbEvent, BdbError> {
        let mut rx_buf = [0u8; 256];
        let mut tx_buf = [0u8; 256];
        self.poll_once_with_buffers(app, now_ms, &mut rx_buf, &mut tx_buf)
            .await
    }

    pub async fn poll_once_with_buffers<D: Device>(
        &mut self,
        app: &mut D,
        now_ms: u32,
        rx_buf: &mut [u8],
        tx_buf: &mut [u8],
    ) -> Result<BdbEvent, BdbError> {
        self.last_device_tick = app.tick(now_ms);
        let poll = match self.device.poll_aps(&mut self.nlme, rx_buf, 1).await {
            Ok(poll) => poll,
            Err(
                NetworkError::MacError(zigbee_mac::mlme::MacError::NoData)
                | NetworkError::InvalidFrame,
            ) => return Ok(BdbEvent::UnsupportedFrame),
            Err(NetworkError::LeaveRequested { rejoin: true }) => {
                self.rejoin_after_network_leave().await?;
                return Ok(BdbEvent::Rejoined);
            }
            Err(NetworkError::LeaveRequested { rejoin: false }) => {
                let _ = self
                    .nlme
                    .leave(&NlmeLeaveRequest {
                        rejoin: false,
                        remove_children: false,
                        source: LeaveSource::NetworkRequest {
                            source: ShortAddress(0xffff),
                        },
                    })
                    .await;
                self.mark_network_leave_without_rejoin();
                return Ok(BdbEvent::Left { rejoin: false });
            }
            Err(e) => return Err(e.into()),
        };
        match poll {
            ZigbeeDevicePoll::Command(command) => self.handle_polled_aps_command(command),
            ZigbeeDevicePoll::Data(indication) => {
                self.handle_polled_aps_data(app, indication, tx_buf, now_ms)
                    .await
            }
            ZigbeeDevicePoll::Ack | ZigbeeDevicePoll::FragmentDeferred => {
                Ok(BdbEvent::UnsupportedFrame)
            }
            ZigbeeDevicePoll::FragmentComplete => {
                // Zero-copy dispatch: borrow defrag_state.buf directly, extract a
                // raw pointer + metadata, release the &self.device borrow, then
                // reconstruct the slice for dispatch.
                let (ptr, len, base) = {
                    let Some(ind) = self.device.peek_defrag_indication() else {
                        return Ok(BdbEvent::UnsupportedFrame);
                    };
                    // Copy all non-lifetime fields out of `ind`, replacing `asdu`
                    // with an empty slice so the result is `'static` and the
                    // `&self.device` borrow ends here (NLL last-use).
                    let base = ApsdeSapIndication { asdu: &[], ..ind };
                    (ind.asdu.as_ptr(), ind.asdu.len(), base)
                };
                // SAFETY: `ptr` points into `self.device.apsme.defrag_state.buf`.
                // `handle_polled_aps_data` only accesses `self.nlme` (TX path) and
                // `app`; it does not read or write `apsme.defrag_state`.
                // `clear_defrag` is called only after the dispatch returns, so the
                // buffer remains valid for the entire async call.
                let asdu = unsafe { core::slice::from_raw_parts(ptr, len) };
                let indication = ApsdeSapIndication { asdu, ..base };
                let result = self
                    .handle_polled_aps_data(app, indication, tx_buf, now_ms)
                    .await;
                self.device.clear_defrag();
                result
            }
        }
    }

    /// Send one pending attribute report, if any.
    ///
    /// Returns `Ok(Some(ready))` when a report was sent, `Ok(None)` when
    /// nothing is pending.
    pub async fn poll_report_once<D: Device>(
        &mut self,
        app: &mut D,
        now_ms: u32,
    ) -> Result<Option<ReportReady>, BdbError> {
        let mut tx_buf = [0u8; 256];
        let ready = match app.next_report(now_ms, &mut tx_buf[3..]) {
            Err(e) => return Err(BdbError::ZclCodec(e)),
            Ok(None) => return Ok(None),
            Ok(Some(r)) => r,
        };
        // 3-byte ZCL header for ReportAttributes (0x0a):
        // frame_control = 0x18 (global | server→client | disable-default-response)
        tx_buf[0] = 0x18;
        tx_buf[1] = 0x00; // sequence
        tx_buf[2] = 0x0a; // ReportAttributes
        let total = 3 + ready.len;
        let delivery_result = match ready.destination {
            ReportDestination::Unicast(peer) => {
                match self
                    .device
                    .send_aps_data(
                        &mut self.nlme,
                        ShortAddress(peer.short_addr),
                        peer.endpoint,
                        ready.profile_id,
                        ready.cluster.id.0,
                        ready.endpoint,
                        &tx_buf[..total],
                    )
                    .await
                {
                    Ok(()) => ReportDeliveryResult::Sent,
                    Err(_) => ReportDeliveryResult::Failed,
                }
            }
            ReportDestination::Bound => {
                // Collect matching binding entries into a local array.
                let binding_table = aib::get_ref().binding_table();
                let mut matched = [BindingEntry {
                    src_endpoint: 0,
                    cluster_id: 0,
                    dst_short_addr: 0,
                    dst_endpoint: 0,
                    profile_id: 0,
                }; MAX_BINDING_TABLE_ENTRIES];
                let mut n_matched = 0usize;
                for entry in binding_table.iter() {
                    if entry.src_endpoint == ready.endpoint
                        && entry.cluster_id == ready.cluster.id.0
                        && n_matched < matched.len()
                    {
                        matched[n_matched] = *entry;
                        n_matched += 1;
                    }
                }
                if n_matched == 0 {
                    ReportDeliveryResult::Failed
                } else {
                    let mut all_sent = true;
                    for entry in &matched[..n_matched] {
                        if self
                            .device
                            .send_aps_data(
                                &mut self.nlme,
                                ShortAddress(entry.dst_short_addr),
                                entry.dst_endpoint,
                                entry.profile_id,
                                entry.cluster_id,
                                entry.src_endpoint,
                                &tx_buf[..total],
                            )
                            .await
                            .is_err()
                        {
                            all_sent = false;
                        }
                    }
                    if all_sent {
                        ReportDeliveryResult::Sent
                    } else {
                        ReportDeliveryResult::Failed
                    }
                }
            }
        };
        app.report_delivery_result(ready, delivery_result, now_ms);
        Ok(Some(ready))
    }

    fn handle_polled_aps_command(&mut self, command: Command) -> Result<BdbEvent, BdbError> {
        match command {
            Command::TransportKey(transport_key) => {
                self.install_transport_key(transport_key)?;
                Ok(BdbEvent::TransportKeyInstalled)
            }
            Command::SwitchKey(SwitchKey { key_seq_number }) => {
                let nib = nib::get_ref();
                if nib
                    .security_material_set()
                    .iter()
                    .any(|m| m.key_seq_number == key_seq_number)
                {
                    nib.set_active_key_seq_number(key_seq_number);
                    Ok(BdbEvent::TransportKeyInstalled)
                } else {
                    log::warn!(
                        "[BDB] switch_key: seq {} not in security material set",
                        key_seq_number
                    );
                    Ok(BdbEvent::UnsupportedFrame)
                }
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
        now_ms: u32,
    ) -> Result<BdbEvent, BdbError> {
        if indication.dst_endpoint == 0 && indication.profile_id == 0x0000 {
            return self.handle_zdo_data(app, indication).await;
        }

        self.handle_zcl_data(app, indication, tx_buf, now_ms).await
    }

    fn source_short_address(
        indication: &zigbee::aps::apsde::ApsdeSapIndication<'_>,
    ) -> Option<ShortAddress> {
        match indication.src_address {
            Address::Network(address) => Some(ShortAddress(address)),
            Address::None | Address::Group(_) | Address::Extended(_) => None,
        }
    }

    async fn handle_zdo_data<D: Device>(
        &mut self,
        app: &mut D,
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

        // ZDP server-side: respond to incoming discovery requests.
        match indication.cluster_id {
            // NWK_addr_req (§2.4.3.1.1) → NWK_addr_rsp (§2.4.4.2.1)
            // Broadcast request: only respond if IEEE address matches ours.
            0x0000 => {
                if payload.len() >= 10 {
                    let ieee_bytes: [u8; 8] = payload[0..8].try_into().unwrap_or([0u8; 8]);
                    let ieee_of_interest = IeeeAddress(u64::from_le_bytes(ieee_bytes));
                    let nib = nib::get_ref();
                    if ieee_of_interest == nib.ieee_address() {
                        let mut buf = [0u8; 12];
                        let n = zdp_nwk_addr_rsp(
                            sequence,
                            nib.ieee_address(),
                            nib.network_address(),
                            &mut buf,
                        );
                        self.device
                            .send_aps_data(&mut self.nlme, source, 0, 0x0000, 0x8000, 0, &buf[..n])
                            .await
                            .ok();
                    }
                }
                return Ok(BdbEvent::UnsupportedFrame);
            }
            // IEEE_addr_req (§2.4.3.1.2) → IEEE_addr_rsp (§2.4.4.2.2)
            // Unicast request: only respond if NWK address matches ours.
            0x0001 => {
                if payload.len() >= 4 {
                    let nwk_of_interest = u16::from_le_bytes([payload[0], payload[1]]);
                    let nib = nib::get_ref();
                    if nwk_of_interest == nib.network_address() {
                        let mut buf = [0u8; 12];
                        let n = zdp_ieee_addr_rsp(
                            sequence,
                            nib.ieee_address(),
                            nib.network_address(),
                            &mut buf,
                        );
                        self.device
                            .send_aps_data(&mut self.nlme, source, 0, 0x0000, 0x8001, 0, &buf[..n])
                            .await
                            .ok();
                    }
                }
                return Ok(BdbEvent::UnsupportedFrame);
            }
            // Node_Desc_req (§2.4.3.1.3) → Node_Desc_rsp (§2.4.4.2.2)
            0x0002 => {
                if payload.len() >= 2 {
                    let addr_of_interest = u16::from_le_bytes([payload[0], payload[1]]);
                    let my_addr = nib::get_ref().network_address();
                    let mut buf = [0u8; 20];
                    let n = zdp_node_desc_rsp(
                        sequence,
                        addr_of_interest,
                        my_addr,
                        self.device.logical_type(),
                        &mut buf,
                    );
                    self.device
                        .send_aps_data(&mut self.nlme, source, 0, 0x0000, 0x8002, 0, &buf[..n])
                        .await
                        .ok();
                }
                return Ok(BdbEvent::UnsupportedFrame);
            }
            // Simple_Desc_req (§2.4.3.1.5) → Simple_Desc_rsp (§2.4.4.2.5)
            0x0004 => {
                if payload.len() >= 3 {
                    let addr_of_interest = u16::from_le_bytes([payload[0], payload[1]]);
                    let endpoint = payload[2];
                    let my_addr = nib::get_ref().network_address();
                    let mut buf = [0u8; 64];
                    let n = if addr_of_interest != my_addr {
                        zdp_error_rsp(sequence, 0x81, addr_of_interest, &mut buf)
                    } else if let Some(desc) =
                        app.endpoints().iter().find(|e| e.endpoint == endpoint)
                    {
                        zdp_simple_desc_rsp(sequence, my_addr, desc, &mut buf)
                    } else {
                        zdp_error_rsp(sequence, 0x83, addr_of_interest, &mut buf)
                    };
                    self.device
                        .send_aps_data(&mut self.nlme, source, 0, 0x0000, 0x8004, 0, &buf[..n])
                        .await
                        .ok();
                }
                return Ok(BdbEvent::UnsupportedFrame);
            }
            // Active_EP_req (§2.4.3.1.6) → Active_EP_rsp (§2.4.4.2.6)
            0x0005 => {
                if payload.len() >= 2 {
                    let addr_of_interest = u16::from_le_bytes([payload[0], payload[1]]);
                    let my_addr = nib::get_ref().network_address();
                    let mut buf = [0u8; 32];
                    let n = if addr_of_interest != my_addr {
                        zdp_error_rsp(sequence, 0x81, addr_of_interest, &mut buf)
                    } else {
                        zdp_active_ep_rsp(sequence, my_addr, app.endpoints(), &mut buf)
                    };
                    self.device
                        .send_aps_data(&mut self.nlme, source, 0, 0x0000, 0x8005, 0, &buf[..n])
                        .await
                        .ok();
                }
                return Ok(BdbEvent::UnsupportedFrame);
            }
            // Match_Desc_req (§2.4.3.1.7) → Match_Desc_rsp (§2.4.4.2.7, cluster 0x8006)
            MATCH_DESC_REQ_CLUSTER_ID => {
                if let Ok(req) = MatchDescReq::try_read_payload(payload) {
                    let my_addr = nib::get_ref().network_address();
                    let mut buf = [0u8; 32];
                    let n = zdp_match_desc_rsp(sequence, my_addr, &req, app, &mut buf);
                    self.device
                        .send_aps_data(&mut self.nlme, source, 0, 0x0000, 0x8006, 0, &buf[..n])
                        .await
                        .ok();
                }
                return Ok(BdbEvent::UnsupportedFrame);
            }
            // Bind_req (§2.4.3.2.2) → Bind_rsp (§2.4.4.3.2, cluster 0x8021)
            // Unicast IEEE dst_addr_mode (0x03) only; group bindings not supported.
            0x0021 => {
                let status: u8 = if payload.len() >= 21 && payload[11] == 0x03 {
                    let src_endpoint = payload[8];
                    let cluster_id = u16::from_le_bytes([payload[9], payload[10]]);
                    let dst_endpoint = payload[20];
                    let profile_id = app
                        .endpoints()
                        .iter()
                        .find(|e| e.endpoint == src_endpoint)
                        .map_or(0u16, |e| e.profile_id);
                    let entry = BindingEntry {
                        src_endpoint,
                        cluster_id,
                        dst_short_addr: source.0,
                        dst_endpoint,
                        profile_id,
                    };
                    if self.bind(entry).is_ok() { 0x00 } else { 0xae }
                } else {
                    0x84 // InvalidField
                };
                let buf = [sequence, status];
                self.device
                    .send_aps_data(&mut self.nlme, source, 0, 0x0000, 0x8021, 0, &buf)
                    .await
                    .ok();
                return Ok(BdbEvent::UnsupportedFrame);
            }
            // Unbind_req (§2.4.3.2.4) → Unbind_rsp (§2.4.4.3.4, cluster 0x8022)
            0x0022 => {
                let status: u8 = if payload.len() >= 21 && payload[11] == 0x03 {
                    let src_endpoint = payload[8];
                    let cluster_id = u16::from_le_bytes([payload[9], payload[10]]);
                    let dst_endpoint = payload[20];
                    let profile_id = app
                        .endpoints()
                        .iter()
                        .find(|e| e.endpoint == src_endpoint)
                        .map_or(0u16, |e| e.profile_id);
                    let entry = BindingEntry {
                        src_endpoint,
                        cluster_id,
                        dst_short_addr: source.0,
                        dst_endpoint,
                        profile_id,
                    };
                    let found = aib::get_ref().binding_table().iter().any(|e| e == &entry);
                    self.unbind(&entry);
                    if found { 0x00 } else { 0x88 } // 0x88 = NoEntry
                } else {
                    0x84 // InvalidField
                };
                let buf = [sequence, status];
                self.device
                    .send_aps_data(&mut self.nlme, source, 0, 0x0000, 0x8022, 0, &buf)
                    .await
                    .ok();
                return Ok(BdbEvent::UnsupportedFrame);
            }
            _ => {}
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
        now_ms: u32,
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

        let ctx = match indication.delivery {
            ApsDeliveryMode::Unicast => DispatchContext::unicast(
                now_ms,
                Some(ApsPeer {
                    short_addr: source.0,
                    endpoint: indication.src_endpoint,
                }),
            ),
            ApsDeliveryMode::Broadcast | ApsDeliveryMode::Group => {
                DispatchContext::broadcast(now_ms)
            }
        };

        let cluster_id = ClusterId::new(indication.cluster_id);
        let event = |response_sent| BdbEvent::ZclHandled {
            source,
            endpoint: indication.dst_endpoint,
            cluster_id: indication.cluster_id,
            response_sent,
        };

        let request = ClusterRequest {
            endpoint: indication.dst_endpoint,
            cluster: ClusterKey::new(cluster_id, frame.manufacturer_code()),
            ctx,
            frame: &frame,
        };
        match app.dispatch_cluster(request, tx_buf) {
            Ok(outcome) => {
                // Sync APS group table when ZCL Groups cluster mutates membership.
                match outcome.effects.group {
                    GroupEffect::Added(gid) => self.add_aps_group(gid, indication.dst_endpoint),
                    GroupEffect::Removed(gid) => {
                        self.remove_aps_group(gid, indication.dst_endpoint)
                    }
                    GroupEffect::AllRemoved => self.remove_all_aps_groups(indication.dst_endpoint),
                    GroupEffect::None => {}
                }
                if outcome.response_len > 0 {
                    self.send_zcl_response(&indication, source, &tx_buf[..outcome.response_len])
                        .await?;
                    Ok(event(true))
                } else {
                    Ok(event(false))
                }
            }
            Err(DispatchError::UnsupportedCluster | DispatchError::UnsupportedEndpoint)
                if should_send_default_response(&frame, ctx, Status::UnsupportedCluster) =>
            {
                let n =
                    build_default_response_for_frame(&frame, Status::UnsupportedCluster, tx_buf)
                        .map_err(BdbError::ZclCodec)?;
                self.send_zcl_response(&indication, source, &tx_buf[..n])
                    .await?;
                Ok(event(true))
            }
            Err(DispatchError::UnsupportedEndpoint)
            | Err(DispatchError::UnsupportedCluster)
            | Err(DispatchError::Codec(_)) => Ok(event(false)),
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

    // Leave/not-joined are terminal during BDB TC exchange. Treating them as
    // "wrong APS command" would retry after the network already evicted us.
    fn propagate_tc_terminal_poll_error(
        poll: &Result<Command, NetworkError>,
    ) -> Result<(), NetworkError> {
        match poll {
            Err(NetworkError::LeaveRequested { rejoin }) => {
                Err(NetworkError::LeaveRequested { rejoin: *rejoin })
            }
            Err(NetworkError::NotJoined) => Err(NetworkError::NotJoined),
            _ => Ok(()),
        }
    }

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

            let poll = self
                .device
                .poll_aps_command(&mut self.nlme, BDBC_TC_LINK_KEY_EXCHANGE_POLL_RETRIES)
                .await;
            Self::propagate_tc_terminal_poll_error(&poll)?;

            match poll {
                Ok(Command::TransportKey(TransportKey::TrustCenterLinkKey(key_desc))) => {
                    log::debug!("[BDB] received new TC link key");
                    break key_desc.key;
                }
                other => {
                    log::debug!(
                        "[BDB] TC link key exchange: expected TRANSPORT-KEY(TC link key), got {other:?}"
                    );
                    if attempts >= BDBC_TC_LINK_KEY_EXCHANGE_ATTEMPTS_MAX {
                        log::warn!("[BDB] TC link key exchange failed: no TRANSPORT-KEY");
                        self.bdb_commissioning_status = BdbCommissioningStatus::TclkExFailure;
                        return Err(NetworkError::NoTransportKey);
                    }
                    continue;
                }
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

            let poll = self
                .device
                .poll_aps_command(&mut self.nlme, BDBC_TC_LINK_KEY_EXCHANGE_POLL_RETRIES)
                .await;
            Self::propagate_tc_terminal_poll_error(&poll)?;

            match poll {
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
                other => {
                    log::debug!(
                        "[BDB] TC link key exchange: expected CONFIRM-KEY(success), got {other:?}"
                    );
                    if attempts >= BDBC_TC_LINK_KEY_EXCHANGE_ATTEMPTS_MAX {
                        log::warn!("[BDB] TC link key exchange failed: no CONFIRM-KEY");
                        self.bdb_commissioning_status = BdbCommissioningStatus::TclkExFailure;
                        return Err(NetworkError::NoTransportKey);
                    }
                    continue;
                }
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
    #[error("network error: {0}")]
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

// ZDP server-side response builders

/// NWK_addr_rsp payload (§2.4.4.2.1) — single-device response.
fn zdp_nwk_addr_rsp(seq: u8, ieee_addr: IeeeAddress, nwk_addr: u16, buf: &mut [u8]) -> usize {
    if buf.len() < 12 {
        return 0;
    }
    buf[0] = seq;
    buf[1] = 0x00; // Status: Success
    buf[2..10].copy_from_slice(&ieee_addr.0.to_le_bytes());
    buf[10..12].copy_from_slice(&nwk_addr.to_le_bytes());
    12
}

/// IEEE_addr_rsp payload (§2.4.4.2.2) — same wire format as NWK_addr_rsp.
fn zdp_ieee_addr_rsp(seq: u8, ieee_addr: IeeeAddress, nwk_addr: u16, buf: &mut [u8]) -> usize {
    zdp_nwk_addr_rsp(seq, ieee_addr, nwk_addr, buf)
}

// ---------------------------------------------------------------------------

fn zdp_error_rsp(seq: u8, status: u8, nwk_addr: u16, buf: &mut [u8]) -> usize {
    buf[0] = seq;
    buf[1] = status;
    buf[2] = (nwk_addr & 0xFF) as u8;
    buf[3] = (nwk_addr >> 8) as u8;
    4
}

fn zdp_node_desc_rsp(
    seq: u8,
    addr_of_interest: u16,
    my_addr: u16,
    logical_type: LogicalType,
    buf: &mut [u8],
) -> usize {
    if addr_of_interest != my_addr {
        return zdp_error_rsp(seq, 0x81, addr_of_interest, buf);
    }
    let (type_byte, mac_cap): (u8, u8) = match logical_type {
        LogicalType::Coordinator => (0b000, 0x8E),
        LogicalType::Router => (0b001, 0x8E),
        LogicalType::EndDevice | LogicalType::Reserved(_) => (0b010, 0x80),
    };
    buf[0] = seq;
    buf[1] = 0x00; // Success
    buf[2] = (my_addr & 0xFF) as u8;
    buf[3] = (my_addr >> 8) as u8;
    // Node descriptor: 13 bytes (§2.3.2.3)
    buf[4] = type_byte; // logical type, no complex/user descriptors
    buf[5] = 0x40; // FrequencyBand=High (2.4 GHz), APSFlags=0
    buf[6] = mac_cap; // MAC capabilities
    buf[7] = 0x00; // ManufacturerCode low
    buf[8] = 0x00; // ManufacturerCode high
    buf[9] = 0x40; // MaxBufferSize = 64
    buf[10] = 0x80; // MaxIncomingTransferSize low = 128
    buf[11] = 0x00; // MaxIncomingTransferSize high
    buf[12] = 0x00; // ServerMask low (no server functions)
    buf[13] = 0x2A; // ServerMask high (ZigBee 3.0 compliance rev 21)
    buf[14] = 0x80; // MaxOutgoingTransferSize low = 128
    buf[15] = 0x00; // MaxOutgoingTransferSize high
    buf[16] = 0x00; // DescriptorCapabilities
    17
}

fn zdp_active_ep_rsp(
    seq: u8,
    nwk_addr: u16,
    endpoints: &[EndpointDescriptor],
    buf: &mut [u8],
) -> usize {
    let count = endpoints.len().min(buf.len().saturating_sub(5)) as u8;
    buf[0] = seq;
    buf[1] = 0x00; // Success
    buf[2] = (nwk_addr & 0xFF) as u8;
    buf[3] = (nwk_addr >> 8) as u8;
    buf[4] = count;
    for (i, ep) in endpoints[..count as usize].iter().enumerate() {
        buf[5 + i] = ep.endpoint;
    }
    5 + count as usize
}

fn zdp_simple_desc_rsp(seq: u8, nwk_addr: u16, desc: &EndpointDescriptor, buf: &mut [u8]) -> usize {
    let in_count = desc.input_clusters.len() as u8;
    let out_count = desc.output_clusters.len() as u8;
    // Simple descriptor length = endpoint(1) + profile(2) + device(2) + version(1)
    //                          + in_count(1) + in_clusters(N*2) + out_count(1) +
    //                            out_clusters(M*2)
    let sd_len = 7 + in_count as usize * 2 + 1 + out_count as usize * 2;
    let total = 5 + sd_len;
    if buf.len() < total {
        return zdp_error_rsp(seq, 0x80, nwk_addr, buf);
    }
    buf[0] = seq;
    buf[1] = 0x00; // Success
    buf[2] = (nwk_addr & 0xFF) as u8;
    buf[3] = (nwk_addr >> 8) as u8;
    buf[4] = sd_len as u8;
    let mut off = 5;
    buf[off] = desc.endpoint;
    off += 1;
    buf[off] = (desc.profile_id & 0xFF) as u8;
    buf[off + 1] = (desc.profile_id >> 8) as u8;
    off += 2;
    buf[off] = (desc.device_id & 0xFF) as u8;
    buf[off + 1] = (desc.device_id >> 8) as u8;
    off += 2;
    buf[off] = desc.device_version & 0x0F;
    off += 1;
    buf[off] = in_count;
    off += 1;
    for &cid in desc.input_clusters {
        buf[off] = (cid.0 & 0xFF) as u8;
        buf[off + 1] = (cid.0 >> 8) as u8;
        off += 2;
    }
    buf[off] = out_count;
    off += 1;
    for &cid in desc.output_clusters {
        buf[off] = (cid.0 & 0xFF) as u8;
        buf[off + 1] = (cid.0 >> 8) as u8;
        off += 2;
    }
    off
}

fn zdp_match_desc_rsp<D: Device>(
    seq: u8,
    my_addr: u16,
    req: &MatchDescReq,
    app: &D,
    buf: &mut [u8],
) -> usize {
    let mut match_list = [0u8; 16];
    let mut match_len = 0usize;

    for desc in app.endpoints() {
        if desc.profile_id != req.profile_id {
            continue;
        }
        let in_match = req
            .in_cluster_list
            .iter()
            .any(|c| desc.input_clusters.iter().any(|cl| cl.0 == *c));
        let out_match = req
            .out_cluster_list
            .iter()
            .any(|c| desc.output_clusters.iter().any(|cl| cl.0 == *c));
        if (in_match || out_match) && match_len < match_list.len() {
            match_list[match_len] = desc.endpoint;
            match_len += 1;
        }
    }

    let status = if match_len > 0 { 0x00u8 } else { 0x88u8 };
    buf[0] = seq;
    buf[1] = status;
    buf[2] = (my_addr & 0xFF) as u8;
    buf[3] = (my_addr >> 8) as u8;
    buf[4] = match_len as u8;
    buf[5..5 + match_len].copy_from_slice(&match_list[..match_len]);
    5 + match_len
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
    use zigbee::nwk::frame::CommandFrame as NwkCommandFrame;
    use zigbee::nwk::frame::Frame as NwkFrame;
    use zigbee::nwk::frame::command::Command as NwkCommand;
    use zigbee::nwk::frame::command::leave::CommandOptions as LeaveCommandOptions;
    use zigbee::nwk::frame::command::leave::Leave;
    use zigbee::nwk::frame::command::network_status::NetworkStatus;
    use zigbee::nwk::frame::command::network_status::NetworkStatusCode;
    use zigbee::nwk::frame::command::rejoin_response::RejoinResponse;
    use zigbee::nwk::frame::frame_control::DiscoverRoute;
    use zigbee::nwk::frame::frame_control::FrameControl as NwkFrameControl;
    use zigbee::nwk::frame::frame_control::FrameType as NwkFrameType;
    use zigbee::nwk::frame::header::Header as NwkHeader;
    use zigbee::nwk::nib;
    use zigbee::nwk::nib::DeviceType;
    use zigbee::nwk::nib::NetworkSecurityMaterialDescriptor;
    use zigbee::nwk::nib::NibStorage;
    use zigbee::nwk::nib::NwkNeighbor;
    use zigbee::nwk::nib::relationship;
    use zigbee::nwk::nlme::NetworkError;
    use zigbee::nwk::nlme::Nlme;
    use zigbee::security::SecurityContext;
    use zigbee_cluster_library::cluster_server::ClusterRequest;
    use zigbee_cluster_library::cluster_server::ClusterServer;
    use zigbee_cluster_library::cluster_server::DeviceServerVisitor;
    use zigbee_cluster_library::cluster_server::DispatchError;
    use zigbee_cluster_library::cluster_server::DispatchOutcome;
    use zigbee_cluster_library::cluster_server::EndpointDescriptor;
    use zigbee_cluster_library::cluster_server::ServerMeta;
    use zigbee_cluster_library::cluster_server::dispatch_via_servers;
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
            fn set_channel(
                &mut self,
                channel: u8,
                pan_id: ShortAddress,
            ) -> Result<(), MacError>;
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
            fn sync(
                &mut self,
                request: zigbee_mac::mlme::MlmeSyncRequest,
            ) -> Result<(), MacError>;
            fn reset(&mut self, set_default_pib: bool) -> Result<(), MacError>;
        }
    }

    struct AppDevice {
        basic: BasicServer,
        codec_error: bool,
        tick_count: u8,
        last_tick_ms: u32,
    }

    impl AppDevice {
        fn new() -> Self {
            Self {
                basic: BasicServer::new(BasicConfig::new(3, "ACME", "Sensor-1", 0x01, true)),
                codec_error: false,
                tick_count: 0,
                last_tick_ms: 0,
            }
        }

        fn codec_error() -> Self {
            Self {
                basic: BasicServer::new(BasicConfig::new(3, "ACME", "Sensor-1", 0x01, true)),
                codec_error: true,
                tick_count: 0,
                last_tick_ms: 0,
            }
        }
    }

    static APP_ENDPOINTS: &[EndpointDescriptor] = &[EndpointDescriptor {
        endpoint: 1,
        profile_id: 0x0104,
        device_id: 0,
        device_version: 0,
        input_clusters: &[],
        output_clusters: &[],
    }];

    static APP_ENDPOINTS_TEMP: &[EndpointDescriptor] = &[EndpointDescriptor {
        endpoint: 1,
        profile_id: 0x0104,
        device_id: 0,
        device_version: 0,
        input_clusters: &[ClusterId::new(0x0402)], // Temperature Measurement
        output_clusters: &[],
    }];

    struct AppDeviceTemp;

    impl Device for AppDeviceTemp {
        fn endpoints(&self) -> &'static [EndpointDescriptor] {
            APP_ENDPOINTS_TEMP
        }

        fn visit_servers<V: DeviceServerVisitor>(&mut self, _visitor: &mut V)
        where
            Self: Sized,
        {
        }
    }

    impl Device for AppDevice {
        fn endpoints(&self) -> &'static [EndpointDescriptor] {
            APP_ENDPOINTS
        }

        fn visit_servers<V: DeviceServerVisitor>(&mut self, visitor: &mut V) {
            visitor.visit(
                ServerMeta {
                    endpoint: 1,
                    profile_id: 0x0104,
                    cluster: ClusterKey::new(BasicServer::CLUSTER_ID, None),
                },
                &mut self.basic,
            );
        }

        fn dispatch_cluster(
            &mut self,
            request: ClusterRequest<'_>,
            buf: &mut [u8],
        ) -> Result<DispatchOutcome, DispatchError>
        where
            Self: Sized,
        {
            if self.codec_error {
                return Err(DispatchError::Codec(ZclError::BufferTooSmall));
            }
            dispatch_via_servers(self, request, buf)
        }

        fn tick(&mut self, now_ms: u32) -> DeviceTick
        where
            Self: Sized,
        {
            self.tick_count = self.tick_count.saturating_add(1);
            self.last_tick_ms = now_ms;
            DeviceTick {
                changed: true,
                next_tick_ms: Some(now_ms.wrapping_add(5)),
            }
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
            extended_pan_id: IeeeAddress(0x1122),
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

        // Reset per-test AIB state that now persists in the global singleton.
        aib::get_ref().set_binding_table(StorageVec::new());

        let nlme = Nlme::new(mac);
        nlme.nib().set_network_address(0x5678);
        nlme.nib().set_security_material_set(StorageVec::new());
        nlme.nib().set_panid(0xabcd);
        nlme.nib().set_extended_panid(0x1122);
        nlme.nib().set_logical_channel(11);
        nlme.nib()
            .set_capability_information(CapabilityInformation(0x80));
        let mut neighbors = StorageVec::new();
        neighbors.push(make_parent()).unwrap();
        nlme.nib().set_neighbor_table(neighbors);

        (guard, BaseDeviceBehavior::new(nlme, Config::default()))
    }

    fn install_test_security_material(bdb: &mut BaseDeviceBehavior<MockMlme>) {
        let mut sec = StorageVec::new();
        sec.push(NetworkSecurityMaterialDescriptor {
            key_seq_number: 0,
            outgoing_frame_counter: 0,
            incoming_frame_counter_set: StorageVec::new(),
            key: ByteArray([0xAB; 16]),
            network_key_type: 0x01,
        })
        .unwrap();
        bdb.nlme.nib().set_security_material_set(sec);
        bdb.nlme.nib().set_active_key_seq_number(0);

        let tc_ieee = IeeeAddress(0x0012_4b00_29e7_ae76);
        let aib = aib::get_ref();
        aib.set_trust_center_address(tc_ieee);
        let mut key_set = StorageVec::new();
        key_set
            .push(DeviceKeyPairDescriptor {
                device_address: tc_ieee,
                key_attributes: KeyAttribute::ProvisionalKey,
                link_key: ByteArray(zigbee::security::TRUST_CENTER_LINK_KEY),
                outgoing_frame_counter: 0,
                incoming_frame_counter: 0,
                link_key_type: LinkKeyType::GlobalLinkKey,
            })
            .unwrap();
        aib.set_device_key_pair_set(key_set);
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

    fn write_secured_rejoin_response(buf: &mut [u8], old_addr: u16, new_addr: u16) -> usize {
        let frame_control = NwkFrameControl(0)
            .set_frame_type(NwkFrameType::NwkCommand)
            .set_protocol_version(2)
            .set_discover_route(DiscoverRoute::Suppress)
            .set_security_flag(true);
        let header = NwkHeader {
            frame_control,
            destination: ShortAddress(old_addr),
            source: ShortAddress(0x0000),
            radius: 30,
            sequence_number: 0x55,
            destination_ieee: None,
            source_ieee: None,
            multicast_control: None,
            source_route_subframe: None,
        };
        let frame = NwkFrame::NwkCommand(NwkCommandFrame {
            header,
            command: NwkCommand::RejoinResponse(RejoinResponse {
                network_address: ShortAddress(new_addr),
                status: 0,
            }),
        });
        SecurityContext::get()
            .encrypt_nwk_frame_in_place(frame, buf)
            .unwrap()
    }

    fn write_secured_nwk_command(
        buf: &mut [u8],
        destination: u16,
        command: NwkCommand<'_>,
    ) -> usize {
        let frame_control = NwkFrameControl(0)
            .set_frame_type(NwkFrameType::NwkCommand)
            .set_protocol_version(2)
            .set_discover_route(DiscoverRoute::Suppress)
            .set_security_flag(true);
        let header = NwkHeader {
            frame_control,
            destination: ShortAddress(destination),
            source: ShortAddress(0x0000),
            radius: 30,
            sequence_number: 0x56,
            destination_ieee: None,
            source_ieee: None,
            multicast_control: None,
            source_route_subframe: None,
        };
        let frame = NwkFrame::NwkCommand(NwkCommandFrame { header, command });
        SecurityContext::get()
            .encrypt_nwk_frame_in_place(frame, buf)
            .unwrap()
    }

    fn write_secured_leave_request(buf: &mut [u8], destination: u16, rejoin: bool) -> usize {
        let options = LeaveCommandOptions(0).set_request(true).set_rejoin(rejoin);
        write_secured_nwk_command(
            buf,
            destination,
            NwkCommand::Leave(Leave {
                command_options: options,
            }),
        )
    }

    fn write_secured_network_status(buf: &mut [u8], destination: u16) -> usize {
        write_secured_nwk_command(
            buf,
            destination,
            NwkCommand::NetworkStatus(NetworkStatus {
                status_code: NetworkStatusCode::AddressConflict,
                destination_address: ShortAddress(destination),
            }),
        )
    }

    fn is_secured_rejoin_request(dest: &MacAddress, payload: &[u8]) -> bool {
        if *dest != MacAddress::Short(PanId(0xabcd), MacShortAddress(0x0000)) {
            return false;
        }
        let mut frame_buf = [0u8; 256];
        frame_buf[..payload.len()].copy_from_slice(payload);
        let Ok(NwkFrame::NwkCommand(command_frame)) =
            SecurityContext::get().decrypt_nwk_frame_in_place(&mut frame_buf[..payload.len()])
        else {
            return false;
        };
        command_frame.header.frame_control.security_flag()
            && command_frame.header.destination == ShortAddress(0x0000)
            && command_frame.header.source == ShortAddress(0x5678)
            && matches!(command_frame.command, NwkCommand::RejoinRequest(_))
    }

    fn is_device_annce_broadcast(dest: &MacAddress, _payload: &[u8]) -> bool {
        *dest == MacAddress::Short(PanId(0xabcd), MacShortAddress(0xfffd))
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

    const IN_NODE_DESC_REQ: &[u8] = &[
        0x08, 0x00, 0x78, 0x56, 0x34, 0x12, 0x1e, 0xaa, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x41, 0x78, 0x56,
    ];
    const OUT_NODE_DESC_RSP: &[u8] = &[
        0x00, 0x00, 0x02, 0x80, 0x00, 0x00, 0x00, 0x01, 0x41, 0x00, 0x78, 0x56, 0x01, 0x40, 0x8e,
        0x00, 0x00, 0x40, 0x80, 0x00, 0x00, 0x2a, 0x80, 0x00, 0x00,
    ];

    const IN_SIMPLE_DESC_REQ: &[u8] = &[
        0x08, 0x00, 0x78, 0x56, 0x34, 0x12, 0x1e, 0xaa, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x43, 0x78, 0x56, 0x01,
    ];
    const OUT_SIMPLE_DESC_RSP: &[u8] = &[
        0x00, 0x00, 0x04, 0x80, 0x00, 0x00, 0x00, 0x01, 0x43, 0x00, 0x78, 0x56, 0x08, 0x01, 0x04,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    const IN_ACTIVE_EP_REQ: &[u8] = &[
        0x08, 0x00, 0x78, 0x56, 0x34, 0x12, 0x1e, 0xaa, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x42, 0x78, 0x56,
    ];
    const OUT_ACTIVE_EP_RSP: &[u8] = &[
        0x00, 0x00, 0x05, 0x80, 0x00, 0x00, 0x00, 0x01, 0x42, 0x00, 0x78, 0x56, 0x01, 0x01,
    ];

    // Match_Desc_req (cluster 0x0006): profile=0x0104, in=[0x0402 Temperature],
    // out=[]
    const IN_MATCH_DESC_REQ: &[u8] = &[
        0x08, 0x00, 0x78, 0x56, 0x34, 0x12, 0x1e, 0xaa, // NWK header
        0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, // APS: cluster=0x0006
        0x41, 0x78, 0x56, // ZDP seq, addr=0x5678
        0x04, 0x01, // profile_id=0x0104
        0x01, // num_in_clusters=1
        0x02, 0x04, // cluster 0x0402
        0x00, // num_out_clusters=0
    ];
    // Match_Desc_rsp (cluster 0x8006): endpoint 1 matched
    const OUT_MATCH_DESC_RSP: &[u8] = &[
        0x00, 0x00, 0x06, 0x80, 0x00, 0x00, 0x00, 0x01, // APS: cluster=0x8006
        0x41, 0x00, 0x78, 0x56, 0x01, 0x01, // seq, status=OK, addr, len=1, ep=1
    ];
    // Match_Desc_rsp when no endpoints match (status=0x88)
    const OUT_MATCH_DESC_RSP_NO_MATCH: &[u8] = &[
        0x00, 0x00, 0x06, 0x80, 0x00, 0x00, 0x00, 0x01, 0x41, 0x88, 0x78, 0x56,
        0x00, // seq, status=NoMatch(0x88), addr, len=0
    ];

    // NWK_addr_req (cluster 0x0000): query IEEE addr = IeeeAddress(0) = our addr in
    // tests
    const IN_NWK_ADDR_REQ: &[u8] = &[
        0x08, 0x00, 0x78, 0x56, 0x34, 0x12, 0x1e, 0xaa, // NWK header
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // APS: cluster=0x0000
        0x41, // ZDP seq
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // IEEE addr = IeeeAddress(0)
        0x00, 0x00, // request_type=Single, start_index=0
    ];
    // NWK_addr_rsp (cluster 0x8000): seq=0x41, status=OK, IEEE=0, NWK=0x5678
    const OUT_NWK_ADDR_RSP: &[u8] = &[
        0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x01, // APS: cluster=0x8000
        0x41, 0x00, // ZDP seq, status=Success
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // IEEE addr = IeeeAddress(0)
        0x78, 0x56, // NWK addr = 0x5678
    ];
    // NWK_addr_req for a different IEEE addr (all-0xFF): no response expected
    const IN_NWK_ADDR_REQ_OTHER: &[u8] = &[
        0x08, 0x00, 0x78, 0x56, 0x34, 0x12, 0x1e, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x41, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
    ];

    // IEEE_addr_req (cluster 0x0001): query NWK addr = 0x5678 = our addr in tests
    const IN_IEEE_ADDR_REQ: &[u8] = &[
        0x08, 0x00, 0x78, 0x56, 0x34, 0x12, 0x1e, 0xaa, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x42, 0x78, 0x56, 0x00, 0x00, // ZDP seq, NWK=0x5678, req_type, start_idx
    ];
    // IEEE_addr_rsp (cluster 0x8001): seq=0x42, status=OK, IEEE=0, NWK=0x5678
    const OUT_IEEE_ADDR_RSP: &[u8] = &[
        0x00, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x01, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x78, 0x56,
    ];
    // IEEE_addr_req for a different NWK addr (0x9999): no response expected
    const IN_IEEE_ADDR_REQ_OTHER: &[u8] = &[
        0x08, 0x00, 0x78, 0x56, 0x34, 0x12, 0x1e, 0xaa, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x42, 0x99, 0x99, 0x00, 0x00,
    ];

    // Bind_req (cluster 0x0021): bind ep=1, cluster=0x0402, dst_mode=unicast,
    // dst_ep=1 src_address = IeeeAddress(0) (our addr), dst_address = HA's IEEE
    // (arbitrary bytes)
    const IN_BIND_REQ: &[u8] = &[
        0x08, 0x00, 0x78, 0x56, 0x34, 0x12, 0x1e, 0xaa, // NWK header
        0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x01, // APS: cluster=0x0021
        0x44, // ZDP seq
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SrcAddress = IeeeAddress(0)
        0x01, // SrcEndpoint = 1
        0x02, 0x04, // ClusterID = 0x0402
        0x03, // DstAddrMode = 0x03 (unicast IEEE)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // DstAddress = HA's IEEE
        0x01, // DstEndpoint = 1
    ];
    // Bind_rsp (cluster 0x8021): status=Success
    const OUT_BIND_RSP: &[u8] = &[
        0x00, 0x00, 0x21, 0x80, 0x00, 0x00, 0x00, 0x01, // APS: cluster=0x8021
        0x44, 0x00, // ZDP seq, status=Success
    ];
    // Bind_rsp (cluster 0x8021): status=TableFull (0xae)
    const OUT_BIND_RSP_TABLE_FULL: &[u8] =
        &[0x00, 0x00, 0x21, 0x80, 0x00, 0x00, 0x00, 0x01, 0x44, 0xae];

    // Unbind_req (cluster 0x0022): same fields as IN_BIND_REQ but cluster 0x0022,
    // seq 0x45
    const IN_UNBIND_REQ: &[u8] = &[
        0x08, 0x00, 0x78, 0x56, 0x34, 0x12, 0x1e, 0xaa, // NWK header
        0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x01, // APS: cluster=0x0022
        0x45, // ZDP seq
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SrcAddress = IeeeAddress(0)
        0x01, // SrcEndpoint = 1
        0x02, 0x04, // ClusterID = 0x0402
        0x03, // DstAddrMode = 0x03 (unicast IEEE)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // DstAddress = HA's IEEE
        0x01, // DstEndpoint = 1
    ];
    // Unbind_rsp (cluster 0x8022): status=Success
    const OUT_UNBIND_RSP: &[u8] = &[0x00, 0x00, 0x22, 0x80, 0x00, 0x00, 0x00, 0x01, 0x45, 0x00];
    // Unbind_rsp (cluster 0x8022): status=NoEntry (0x88)
    const OUT_UNBIND_RSP_NO_ENTRY: &[u8] =
        &[0x00, 0x00, 0x22, 0x80, 0x00, 0x00, 0x00, 0x01, 0x45, 0x88];

    const IN_BROADCAST_UNSUPPORTED_CLUSTER: &[u8] = &[
        0x08, 0x00, 0xfd, 0xff, 0x34, 0x12, 0x1e, 0xaa, 0x08, 0x01, 0x06, 0x00, 0x04, 0x01, 0x02,
        0x58, 0x00, 0x44, 0x00, 0x00, 0x00,
    ];

    const IN_CODEC_ERROR: &[u8] = &[
        0x08, 0x00, 0x78, 0x56, 0x34, 0x12, 0x1e, 0xaa, 0x00, 0x01, 0x00, 0x00, 0x04, 0x01, 0x02,
        0x59, 0x00, 0x55, 0x00, 0x00, 0x00,
    ];

    // Plain NWK command frame (frame type = NWK command, protocol version = 2).
    // Route/link-status chatter is valid at NWK but has no APS payload for BDB.
    const IN_NWK_COMMAND: &[u8] = &[0x09, 0x00, 0x78, 0x56, 0x34, 0x12, 0x1e, 0xab, 0xff];
    const IN_NWK_LEAVE_REQUEST: &[u8] =
        &[0x09, 0x00, 0x78, 0x56, 0x34, 0x12, 0x1e, 0xac, 0x04, 0x60];

    #[test]
    fn poll_once_read_attributes_sends_cluster_response() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_READ_BASIC);
        expect_zcl_response(&mut mac, OUT_READ_BASIC);
        let (_guard, mut bdb) = make_bdb(mac);
        let mut app = AppDevice::new();

        let event = block_on(bdb.poll_once(&mut app, 0)).unwrap();

        assert_eq!(
            event,
            BdbEvent::ZclHandled {
                source: ShortAddress(0x1234),
                endpoint: 0x01,
                cluster_id: 0x0000,
                response_sent: true,
            }
        );
        assert_eq!(app.tick_count, 1);
        assert_eq!(app.last_tick_ms, 0);
        assert_eq!(
            bdb.last_device_tick(),
            DeviceTick {
                changed: true,
                next_tick_ms: Some(5),
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

        let event = block_on(bdb.poll_once(&mut app, 0)).unwrap();

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

        let event = block_on(bdb.poll_once(&mut app, 0)).unwrap();

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

        let event = block_on(bdb.poll_once(&mut app, 0)).unwrap();

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
    fn poll_once_match_desc_req_responds_when_cluster_matches() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_MATCH_DESC_REQ);
        expect_zcl_response(&mut mac, OUT_MATCH_DESC_RSP);
        let (_guard, mut bdb) = make_bdb(mac);
        let mut app = AppDeviceTemp;

        let event = block_on(bdb.poll_once(&mut app, 0)).unwrap();

        assert_eq!(event, BdbEvent::UnsupportedFrame);
    }

    #[test]
    fn poll_once_match_desc_req_responds_no_match_when_no_clusters() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_MATCH_DESC_REQ);
        expect_zcl_response(&mut mac, OUT_MATCH_DESC_RSP_NO_MATCH);
        let (_guard, mut bdb) = make_bdb(mac);
        let mut app = AppDevice::new(); // empty cluster lists → no match

        let event = block_on(bdb.poll_once(&mut app, 0)).unwrap();

        assert_eq!(event, BdbEvent::UnsupportedFrame);
    }

    #[test]
    fn poll_once_node_desc_req_sends_zdo_response() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_NODE_DESC_REQ);
        expect_zcl_response(&mut mac, OUT_NODE_DESC_RSP);
        let (_guard, mut bdb) = make_bdb(mac);
        let mut app = AppDevice::new();

        let event = block_on(bdb.poll_once(&mut app, 0)).unwrap();

        assert_eq!(event, BdbEvent::UnsupportedFrame);
    }

    #[test]
    fn poll_once_simple_desc_req_sends_endpoint_descriptor() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_SIMPLE_DESC_REQ);
        expect_zcl_response(&mut mac, OUT_SIMPLE_DESC_RSP);
        let (_guard, mut bdb) = make_bdb(mac);
        let mut app = AppDevice::new();

        let event = block_on(bdb.poll_once(&mut app, 0)).unwrap();

        assert_eq!(event, BdbEvent::UnsupportedFrame);
    }

    #[test]
    fn poll_once_active_ep_req_sends_endpoint_list() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_ACTIVE_EP_REQ);
        expect_zcl_response(&mut mac, OUT_ACTIVE_EP_RSP);
        let (_guard, mut bdb) = make_bdb(mac);
        let mut app = AppDevice::new();

        let event = block_on(bdb.poll_once(&mut app, 0)).unwrap();

        assert_eq!(event, BdbEvent::UnsupportedFrame);
    }

    #[test]
    fn poll_once_nwk_addr_req_responds_with_own_address() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_NWK_ADDR_REQ);
        expect_zcl_response(&mut mac, OUT_NWK_ADDR_RSP);
        let (_guard, mut bdb) = make_bdb(mac);
        let mut app = AppDevice::new();

        let event = block_on(bdb.poll_once(&mut app, 0)).unwrap();

        assert_eq!(event, BdbEvent::UnsupportedFrame);
    }

    #[test]
    fn poll_once_nwk_addr_req_ignores_different_ieee_address() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_NWK_ADDR_REQ_OTHER);
        // no transmit_data expectation — mockall panics if it fires unexpectedly
        let (_guard, mut bdb) = make_bdb(mac);
        let mut app = AppDevice::new();

        let event = block_on(bdb.poll_once(&mut app, 0)).unwrap();

        assert_eq!(event, BdbEvent::UnsupportedFrame);
    }

    #[test]
    fn poll_once_ieee_addr_req_responds_with_own_ieee_address() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_IEEE_ADDR_REQ);
        expect_zcl_response(&mut mac, OUT_IEEE_ADDR_RSP);
        let (_guard, mut bdb) = make_bdb(mac);
        let mut app = AppDevice::new();

        let event = block_on(bdb.poll_once(&mut app, 0)).unwrap();

        assert_eq!(event, BdbEvent::UnsupportedFrame);
    }

    #[test]
    fn poll_once_ieee_addr_req_ignores_different_nwk_address() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_IEEE_ADDR_REQ_OTHER);
        let (_guard, mut bdb) = make_bdb(mac);
        let mut app = AppDevice::new();

        let event = block_on(bdb.poll_once(&mut app, 0)).unwrap();

        assert_eq!(event, BdbEvent::UnsupportedFrame);
    }

    #[test]
    fn switch_key_activates_matching_key() {
        let mut mac = MockMlme::new();
        mac.expect_poll_data()
            .returning(|_, _| Err(MacError::NoData));
        let (_guard, mut bdb) = make_bdb(mac);
        install_test_security_material(&mut bdb); // installs seq=0

        let event = bdb
            .handle_polled_aps_command(Command::SwitchKey(SwitchKey { key_seq_number: 0 }))
            .unwrap();

        assert_eq!(event, BdbEvent::TransportKeyInstalled);
        assert_eq!(nib::get_ref().active_key_seq_number(), 0);
    }

    #[test]
    fn switch_key_unknown_seq_returns_unsupported() {
        let mut mac = MockMlme::new();
        mac.expect_poll_data()
            .returning(|_, _| Err(MacError::NoData));
        let (_guard, mut bdb) = make_bdb(mac);
        install_test_security_material(&mut bdb); // installs seq=0, not seq=7

        let event = bdb
            .handle_polled_aps_command(Command::SwitchKey(SwitchKey { key_seq_number: 7 }))
            .unwrap();

        assert_eq!(event, BdbEvent::UnsupportedFrame);
        assert_eq!(nib::get_ref().active_key_seq_number(), 0);
    }

    #[test]
    fn poll_once_bind_req_adds_binding() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_BIND_REQ);
        expect_zcl_response(&mut mac, OUT_BIND_RSP);
        let (_guard, mut bdb) = make_bdb(mac);
        let mut app = AppDeviceTemp;

        let event = block_on(bdb.poll_once(&mut app, 0)).unwrap();

        assert_eq!(event, BdbEvent::UnsupportedFrame);
        assert_eq!(bdb.bindings().len(), 1);
        assert_eq!(
            bdb.bindings()[0],
            BindingEntry {
                src_endpoint: 1,
                cluster_id: 0x0402,
                dst_short_addr: 0x1234,
                dst_endpoint: 1,
                profile_id: 0x0104,
            }
        );
    }

    #[test]
    fn poll_once_bind_req_table_full_returns_table_full_status() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_BIND_REQ);
        expect_zcl_response(&mut mac, OUT_BIND_RSP_TABLE_FULL);
        let (_guard, mut bdb) = make_bdb(mac);
        let mut app = AppDeviceTemp;
        for i in 0..MAX_BINDING_TABLE_ENTRIES {
            bdb.bind(BindingEntry {
                src_endpoint: 1,
                cluster_id: i as u16,
                dst_short_addr: 0x5678,
                dst_endpoint: 1,
                profile_id: 0x0104,
            })
            .unwrap();
        }

        let event = block_on(bdb.poll_once(&mut app, 0)).unwrap();

        assert_eq!(event, BdbEvent::UnsupportedFrame);
    }

    #[test]
    fn poll_once_unbind_req_removes_existing_binding() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_UNBIND_REQ);
        expect_zcl_response(&mut mac, OUT_UNBIND_RSP);
        let (_guard, mut bdb) = make_bdb(mac);
        let mut app = AppDeviceTemp;
        bdb.bind(BindingEntry {
            src_endpoint: 1,
            cluster_id: 0x0402,
            dst_short_addr: 0x1234,
            dst_endpoint: 1,
            profile_id: 0x0104,
        })
        .unwrap();

        let event = block_on(bdb.poll_once(&mut app, 0)).unwrap();

        assert_eq!(event, BdbEvent::UnsupportedFrame);
        assert!(bdb.bindings().is_empty());
    }

    #[test]
    fn poll_once_unbind_req_no_entry_returns_no_entry_status() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_UNBIND_REQ);
        expect_zcl_response(&mut mac, OUT_UNBIND_RSP_NO_ENTRY);
        let (_guard, mut bdb) = make_bdb(mac);
        let mut app = AppDeviceTemp;

        let event = block_on(bdb.poll_once(&mut app, 0)).unwrap();

        assert_eq!(event, BdbEvent::UnsupportedFrame);
    }

    #[test]
    fn poll_once_codec_error_sends_no_partial_response() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_CODEC_ERROR);
        let (_guard, mut bdb) = make_bdb(mac);
        let mut app = AppDevice::codec_error();

        let event = block_on(bdb.poll_once(&mut app, 0)).unwrap();

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

    #[test]
    fn poll_once_no_pending_data_is_idle() {
        let mut mac = MockMlme::new();
        mac.expect_poll_data()
            .returning(|_, _| Err(MacError::NoData));
        let (_guard, mut bdb) = make_bdb(mac);
        let mut app = AppDevice::new();

        let event = block_on(bdb.poll_once(&mut app, 0)).unwrap();

        assert_eq!(event, BdbEvent::UnsupportedFrame);
    }

    #[test]
    fn poll_once_nwk_command_frame_is_idle() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_NWK_COMMAND);
        let (_guard, mut bdb) = make_bdb(mac);
        let mut app = AppDevice::new();

        let event = block_on(bdb.poll_once(&mut app, 0)).unwrap();

        assert_eq!(event, BdbEvent::UnsupportedFrame);
    }

    #[test]
    fn poll_once_nwk_leave_rejoin_attempts_rejoin_and_announces() {
        let mut mac = MockMlme::new();
        let mut seq = mockall::Sequence::new();
        mac.expect_poll_data()
            .times(1)
            .in_sequence(&mut seq)
            .withf(|coord_address, _| {
                *coord_address == MacAddress::Short(PanId(0xabcd), MacShortAddress(0x0000))
            })
            .returning(|_, buf| {
                let len = write_secured_leave_request(buf, 0x5678, true);
                Ok((len, 200))
            });
        mac.expect_transmit_data()
            .times(1)
            .in_sequence(&mut seq)
            .withf(is_secured_rejoin_request)
            .returning(|_, _| Ok(()));
        mac.expect_poll_data()
            .times(1)
            .in_sequence(&mut seq)
            .withf(|coord_address, _| {
                *coord_address == MacAddress::Short(PanId(0xabcd), MacShortAddress(0x0000))
            })
            .returning(|_, buf| {
                let len = write_secured_rejoin_response(buf, 0x5678, 0x9c5d);
                Ok((len, 200))
            });
        mac.expect_transmit_data()
            .times(1)
            .in_sequence(&mut seq)
            .withf(is_device_annce_broadcast)
            .returning(|_, _| Ok(()));

        let (_guard, mut bdb) = make_bdb(mac);
        install_test_security_material(&mut bdb);
        let mut app = AppDevice::new();

        let event = block_on(bdb.poll_once(&mut app, 0)).unwrap();

        assert_eq!(event, BdbEvent::Rejoined);
        assert_eq!(bdb.nlme.nib().network_address(), 0x9c5d);
        assert!(bdb.bdb_node_is_on_a_network);
        assert_eq!(
            bdb.bdb_commissioning_status,
            BdbCommissioningStatus::Success
        );
    }

    // ------------------------------------------------------------------

    #[test]
    fn captured_join_shape_ignores_unsolicited_response_then_rejoins() {
        let mut mac = MockMlme::new();
        let mut seq = mockall::Sequence::new();
        mac.expect_poll_data()
            .times(1)
            .in_sequence(&mut seq)
            .withf(|coord_address, _| {
                *coord_address == MacAddress::Short(PanId(0xabcd), MacShortAddress(0x0000))
            })
            .returning(|_, buf| {
                let len = write_secured_network_status(buf, 0x5678);
                Ok((len, 200))
            });
        mac.expect_poll_data()
            .times(1)
            .in_sequence(&mut seq)
            .withf(|coord_address, _| {
                *coord_address == MacAddress::Short(PanId(0xabcd), MacShortAddress(0x0000))
            })
            .returning(|_, buf| {
                let len = write_secured_rejoin_response(buf, 0x5678, 0x9c5d);
                Ok((len, 200))
            });
        mac.expect_poll_data()
            .times(1)
            .in_sequence(&mut seq)
            .withf(|coord_address, _| {
                *coord_address == MacAddress::Short(PanId(0xabcd), MacShortAddress(0x0000))
            })
            .returning(|_, buf| {
                let len = write_secured_leave_request(buf, 0x5678, true);
                Ok((len, 200))
            });
        mac.expect_transmit_data()
            .times(1)
            .in_sequence(&mut seq)
            .withf(is_secured_rejoin_request)
            .returning(|_, _| Ok(()));
        mac.expect_poll_data()
            .times(1)
            .in_sequence(&mut seq)
            .withf(|coord_address, _| {
                *coord_address == MacAddress::Short(PanId(0xabcd), MacShortAddress(0x0000))
            })
            .returning(|_, buf| {
                let len = write_secured_rejoin_response(buf, 0x5678, 0x9c5d);
                Ok((len, 200))
            });
        mac.expect_transmit_data()
            .times(1)
            .in_sequence(&mut seq)
            .withf(is_device_annce_broadcast)
            .returning(|_, _| Ok(()));

        let (_guard, mut bdb) = make_bdb(mac);
        install_test_security_material(&mut bdb);
        let mut app = AppDevice::new();

        let first = block_on(bdb.poll_once(&mut app, 0)).unwrap();
        let second = block_on(bdb.poll_once(&mut app, 1)).unwrap();
        let third = block_on(bdb.poll_once(&mut app, 2)).unwrap();

        assert_eq!(first, BdbEvent::UnsupportedFrame);
        assert_eq!(second, BdbEvent::UnsupportedFrame);
        assert_eq!(third, BdbEvent::Rejoined);
        assert_eq!(bdb.nlme.nib().network_address(), 0x9c5d);
        assert!(bdb.bdb_node_is_on_a_network);
        assert_eq!(
            bdb.bdb_commissioning_status,
            BdbCommissioningStatus::Success
        );
    }
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

    #[test]
    fn tc_link_key_exchange_polls_before_retrying_request_key() {
        let attempts = usize::from(BDBC_TC_LINK_KEY_EXCHANGE_ATTEMPTS_MAX);
        let polls_per_attempt = usize::from(BDBC_TC_LINK_KEY_EXCHANGE_POLL_RETRIES) * 2;
        let mut mac = MockMlme::new();
        mac.expect_transmit_data()
            .times(attempts)
            .returning(|_, _| Ok(()));
        mac.expect_poll_data()
            .times(attempts * polls_per_attempt)
            .returning(|_, _| Err(MacError::NoData));
        let (_guard, mut bdb) = make_bdb(mac);
        install_test_security_material(&mut bdb);

        let result = block_on(bdb.tc_link_key_exchange());

        assert!(matches!(result, Err(NetworkError::NoTransportKey)));
        assert_eq!(
            bdb.bdb_commissioning_status,
            BdbCommissioningStatus::TclkExFailure
        );
    }

    #[test]
    fn tc_link_key_exchange_treats_leave_as_terminal() {
        let poll: Result<Command, NetworkError> =
            Err(NetworkError::LeaveRequested { rejoin: true });

        let result = BaseDeviceBehavior::<MockMlme>::propagate_tc_terminal_poll_error(&poll);

        assert!(matches!(
            result,
            Err(NetworkError::LeaveRequested { rejoin: true })
        ));
    }

    #[test]
    fn tc_link_key_exchange_keeps_no_data_retryable() {
        let poll: Result<Command, NetworkError> = Err(NetworkError::MacError(MacError::NoData));

        assert!(BaseDeviceBehavior::<MockMlme>::propagate_tc_terminal_poll_error(&poll).is_ok());
    }

    // ------------------------------------------------------------------
    // Binding table tests
    // ------------------------------------------------------------------

    fn sample_binding() -> BindingEntry {
        BindingEntry {
            src_endpoint: 1,
            cluster_id: 0x0006,
            dst_short_addr: 0x0000,
            dst_endpoint: 1,
            profile_id: 0x0104,
        }
    }

    #[test]
    fn bind_adds_entry_to_table() {
        let mac = MockMlme::new();
        let (_guard, mut bdb) = make_bdb(mac);
        bdb.bind(sample_binding()).unwrap();
        assert_eq!(bdb.bindings().len(), 1);
        assert_eq!(bdb.bindings()[0], sample_binding());
    }

    #[test]
    fn bind_duplicate_is_idempotent() {
        let mac = MockMlme::new();
        let (_guard, mut bdb) = make_bdb(mac);
        bdb.bind(sample_binding()).unwrap();
        bdb.bind(sample_binding()).unwrap();
        assert_eq!(bdb.bindings().len(), 1);
    }

    #[test]
    fn unbind_removes_entry() {
        let mac = MockMlme::new();
        let (_guard, mut bdb) = make_bdb(mac);
        bdb.bind(sample_binding()).unwrap();
        bdb.unbind(&sample_binding());
        assert!(bdb.bindings().is_empty());
    }

    #[test]
    fn unbind_noop_when_not_found() {
        let mac = MockMlme::new();
        let (_guard, mut bdb) = make_bdb(mac);
        bdb.unbind(&sample_binding()); // no panic
        assert!(bdb.bindings().is_empty());
    }

    #[test]
    fn bind_returns_err_when_table_full() {
        let mac = MockMlme::new();
        let (_guard, mut bdb) = make_bdb(mac);
        for i in 0..MAX_BINDING_TABLE_ENTRIES as u8 {
            let entry = BindingEntry {
                src_endpoint: i,
                cluster_id: 0x0006,
                dst_short_addr: 0x0000,
                dst_endpoint: 1,
                profile_id: 0x0104,
            };
            bdb.bind(entry).unwrap();
        }
        // Table is full. Push a distinct entry (dst_short_addr differs from all above).
        let overflow = BindingEntry {
            src_endpoint: 0xFF,
            cluster_id: 0x0006,
            dst_short_addr: 0x9999,
            dst_endpoint: 2,
            profile_id: 0x0104,
        };
        assert!(bdb.bind(overflow).is_err());
    }

    // ------------------------------------------------------------------
    // ------------------------------------------------------------------
    // APS group table sync tests
    // ------------------------------------------------------------------

    use zigbee_cluster_library::common::GroupsServer;
    use zigbee_types::StorageVec as SV;

    struct GroupsDevice {
        groups: GroupsServer<8>,
    }

    static GROUPS_ENDPOINTS: &[EndpointDescriptor] = &[EndpointDescriptor {
        endpoint: 1,
        profile_id: 0x0104,
        device_id: 0x0100,
        device_version: 0,
        input_clusters: &[zigbee_cluster_library::types::ids::ClusterId::new(0x0004)],
        output_clusters: &[],
    }];

    impl Device for GroupsDevice {
        fn endpoints(&self) -> &'static [EndpointDescriptor] {
            GROUPS_ENDPOINTS
        }

        fn visit_servers<V: DeviceServerVisitor>(&mut self, visitor: &mut V) {
            visitor.visit(
                ServerMeta {
                    endpoint: 1,
                    profile_id: 0x0104,
                    cluster: ClusterKey::new(GroupsServer::<8>::CLUSTER_ID, None),
                },
                &mut self.groups,
            );
        }
    }

    // NWK+APS+ZCL: AddGroup(gid=0x0001) → endpoint 1, cluster 0x0004
    const IN_ADD_GROUP: &[u8] = &[
        0x08, 0x00, 0x78, 0x56, 0x34, 0x12, 0x1e, 0xab, // NWK
        0x00, 0x01, 0x04, 0x00, 0x04, 0x01, 0x02, 0x57, // APS: dst_ep=1, cluster=0x0004
        0x01, 0x55, 0x00, 0x01, 0x00, 0x00, // ZCL: cluster-spec, AddGroup(0x0001)
    ];

    // NWK+APS+ZCL: RemoveGroup(gid=0x0001)
    const IN_REMOVE_GROUP: &[u8] = &[
        0x08, 0x00, 0x78, 0x56, 0x34, 0x12, 0x1e, 0xac, // NWK
        0x00, 0x01, 0x04, 0x00, 0x04, 0x01, 0x02, 0x58, // APS
        0x01, 0x56, 0x03, 0x01, 0x00, // ZCL: RemoveGroup(0x0001)
    ];

    // NWK+APS+ZCL: RemoveAllGroups
    const IN_REMOVE_ALL_GROUPS: &[u8] = &[
        0x08, 0x00, 0x78, 0x56, 0x34, 0x12, 0x1e, 0xad, // NWK
        0x00, 0x01, 0x04, 0x00, 0x04, 0x01, 0x02, 0x59, // APS
        0x01, 0x57, 0x04, // ZCL: RemoveAllGroups
    ];

    fn reset_aps_group_table() {
        aib::get_ref().set_group_table(SV::new());
    }

    #[test]
    fn add_aps_group_inserts_entry() {
        let mac = MockMlme::new();
        let (_guard, bdb) = make_bdb(mac);
        reset_aps_group_table();
        bdb.add_aps_group(0x0001, 1);
        let table = aib::get_ref().group_table();
        assert_eq!(table.len(), 1);
        assert_eq!(table[0].group_address, 0x0001);
        assert_eq!(table[0].endpoint, 1);
    }

    #[test]
    fn add_aps_group_is_idempotent() {
        let mac = MockMlme::new();
        let (_guard, bdb) = make_bdb(mac);
        reset_aps_group_table();
        bdb.add_aps_group(0x0001, 1);
        bdb.add_aps_group(0x0001, 1);
        assert_eq!(aib::get_ref().group_table().len(), 1);
    }

    #[test]
    fn remove_aps_group_removes_entry() {
        let mac = MockMlme::new();
        let (_guard, bdb) = make_bdb(mac);
        reset_aps_group_table();
        bdb.add_aps_group(0x0001, 1);
        bdb.add_aps_group(0x0002, 1);
        bdb.remove_aps_group(0x0001, 1);
        let table = aib::get_ref().group_table();
        assert_eq!(table.len(), 1);
        assert_eq!(table[0].group_address, 0x0002);
    }

    #[test]
    fn remove_all_aps_groups_clears_endpoint() {
        let mac = MockMlme::new();
        let (_guard, bdb) = make_bdb(mac);
        reset_aps_group_table();
        bdb.add_aps_group(0x0001, 1);
        bdb.add_aps_group(0x0002, 1);
        bdb.add_aps_group(0x0003, 2); // different endpoint — should survive
        bdb.remove_all_aps_groups(1);
        let table = aib::get_ref().group_table();
        assert_eq!(table.len(), 1);
        assert_eq!(table[0].group_address, 0x0003);
        assert_eq!(table[0].endpoint, 2);
    }

    #[test]
    fn dispatch_add_group_syncs_aps_group_table() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_ADD_GROUP);
        mac.expect_transmit_data().returning(|_, _| Ok(())); // accept AddGroupResponse
        let (_guard, mut bdb) = make_bdb(mac);
        reset_aps_group_table();
        let mut app = GroupsDevice {
            groups: GroupsServer::new(0x80),
        };

        block_on(bdb.poll_once(&mut app, 0)).unwrap();

        let table = aib::get_ref().group_table();
        assert_eq!(table.len(), 1);
        assert_eq!(table[0].group_address, 0x0001);
        assert_eq!(table[0].endpoint, 1);
    }

    #[test]
    fn dispatch_remove_group_clears_aps_group_table_entry() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_REMOVE_GROUP);
        mac.expect_transmit_data().returning(|_, _| Ok(()));
        let (_guard, mut bdb) = make_bdb(mac);
        reset_aps_group_table();
        bdb.add_aps_group(0x0001, 1);
        let mut app = GroupsDevice {
            groups: GroupsServer::new(0x80),
        };
        // pre-populate GroupsServer so RemoveGroup finds the entry
        app.groups
            .handle_command(
                zigbee_cluster_library::types::ids::CommandId::new(0x00),
                &[0x01, 0x00, 0x00],
                zigbee_cluster_library::cluster_server::DispatchContext::unicast(0, None),
                &mut [0u8; 16],
            )
            .unwrap();

        block_on(bdb.poll_once(&mut app, 0)).unwrap();

        assert_eq!(aib::get_ref().group_table().len(), 0);
    }

    #[test]
    fn dispatch_remove_all_groups_clears_aps_group_table() {
        let mut mac = MockMlme::new();
        expect_poll_data(&mut mac, IN_REMOVE_ALL_GROUPS);
        mac.expect_transmit_data().returning(|_, _| Ok(()));
        let (_guard, mut bdb) = make_bdb(mac);
        reset_aps_group_table();
        bdb.add_aps_group(0x0001, 1);
        bdb.add_aps_group(0x0002, 1);
        let mut app = GroupsDevice {
            groups: GroupsServer::new(0x80),
        };

        block_on(bdb.poll_once(&mut app, 0)).unwrap();

        assert_eq!(aib::get_ref().group_table().len(), 0);
    }

    // ------------------------------------------------------------------
    // poll_report_once with Bound destination
    // ------------------------------------------------------------------

    use zigbee_cluster_library::cluster_server::ReportReady;
    use zigbee_cluster_library::frame::Status;
    use zigbee_cluster_library::lighting::on_off::OnOffServer;

    struct OnOffDevice {
        on_off: OnOffServer,
    }

    static ON_OFF_ENDPOINTS: &[EndpointDescriptor] = &[EndpointDescriptor {
        endpoint: 1,
        profile_id: 0x0104,
        device_id: 0x0100,
        device_version: 0,
        input_clusters: &[zigbee_cluster_library::types::ids::ClusterId::new(0x0006)],
        output_clusters: &[],
    }];

    impl Device for OnOffDevice {
        fn endpoints(&self) -> &'static [EndpointDescriptor] {
            ON_OFF_ENDPOINTS
        }

        fn visit_servers<V: DeviceServerVisitor>(&mut self, visitor: &mut V) {
            visitor.visit(
                ServerMeta {
                    endpoint: 1,
                    profile_id: 0x0104,
                    cluster: ClusterKey::new(OnOffServer::CLUSTER_ID, None),
                },
                &mut self.on_off,
            );
        }
    }

    #[test]
    fn poll_report_once_unicast_uses_peer_endpoint_as_destination_and_local_endpoint_as_source() {
        const OUT_ON_OFF_REPORT: &[u8] = &[
            0x00, 0x02, 0x06, 0x00, 0x04, 0x01, 0x01, 0x01, 0x18, 0x00, 0x0a, 0x00, 0x00, 0x10,
            0x01,
        ];

        let mut mac = MockMlme::new();
        mac.expect_transmit_data()
            .withf(|dest, payload| {
                *dest == MacAddress::Short(PanId(0xabcd), MacShortAddress(0x0000))
                    && aps_payload_from_nwk(payload) == OUT_ON_OFF_REPORT
            })
            .returning(|_, _| Ok(()));
        let (_guard, mut bdb) = make_bdb(mac);

        let mut app = OnOffDevice {
            on_off: OnOffServer::new(false),
        };
        let record = zigbee_cluster_library::cluster_server::ConfigureReportingRecord {
            direction: 0,
            attr_id: AttributeId::new(0x0000),
            attr_type: TypeId::Boolean.as_u8(),
            min_interval: 0,
            max_interval: 60,
            reportable_change: &[],
            timeout_period: 0,
        };
        let source = zigbee_cluster_library::cluster_server::ApsPeer {
            short_addr: 0x1234,
            endpoint: 2,
        };
        assert_eq!(
            app.on_off
                .configure_reporting(record, DispatchContext::unicast(0, Some(source))),
            Status::Success
        );
        app.on_off
            .handle_command(
                zigbee_cluster_library::types::ids::CommandId::new(0x01),
                &[],
                DispatchContext::unicast(0, None),
                &mut [],
            )
            .unwrap();

        let result = block_on(bdb.poll_report_once(&mut app, 0));

        assert!(result.unwrap().is_some());
    }

    #[test]
    fn poll_report_once_bound_no_binding_returns_failed_and_drops() {
        let mac = MockMlme::new();
        let (_guard, mut bdb) = make_bdb(mac);

        let mut app = OnOffDevice {
            on_off: OnOffServer::new(false),
        };
        // Configure bound reporting (min=0, max=60s).
        app.on_off.configure_bound_reporting(0, 60, 0);
        // Trigger an update so a report is pending.
        app.on_off
            .handle_command(
                zigbee_cluster_library::types::ids::CommandId::new(0x01),
                &[],
                zigbee_cluster_library::cluster_server::DispatchContext::unicast(0, None),
                &mut [],
            )
            .unwrap();

        // No binding registered → poll_report_once returns Ok(Some(..)) but delivers as
        // Failed.
        let result = block_on(bdb.poll_report_once(&mut app, 0));
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn poll_report_once_bound_with_binding_sends_to_peer() {
        const OUT_BOUND_ON_OFF_REPORT: &[u8] = &[
            0x00, 0x01, 0x06, 0x00, 0x04, 0x01, 0x01, 0x01, 0x18, 0x00, 0x0a, 0x00, 0x00, 0x10,
            0x01,
        ];

        let mut mac = MockMlme::new();
        mac.expect_transmit_data()
            .withf(|dest, payload| {
                *dest == MacAddress::Short(PanId(0xabcd), MacShortAddress(0x0000))
                    && aps_payload_from_nwk(payload) == OUT_BOUND_ON_OFF_REPORT
            })
            .returning(|_, _| Ok(()));
        let (_guard, mut bdb) = make_bdb(mac);

        bdb.bind(BindingEntry {
            src_endpoint: 1,
            cluster_id: 0x0006,
            dst_short_addr: 0x0000,
            dst_endpoint: 1,
            profile_id: 0x0104,
        })
        .unwrap();

        let mut app = OnOffDevice {
            on_off: OnOffServer::new(false),
        };
        app.on_off.configure_bound_reporting(0, 60, 0);
        app.on_off
            .handle_command(
                zigbee_cluster_library::types::ids::CommandId::new(0x01),
                &[],
                zigbee_cluster_library::cluster_server::DispatchContext::unicast(0, None),
                &mut [],
            )
            .unwrap();

        let result = block_on(bdb.poll_report_once(&mut app, 0));
        assert!(result.unwrap().is_some());
    }
}
