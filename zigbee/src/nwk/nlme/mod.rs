//! Network Management Entity
//!
//! The NLME shall provide a management service to allow an application to
//! interact with the stack.
//!
//! it provides:
//! * configuring a new device
//! * starting a network
//! * joining, rejoining and leaving a network
//! * addressing
//! * neighbor discovery
//! * route discovery
//! * reception control
//! * routing

use byte::BytesExt;
use byte::TryRead;
use management::LeaveSource;
use management::NlmeEdScanConfirm;
use management::NlmeEdScanRequest;
use management::NlmeJoinConfirm;
use management::NlmeJoinRequest;
use management::NlmeJoinStatus;
use management::NlmeLeaveConfirm;
use management::NlmeLeaveRequest;
use management::NlmeLeaveStatus;
use management::NlmeNetworkDiscoveryConfirm;
use management::NlmeNetworkFormationConfirm;
use management::NlmeNetworkFormationRequest;
use management::NlmePermitJoiningConfirm;
use management::NlmePermitJoiningRequest;
use management::NlmeRejoinRequest;
use management::NlmeResetConfirm;
use management::NlmeResetRequest;
use management::NlmeResetStatus;
use management::NlmeStartRouterConfirm;
use management::NlmeStartRouterRequest;
use management::NlmeSyncConfirm;
use management::NlmeSyncRequest;
use management::NlmeSyncStatus;
use management::RejoinNetwork;
use management::RejoinScan;
use thiserror::Error;
use zigbee_mac::Address;
use zigbee_mac::AssociationStatus;
use zigbee_mac::ExtendedAddress;
use zigbee_mac::MacShortAddress;
use zigbee_mac::PanId;
use zigbee_mac::mlme::MacError;
use zigbee_mac::mlme::Mlme;
use zigbee_mac::mlme::MlmeSyncRequest;
use zigbee_mac::mlme::ScanType;
use zigbee_types::IeeeAddress;
use zigbee_types::ShortAddress;
use zigbee_types::StorageVec;

use crate::aps::aib;
use crate::nwk::frame::CommandFrame as NwkCommandFrame;
use crate::nwk::frame::DataFrame as NwkDataFrame;
use crate::nwk::frame::Frame as NwkFrame;
use crate::nwk::frame::command::Command as NwkCommand;
use crate::nwk::frame::command::leave::CommandOptions as LeaveCommandOptions;
use crate::nwk::frame::command::leave::Leave as NwkLeave;
use crate::nwk::frame::command::rejoin_request::CapabilityInformation as RejoinCapabilityInformation;
use crate::nwk::frame::command::rejoin_request::RejoinRequest as NwkRejoinRequestFrame;
use crate::nwk::frame::command::rejoin_response::RejoinResponse;
use crate::nwk::frame::frame_control::DiscoverRoute;
use crate::nwk::frame::frame_control::FrameControl as NwkFrameControl;
use crate::nwk::frame::frame_control::FrameType as NwkFrameType;
use crate::nwk::frame::header::Header as NwkHeader;
use crate::nwk::nib::CapabilityInformation;
use crate::nwk::nib::DeviceType;
use crate::nwk::nib::MAX_PARENT_LINK_COST;
use crate::nwk::nib::NWK_COORDINATOR_ADDRESS;
use crate::nwk::nib::Nib;
use crate::nwk::nib::NibStorage;
use crate::nwk::nib::NwkNeighbor;
use crate::nwk::nib::link_cost_from_lqi;
use crate::nwk::nib::relationship;
use crate::security::SecurityContext;

/// Network management entity
pub mod management;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("mac error: {0}")]
    MacError(#[from] MacError),
    #[error("not joined to a network")]
    NotJoined,
    #[error("no transport key received from coordinator")]
    NoTransportKey,
    #[error("joined network has no security material installed")]
    MissingSecurityMaterial,
    #[error("frame parse error")]
    ParseError,
    #[error("invalid frame")]
    InvalidFrame,
    #[error("leave requested by network (rejoin={rejoin})")]
    LeaveRequested { rejoin: bool },
    #[error("security error: {0}")]
    SecurityError(#[from] crate::security::SecurityError),
}

impl From<byte::Error> for NetworkError {
    fn from(_: byte::Error) -> Self {
        Self::ParseError
    }
}

struct RejoinCandidateInfo {
    nwk_addr: ShortAddress,
    mac_addr: Address,
    pan_id: u16,
    channel: u8,
    update_id: u8,
}

/// Network Layer Management Entity (§3.2.2).
///
/// Provides the management service access point (NLME-SAP) that allows
/// the next higher layer to interact with the NWK layer: network
/// discovery, formation, joining, rejoining, data transmission, etc.
pub struct Nlme<M> {
    mac: M,
    nwk_seq: u8,
    buf: [u8; 256],
}

macro_rules! fail {
    ($status:expr, $nib:expr) => {
        return NlmeJoinConfirm {
            status: $status,
            network_address: ShortAddress($nib.network_address()),
            extended_pan_id: IeeeAddress($nib.extended_panid()),
            channel: $nib.logical_channel(),
            enhanced_beacon_type: false,
            mac_interface_index: 0,
        }
    };
    ($status:expr) => {
        return NlmeJoinConfirm {
            status: $status,
            network_address: ShortAddress(0xffff),
            extended_pan_id: IeeeAddress(0u64),
            channel: 0,
            enhanced_beacon_type: false,
            mac_interface_index: 0u8,
        }
    };
}

impl<M> Nlme<M>
where
    M: Mlme,
{
    pub fn new(mac: M) -> Self {
        Self {
            mac,
            nwk_seq: 0,
            buf: [0u8; 256],
        }
    }

    fn next_nwk_seq(&mut self) -> u8 {
        self.nwk_seq = self.nwk_seq.wrapping_add(1);
        self.nwk_seq
    }


    fn build_nwk_header<'h>(
        &mut self,
        destination: ShortAddress,
        frame_type: NwkFrameType,
        secure: bool,
    ) -> NwkHeader<'h> {
        let source = ShortAddress(self.nib().network_address());
        let frame_control = NwkFrameControl(0)
            .set_frame_type(frame_type)
            .set_protocol_version(2)
            .set_discover_route(DiscoverRoute::Suppress)
            .set_security_flag(secure);
        let seq = self.next_nwk_seq();
        NwkHeader {
            frame_control,
            destination,
            source,
            radius: 30,
            sequence_number: seq,
            destination_ieee: None,
            source_ieee: None,
            multicast_control: None,
            source_route_subframe: None,
        }
    }

    /// Build a NWK data frame and write it into `self.buf`.
    ///
    /// When `secure` is true the frame is encrypted with the active
    /// network key. Returns the total frame length.
    fn build_nwk_data_frame(
        &mut self,
        destination: ShortAddress,
        secure: bool,
        payload: &[u8],
    ) -> Result<usize, NetworkError> {
        let header = self.build_nwk_header(destination, NwkFrameType::Data, secure);
        if secure {
            let nwk_frame = NwkFrame::Data(NwkDataFrame {
                header,
                payload,
                payload_offset: 0,
            });
            let cx = SecurityContext::get();
            let len = cx.encrypt_nwk_frame_in_place(nwk_frame, &mut self.buf)?;
            Ok(len)
        } else {
            let offset = &mut 0;
            self.buf.write_with(offset, header, ())?;
            let hdr_len = *offset;
            if payload.len() > self.buf.len() - hdr_len {
                return Err(NetworkError::InvalidFrame);
            }
            self.buf[hdr_len..hdr_len + payload.len()].copy_from_slice(payload);
            Ok(hdr_len + payload.len())
        }
    }

    /// Returns a reference to the global NIB singleton.
    pub fn nib(&self) -> &'static Nib<NibStorage> {
        crate::nwk::nib::get_ref()
    }

    /// Return the most recent `update_id` across `neighbors`, treating it as a
    /// modular counter (§3.6.1.4.1.1).  Returns `None` when the iterator is empty.
    fn best_update_id<'a>(mut neighbors: impl Iterator<Item = &'a NwkNeighbor>) -> Option<u8> {
        let first = neighbors.next()?;
        let best = neighbors.fold(first.update_id, |best, n| {
            if n.update_id.wrapping_sub(best).cast_signed() > 0 {
                n.update_id
            } else {
                best
            }
        });
        Some(best)
    }

    fn select_parent_candidates(
        &self,
        extended_pan_id: IeeeAddress,
        join_as_router: bool,
    ) -> heapless::Vec<usize, 16> {
        let table = self.nib().neighbor_table();
        let stack_profile = self.nib().stack_profile();

        // §3.6.1.4.1.1: treat update_id as a modular counter; keep only
        // neighbors whose update_id matches the most recent seen for this EPID.
        let Some(best_update_id) = Self::best_update_id(
            table.iter().filter(|n| n.extended_pan_id == extended_pan_id),
        ) else {
            return heapless::Vec::new();
        };

        // Collect indices of eligible parents.
        let mut candidates: heapless::Vec<usize, 16> = table
            .iter()
            .enumerate()
            .filter(|(_, n)| {
                let ok = n.extended_pan_id == extended_pan_id
                    && n.permit_joining
                    && if join_as_router {
                        n.router_capacity
                    } else {
                        n.end_device_capacity
                    }
                    && link_cost_from_lqi(n.lqi) <= MAX_PARENT_LINK_COST
                    && n.potential_parent == 1
                    && n.update_id == best_update_id;
                if !ok && n.extended_pan_id == extended_pan_id {
                    log::debug!(
                        "[NWK] parent candidate rejected: addr={:#06x} \
                         permit_joining={} router_cap={} end_dev_cap={} \
                         lqi={} link_cost={} potential_parent={} \
                         update_id={} (best={})",
                        n.network_address.0,
                        n.permit_joining,
                        n.router_capacity,
                        n.end_device_capacity,
                        n.lqi,
                        link_cost_from_lqi(n.lqi),
                        n.potential_parent,
                        n.update_id,
                        best_update_id,
                    );
                }
                ok
            })
            .map(|(i, _)| i)
            .collect();

        // When nwkStackProfile == 1 prefer minimum depth (§3.6.1.4.1.1).
        if stack_profile == 1 {
            candidates.sort_unstable_by_key(|&i| table[i].depth);
        }

        candidates
    }

    /// Select candidate parents for secured NWK rejoin after discovery.
    ///
    /// Rejoin must stay on the current network identity: same EPID, PAN ID,
    /// and newest update id observed for that PAN. Prefer non-current parents
    /// when discovery found one, then best link cost / LQI.
    fn select_rejoin_candidates(
        &self,
        extended_pan_id: IeeeAddress,
        join_as_router: bool,
    ) -> heapless::Vec<usize, 16> {
        let table = self.nib().neighbor_table();
        let pan_id = self.nib().panid();
        let current_parent = table
            .iter()
            .find(|n| n.relationship == relationship::PARENT)
            .map(|n| n.network_address);

        let Some(best_update_id) = Self::best_update_id(
            table
                .iter()
                .filter(|n| n.extended_pan_id == extended_pan_id && n.pan_id == pan_id),
        ) else {
            return heapless::Vec::new();
        };

        let mut candidates: heapless::Vec<usize, 16> = table
            .iter()
            .enumerate()
            .filter(|(_, n)| {
                let coordinator = n.network_address.0 == NWK_COORDINATOR_ADDRESS;
                n.extended_pan_id == extended_pan_id
                    && n.pan_id == pan_id
                    && n.update_id == best_update_id
                    && n.potential_parent == 1
                    && if join_as_router {
                        coordinator || n.router_capacity
                    } else {
                        coordinator || n.end_device_capacity
                    }
                    && link_cost_from_lqi(n.lqi) <= MAX_PARENT_LINK_COST
            })
            .map(|(i, _)| i)
            .collect();

        let has_alternative = candidates.iter().any(|&i| {
            current_parent.is_none_or(|parent_addr| table[i].network_address != parent_addr)
        });

        candidates.sort_unstable_by_key(|&i| {
            let is_current_parent =
                current_parent.is_some_and(|parent_addr| table[i].network_address == parent_addr);
            (
                has_alternative && is_current_parent,
                link_cost_from_lqi(table[i].lqi),
                core::cmp::Reverse(table[i].lqi),
                table[i].depth,
            )
        });

        candidates
    }

    fn rejoin_candidate_address(&self, candidate_idx: usize) -> RejoinCandidateInfo {
        let nib = self.nib();
        let table = nib.neighbor_table();
        let candidate = &table[candidate_idx];
        let is_current_parent = candidate.relationship == relationship::PARENT;
        let pan_id = if is_current_parent {
            nib.panid()
        } else {
            candidate.pan_id
        };
        let logical_channel = if is_current_parent {
            nib.logical_channel()
        } else {
            candidate.logical_channel
        };
        let update_id = if is_current_parent {
            nib.update_id()
        } else {
            candidate.update_id
        };
        let mac_addr = if candidate.network_address.0 <= 0xfff7 {
            Address::Short(PanId(pan_id), MacShortAddress(candidate.network_address.0))
        } else {
            Address::Extended(PanId(pan_id), ExtendedAddress(candidate.extended_address.0))
        };
        RejoinCandidateInfo {
            nwk_addr: candidate.network_address,
            mac_addr,
            pan_id,
            channel: logical_channel,
            update_id,
        }
    }

    /// Build the IEEE 802.15.4 MAC `CapabilityInformation` from the NWK
    /// layer `CapabilityInformation` bitmap (Table 3-62).
    fn build_mac_capabilities(cap: &CapabilityInformation) -> zigbee_mac::CapabilityInformation {
        zigbee_mac::CapabilityInformation {
            // Bit 1 — Device type: 1 if joining as router (FFD)
            full_function_device: cap.device_type(),
            // Bit 2 — Power source
            mains_power: cap.power_source(),
            // Bit 3 — Receiver on when idle
            idle_receive: cap.receiver_on_when_idle(),
            // Bit 6 — Security capability
            frame_protection: cap.security_capability(),
            // Bit 7 — Allocate address
            allocate_address: cap.allocate_address(),
        }
    }

    /// Find the parent's MAC address from the neighbor table.
    fn parent_address(&self) -> Result<Address, NetworkError> {
        let table = self.nib().neighbor_table();
        let parent = table
            .iter()
            .find(|n| n.relationship == relationship::PARENT)
            .ok_or(NetworkError::NotJoined)?;
        let pan_id = PanId(self.nib().panid());
        if parent.network_address.0 <= 0xfff7 {
            Ok(Address::Short(
                pan_id,
                MacShortAddress(parent.network_address.0),
            ))
        } else {
            Ok(Address::Extended(
                pan_id,
                ExtendedAddress(parent.extended_address.0),
            ))
        }
    }

    async fn poll_nwk_data_bytes(
        &mut self,
        buf: &mut [u8],
        retries: u8,
    ) -> Result<usize, NetworkError> {
        let coord_addr = self.parent_address()?;
        for _ in 0..retries {
            match self.mac.poll_data(coord_addr, buf).await {
                Ok((len, _lqi)) => return Ok(len),
                Err(MacError::NoData) => (),
                Err(e) => return Err(e.into()),
            }
        }

        Err(NetworkError::MacError(MacError::NoData))
    }

    /// 3.2.2.3
    pub async fn network_discovery(
        &mut self,
        channels: core::ops::Range<u8>,
        duration: u8,
    ) -> Result<NlmeNetworkDiscoveryConfirm, NetworkError> {
        let scan_result = self
            .mac
            .scan_network(ScanType::Active, channels, duration)
            .await?;

        // Populate the neighbor table with mandatory fields (Table 3-63)
        // and optional discovery-time fields (Table 3-64).
        let mut neighbor_table = self.nib().neighbor_table();
        for pd in &scan_result.pan_descriptor {
            let (network_address, extended_address) = match pd.coord_address {
                Address::Short(_pan_id, short_address) => {
                    (ShortAddress(short_address.0), IeeeAddress(0))
                }
                Address::Extended(_, ieee) => (ShortAddress(0xffff), IeeeAddress(ieee.0)),
            };
            let is_coordinator = pd.superframe_spec.pan_coordinator;
            log::debug!(
                "[NWK] beacon: ch={} addr={:?} pan={:#06x} \
                 assoc_permit={} router_cap={} end_dev_cap={} \
                 potential_parent={} lqi={} link_cost={} update_id={}",
                pd.channel,
                pd.coord_address,
                pd.coord_pan_id.0,
                pd.superframe_spec.association_permit,
                pd.zigbee_beacon.stack_profile.router_capacity(),
                pd.zigbee_beacon.stack_profile.end_device_capacity(),
                u8::from(pd.zigbee_beacon.stack_profile.router_capacity() || is_coordinator),
                pd.link_quality,
                link_cost_from_lqi(pd.link_quality),
                pd.zigbee_beacon.update_id,
            );
            let neighbor = NwkNeighbor {
                extended_address,
                network_address,
                device_type: if is_coordinator {
                    DeviceType::Coordinator
                } else {
                    DeviceType::Router
                },
                rx_on_when_idle: is_coordinator || pd.zigbee_beacon.stack_profile.router_capacity(),
                end_device_configuration: 0,
                relationship: relationship::NONE,
                transmit_failure: 0,
                lqi: pd.link_quality,
                outgoing_cost: 0,
                age: 0,
                keepalive_received: false,
                // Table 3-64: optional discovery-time fields
                extended_pan_id: pd.zigbee_beacon.extended_pan_id,
                logical_channel: pd.channel,
                depth: pd.zigbee_beacon.stack_profile.device_depth(),
                permit_joining: pd.superframe_spec.association_permit,
                // end devices cannot be parents (Table 3-64)
                potential_parent: u8::from(
                    pd.zigbee_beacon.stack_profile.router_capacity() || is_coordinator,
                ),
                router_capacity: pd.zigbee_beacon.stack_profile.router_capacity(),
                end_device_capacity: pd.zigbee_beacon.stack_profile.end_device_capacity(),
                update_id: pd.zigbee_beacon.update_id,
                pan_id: pd.coord_pan_id.0,
            };

            if let Some(existing) = neighbor_table.iter_mut().find(|n| {
                n.extended_pan_id == neighbor.extended_pan_id
                    && n.pan_id == neighbor.pan_id
                    && n.network_address == neighbor.network_address
                    && n.extended_address == neighbor.extended_address
            }) {
                let relationship = existing.relationship;
                *existing = neighbor;
                existing.relationship = relationship;
            } else {
                neighbor_table
                    .push(neighbor)
                    .map_err(|_| NetworkError::InvalidFrame)?;
            }
        }

        self.nib().set_neighbor_table(neighbor_table);

        // Build network descriptors for the confirm primitive.
        let network_descriptors = scan_result
            .pan_descriptor
            .into_iter()
            .map(From::from)
            .collect();

        Ok(NlmeNetworkDiscoveryConfirm {
            network_descriptor: network_descriptors,
        })
    }

    /// 3.2.2.5
    pub async fn network_formation(
        &self,
        _request: NlmeNetworkFormationRequest,
    ) -> NlmeNetworkFormationConfirm {
        todo!()
    }

    /// 3.2.2.7
    // figure 3-39
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)]
    pub async fn permit_joining(
        &self,
        _request: NlmePermitJoiningRequest,
    ) -> NlmePermitJoiningConfirm {
        NlmePermitJoiningConfirm {
            status: NlmeJoinStatus::InvalidRequest,
        }
    }

    /// 3.2.2.9
    pub async fn start_router(&self, _request: NlmeStartRouterRequest) -> NlmeStartRouterConfirm {
        todo!()
    }

    /// 3.2.2.11 — ED scan. Not supported by ESP MLME; always returns MacError.
    pub fn ed_scan(&self, request: &NlmeEdScanRequest) -> NlmeEdScanConfirm {
        let _ = request;
        NlmeEdScanConfirm {
            status: NlmeJoinStatus::MacError,
            scanned_channels: 0..0,
            energy_detect_list: heapless::Vec::new(),
        }
    }

    /// NLME-SYNC.request (§3.2.2.26) — tune radio to parent channel/PAN.
    ///
    /// Reads channel and PAN from the NIB; returns `NoSynchronization` when no
    /// parent entry exists in the neighbor table.
    pub fn sync(&mut self, request: NlmeSyncRequest) -> NlmeSyncConfirm {
        let nib = self.nib();
        let parent_entry = nib
            .neighbor_table()
            .iter()
            .find(|n| n.relationship == relationship::PARENT)
            .map(|n| (n.pan_id, n.logical_channel));

        let Some((pan_id, channel)) = parent_entry else {
            return NlmeSyncConfirm {
                status: NlmeSyncStatus::NoSynchronization,
            };
        };

        let mac_request = MlmeSyncRequest {
            logical_channel: channel,
            pan_id: ShortAddress(pan_id),
            track_beacon: request.track_beacon,
        };

        match self.mac.sync(mac_request) {
            Ok(()) => NlmeSyncConfirm {
                status: NlmeSyncStatus::Success,
            },
            Err(_) => NlmeSyncConfirm {
                status: NlmeSyncStatus::InvalidRequest,
            },
        }
    }

    /// NLME-RESET.request (§3.2.2.21).
    ///
    /// When `warm_start` is false (cold reset), clears all NWK state.
    /// When `warm_start` is true, only transient state is cleared.
    /// Always resets the MAC via MLME-RESET.
    pub fn reset(&mut self, request: &NlmeResetRequest) -> NlmeResetConfirm {
        // Always reset MAC first.
        let set_default_pib = !request.warm_start;
        if self.mac.reset(set_default_pib).is_err() {
            return NlmeResetConfirm {
                status: NlmeResetStatus::MacError,
            };
        }
        if !request.warm_start {
            self.clear_network_state_for_permanent_leave();
        }
        NlmeResetConfirm {
            status: NlmeResetStatus::Success,
        }
    }

    /// 3.2.2.13
    ///
    /// When `rejoin_network == NwkRejoin` this delegates to [`Self::rejoin`]
    /// with `scan = RejoinScan::SameChannel`.  Callers that need a channel-scanning
    /// rejoin must call `rejoin()` directly with the desired `RejoinScan::Channels`.
    pub async fn join(&mut self, request: NlmeJoinRequest) -> NlmeJoinConfirm {
        if request.rejoin_network == RejoinNetwork::NwkRejoin {
            return self
                .rejoin(NlmeRejoinRequest {
                    extended_pan_id: request.extended_pan_id,
                    capability_information: request.capability_information,
                    secure: request.security_enabled,
                    scan: RejoinScan::SameChannel,
                })
                .await;
        }

        // --- Validate the request (§3.2.2.13.3) ---

        // Orphan (0x01) and channel change (0x03) are not yet implemented.
        if request.rejoin_network != RejoinNetwork::Association {
            fail!(NlmeJoinStatus::InvalidRequest);
        }

        // A device already joined must not re-associate (§3.6.1.4.1.1).
        if self.nib().network_address() != 0xffff {
            fail!(NlmeJoinStatus::InvalidRequest);
        }

        // --- Parent selection (§3.6.1.4.1.1) ---

        // Whether joining as router or end device, set nwkParentInformation
        // to 0 before searching (spec requirement).
        self.nib().set_parent_information(0);

        let join_as_router = request.capability_information.device_type();

        let candidates = self.select_parent_candidates(request.extended_pan_id, join_as_router);

        if candidates.is_empty() {
            fail!(NlmeJoinStatus::NotPermitted);
        }

        // Build MAC CapabilityInformation from NWK CapabilityInformation
        // bitmap (Table 3-62).
        let mac_caps = Self::build_mac_capabilities(&request.capability_information);

        // Store in NIB (§3.6.1.4.1.1: "the capability information shall be
        // stored as the value of the nwkCapabilityInformation NIB attribute").
        self.nib()
            .set_capability_information(request.capability_information);

        // --- Try each candidate in order (§3.6.1.4.1.1) ---
        let mut last_status = NlmeJoinStatus::NotPermitted;

        for &candidate_idx in &candidates {
            // Read the neighbor info we need before the async call.
            let table = self.nib().neighbor_table();
            let neighbor = &table[candidate_idx];
            let channel = neighbor.logical_channel;
            let pan_id = PanId(neighbor.pan_id);
            let dest = if neighbor.network_address.0 <= 0xfff7 {
                Address::Short(pan_id, MacShortAddress(neighbor.network_address.0))
            } else {
                Address::Extended(pan_id, ExtendedAddress(neighbor.extended_address.0))
            };
            drop(table);

            // Issue MLME-ASSOCIATE.request to MAC sub-layer.
            match self.mac.associate(channel, dest, mac_caps).await {
                Ok(response) => match response.status {
                    AssociationStatus::Successful => {
                        // --- Success: update NIB (§3.6.1.4.1.1) ---
                        let assigned_addr = response.association_address;
                        self.nib().set_network_address(assigned_addr.0);
                        self.nib().set_extended_panid(request.extended_pan_id.0);
                        self.nib().set_panid(pan_id.0);

                        let parent = self.nib().neighbor_table()[candidate_idx].clone();
                        let parent_update_id = parent.update_id;
                        let parent_channel = parent.logical_channel;
                        self.nib().set_update_id(parent_update_id);
                        self.nib().set_logical_channel(parent_channel);

                        let mut parent = parent;
                        parent.relationship = relationship::PARENT;
                        parent.extended_pan_id = IeeeAddress(0);
                        parent.depth = 0;
                        parent.permit_joining = false;
                        parent.potential_parent = 0;
                        parent.router_capacity = false;
                        parent.end_device_capacity = false;
                        parent.update_id = 0;

                        let mut table = StorageVec::new();
                        if table.push(parent).is_err() {
                            fail!(NlmeJoinStatus::MacError);
                        }
                        self.nib().set_neighbor_table(table);

                        return NlmeJoinConfirm {
                            status: NlmeJoinStatus::Success,
                            network_address: assigned_addr,
                            extended_pan_id: request.extended_pan_id,
                            channel: parent_channel,
                            enhanced_beacon_type: false,
                            mac_interface_index: 0u8,
                        };
                    }
                    AssociationStatus::NetworkAtCapacity => {
                        // Mark this neighbor as not a potential parent so
                        // we don't retry (§3.6.1.4.1.1).
                        let mut table = self.nib().neighbor_table();
                        table[candidate_idx].potential_parent = 0;
                        self.nib().set_neighbor_table(table);
                        last_status = NlmeJoinStatus::PanAtCapacity;
                    }
                    AssociationStatus::AccessDenied => {
                        let mut table = self.nib().neighbor_table();
                        table[candidate_idx].potential_parent = 0;
                        self.nib().set_neighbor_table(table);
                        last_status = NlmeJoinStatus::PanAccessDenied;
                    }
                    _ => {
                        // Other status codes (FastAssociationSuccessful,
                        // HoppingSequenceOffsetDuplication, etc.) are
                        // treated as a generic MAC-level failure.
                        last_status = NlmeJoinStatus::MacError;
                    }
                },
                Err(_mac_err) => {
                    // MAC-level failure (no ack, radio error, etc.)
                    last_status = NlmeJoinStatus::MacError;
                }
            }
        }

        // All candidates exhausted — return the last error status.
        fail!(last_status)
    }

    /// Secured NWK rejoin (§3.6.1.4.3.3).
    ///
    /// `SameChannel` uses the current parent. `Channels` performs active
    /// discovery, keeps the existing network/security state, and tries
    /// eligible parents on the current EPID/PAN by best link.
    pub async fn rejoin(&mut self, request: NlmeRejoinRequest) -> NlmeJoinConfirm {
        let nib = self.nib();

        if !request.secure {
            // Insecure/TC rejoin is a future milestone (see TODO.md §Non-goals).
            fail!(NlmeJoinStatus::InvalidRequest, nib);
        }

        // Validate NWK state (§3.6.1.4.3.3 preconditions).
        if nib.security_material_set().is_empty() {
            fail!(NlmeJoinStatus::InvalidRequest, nib);
        }
        if nib.panid() == 0xffff {
            fail!(NlmeJoinStatus::InvalidRequest, nib);
        }
        if nib.extended_panid() == 0 || IeeeAddress(nib.extended_panid()) != request.extended_pan_id
        {
            fail!(NlmeJoinStatus::InvalidRequest, nib);
        }

        let scanned_rejoin = matches!(&request.scan, RejoinScan::Channels { .. });

        let candidate_indices: heapless::Vec<usize, 16> = match request.scan {
            RejoinScan::SameChannel => {
                if !(11..=26).contains(&nib.logical_channel()) {
                    fail!(NlmeJoinStatus::InvalidRequest, nib);
                }
                let table = nib.neighbor_table();
                let mut candidates = heapless::Vec::new();
                if let Some((idx, _)) = table
                    .iter()
                    .enumerate()
                    .find(|(_, n)| n.relationship == relationship::PARENT)
                    && candidates.push(idx).is_err()
                {
                    fail!(NlmeJoinStatus::MacError, nib);
                }
                candidates
            }
            RejoinScan::Channels { channels, duration } => {
                if let Err(e) = self.network_discovery(channels, duration).await {
                    log::warn!("[NWK] rejoin: discovery failed: {e:?}");
                    fail!(
                        match e {
                            NetworkError::MacError(MacError::NoBeacon) => {
                                NlmeJoinStatus::NoNetworks
                            }
                            _ => NlmeJoinStatus::MacError,
                        },
                        nib
                    );
                }
                self.select_rejoin_candidates(
                    request.extended_pan_id,
                    request.capability_information.device_type(),
                )
            }
        };

        if candidate_indices.is_empty() {
            fail!(NlmeJoinStatus::NotPermitted, nib);
        }

        let mut last_status = NlmeJoinStatus::NotPermitted;

        for &candidate_idx in &candidate_indices {
            match self
                .try_rejoin_candidate(
                    candidate_idx,
                    scanned_rejoin,
                    request.capability_information.0,
                )
                .await
            {
                Ok(confirm) => return confirm,
                Err(status) => last_status = status,
            }
        }

        fail!(last_status, nib)
    }

    async fn try_rejoin_candidate(
        &mut self,
        candidate_idx: usize,
        scanned_rejoin: bool,
        capability: u8,
    ) -> Result<NlmeJoinConfirm, NlmeJoinStatus> {
        let info = self.rejoin_candidate_address(candidate_idx);

        if scanned_rejoin
            && let Err(e) = self
                .mac
                .set_channel(info.channel, ShortAddress(info.pan_id))
        {
            log::error!(
                "[NWK] rejoin: failed to tune to ch={} pan={:#06x}: {e:?}",
                info.channel,
                info.pan_id,
            );
            return Err(NlmeJoinStatus::MacError);
        }

        let cmd = NwkCommand::RejoinRequest(NwkRejoinRequestFrame {
            capability_information: RejoinCapabilityInformation(capability),
        });

        if let Err(e) = self
            .send_nwk_command(info.nwk_addr, info.mac_addr, true, cmd)
            .await
        {
            log::error!(
                "[NWK] rejoin: failed to send RejoinRequest to {:?}: {e:?}",
                info.nwk_addr,
            );
            return Err(NlmeJoinStatus::MacError);
        }

        let response = match self
            .poll_for_rejoin_response_from(info.mac_addr, 15)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                log::warn!("[NWK] rejoin: no RejoinResponse from {:?}: {e:?}", info.nwk_addr);
                return Err(NlmeJoinStatus::NotPermitted);
            }
        };

        if response.status != 0 {
            log::warn!(
                "[NWK] rejoin: RejoinResponse from {:?} status={:#04x}",
                info.nwk_addr,
                response.status
            );
            return Err(NlmeJoinStatus::NotPermitted);
        }

        let nib = self.nib();
        log::info!(
            "[NWK] rejoin success: old_addr={:#06x} new_addr={:?} parent={:?}",
            nib.network_address(),
            response.network_address,
            info.nwk_addr,
        );
        nib.set_panid(info.pan_id);
        nib.set_logical_channel(info.channel);
        nib.set_update_id(info.update_id);
        nib.set_network_address(response.network_address.0);
        self.update_rejoin_parent(info.nwk_addr);

        Ok(NlmeJoinConfirm {
            status: NlmeJoinStatus::Success,
            network_address: response.network_address,
            extended_pan_id: IeeeAddress(nib.extended_panid()),
            channel: nib.logical_channel(),
            enhanced_beacon_type: false,
            mac_interface_index: 0,
        })
    }

    fn update_rejoin_parent(&self, parent_nwk_addr: ShortAddress) {
        let nib = self.nib();
        let mut table = nib.neighbor_table();
        let mut found = false;
        for parent in table.iter_mut() {
            if parent.network_address == parent_nwk_addr {
                parent.relationship = relationship::PARENT;
                parent.transmit_failure = 0;
                parent.age = 0;
                parent.keepalive_received = false;
                parent.extended_pan_id = IeeeAddress(nib.extended_panid());
                parent.logical_channel = nib.logical_channel();
                parent.update_id = nib.update_id();
                parent.pan_id = nib.panid();
                found = true;
            } else if parent.relationship == relationship::PARENT {
                parent.relationship = relationship::NONE;
            }
        }
        if found {
            nib.set_neighbor_table(table);
        }
    }

    /// Preserve the monotonic outgoing NWK frame counter even though the active
    /// network-key material is removed.
    fn clear_network_state_for_permanent_leave(&self) {
        let outgoing_frame_counter = self
            .nib()
            .security_material_set()
            .iter()
            .map(|m| m.outgoing_frame_counter)
            .max()
            .unwrap_or(0)
            .max(self.nib().outgoing_frame_counter());
        self.nib().set_network_address(0xffff);
        self.nib().set_panid(0xffff);
        self.nib().set_extended_panid(0);
        self.nib().set_neighbor_table(StorageVec::new());
        self.nib()
            .set_outgoing_frame_counter(outgoing_frame_counter);
        self.nib().set_security_material_set(StorageVec::new());
    }

    /// NLME-LEAVE.request (§3.6.9).
    ///
    /// When `source` is `Local`, transmits a NWK Leave command frame to the
    /// parent before cleaning up state. Network-initiated leaves skip the
    /// outbound frame (the network already sent the command). Best-effort
    /// transmit: failure is logged but does not prevent local state cleanup.
    pub async fn leave(&mut self, request: &NlmeLeaveRequest) -> NlmeLeaveConfirm {
        if matches!(request.source, LeaveSource::Local) {
            if let Ok(parent_mac_addr) = self.parent_address() {
                let parent_nwk_addr = self
                    .nib()
                    .neighbor_table()
                    .iter()
                    .find(|n| n.relationship == relationship::PARENT)
                    .map_or(ShortAddress(0x0000), |n| n.network_address);

                let cmd_options = LeaveCommandOptions(0)
                    .set_request(false)
                    .set_rejoin(request.rejoin)
                    .set_remove_children(request.remove_children);

                let cmd = NwkCommand::Leave(NwkLeave {
                    command_options: cmd_options,
                });

                if let Err(e) = self
                    .send_nwk_command(parent_nwk_addr, parent_mac_addr, true, cmd)
                    .await
                {
                    log::warn!("[NWK] leave: failed to send NWK Leave command: {e:?}");
                }
            } else {
                log::warn!("[NWK] leave: no parent found, skipping Leave frame transmit");
            }
        }

        if !request.rejoin {
            // When rejoining, preserve all crypto/PAN/channel state:
            // network_address, PAN, EPID, channel, network key, and frame
            // counters must remain intact to build and encrypt RejoinRequest
            // (§3.6.1.4.3.3).
            aib::get_ref().set_binding_table(StorageVec::new());
            self.clear_network_state_for_permanent_leave();
        }

        NlmeLeaveConfirm {
            status: NlmeLeaveStatus::Success,
            rejoin: request.rejoin,
        }
    }

    /// Build a secured or unsecured NWK command frame into `self.buf`.
    ///
    /// Returns the byte length of the encoded frame.
    fn build_nwk_command_frame(
        &mut self,
        destination: ShortAddress,
        secure: bool,
        command: NwkCommand<'_>,
    ) -> Result<usize, NetworkError> {
        let header = self.build_nwk_header(destination, NwkFrameType::NwkCommand, secure);
        if secure {
            let nwk_frame = NwkFrame::NwkCommand(NwkCommandFrame { header, command });
            let cx = SecurityContext::get();
            let len = cx.encrypt_nwk_frame_in_place(nwk_frame, &mut self.buf)?;
            Ok(len)
        } else {
            let offset = &mut 0usize;
            self.buf.write_with(offset, header, ())?;
            self.buf.write_with(offset, command, ())?;
            Ok(*offset)
        }
    }

    /// Build and transmit a NWK command frame.
    async fn send_nwk_command(
        &mut self,
        nwk_dest: ShortAddress,
        mac_dest: Address,
        secure: bool,
        command: NwkCommand<'_>,
    ) -> Result<(), NetworkError> {
        let total_len = self.build_nwk_command_frame(nwk_dest, secure, command)?;
        self.mac
            .transmit_data(mac_dest, &self.buf[..total_len])
            .await?;
        Ok(())
    }

    /// Poll for a `RejoinResponse` NWK command frame.
    ///
    /// Skips `NetworkStatus` frames (informational during rejoin) and retries
    /// up to `retries` times. Returns `NetworkError::NotJoined` on timeout.
    async fn poll_for_rejoin_response_from(
        &mut self,
        coord_addr: Address,
        retries: u8,
    ) -> Result<RejoinResponse, NetworkError> {
        let mut rx_buf = [0u8; 128];
        for _ in 0..retries {
            let len = match self.mac.poll_data(coord_addr, &mut rx_buf).await {
                Ok((len, _lqi)) => len,
                Err(MacError::NoData) => continue,
                Err(e) => return Err(e.into()),
            };
            let cx = SecurityContext::get();
            let frame = match cx.decrypt_nwk_frame_in_place(&mut rx_buf[..len]) {
                Ok(f) => f,
                Err(e) => {
                    log::debug!("[NWK] poll_for_rejoin_response: decrypt error: {e:?}");
                    continue;
                }
            };
            if let NwkFrame::NwkCommand(cmd_frame) = frame {
                if !cmd_frame.header.frame_control.security_flag() {
                    log::debug!(
                        "[NWK] poll_for_rejoin_response: ignoring unsecured RejoinResponse path frame"
                    );
                    continue;
                }
                match cmd_frame.command {
                    NwkCommand::RejoinResponse(resp) => return Ok(resp),
                    NwkCommand::NetworkStatus(_) => {
                        log::debug!("[NWK] poll_for_rejoin_response: ignoring NetworkStatus");
                    }
                    other => {
                        log::debug!("[NWK] poll_for_rejoin_response: ignoring command {other:?}");
                    }
                }
            }
        }
        Err(NetworkError::NotJoined)
    }

    /// Poll the coordinator for pending data, strip the NWK header, and
    /// return the APS payload (§3.6.2).
    pub async fn poll_nwk_data<'a>(
        &mut self,
        buf: &'a mut [u8],
        retries: u8,
    ) -> Result<NwkDataFrame<'a>, NetworkError> {
        let len = self.poll_nwk_data_bytes(buf, retries).await?;
        let cx = SecurityContext::get();
        let nwk_frame = cx.decrypt_nwk_frame_in_place(&mut buf[..len])?;

        match nwk_frame {
            NwkFrame::Data(data_frame) => Ok(data_frame),
            NwkFrame::NwkCommand(command_frame) => {
                log::debug!(
                    "[NWK] poll_nwk_data: skipping NWK command src={:?} dst={:?} command={:?}",
                    command_frame.header.source,
                    command_frame.header.destination,
                    command_frame.command
                );
                if let NwkCommand::Leave(leave) = &command_frame.command {
                    let local = ShortAddress(self.nib().network_address());
                    let destination = command_frame.header.destination;
                    if leave.command_options.request()
                        && (destination == local || (0xfffc..=0xffff).contains(&destination.0))
                    {
                        if !command_frame.header.frame_control.security_flag() {
                            log::warn!(
                                "[NWK] ignoring unsecured leave request: src={:?} dst={:?}",
                                command_frame.header.source,
                                destination,
                            );
                            return Err(NetworkError::InvalidFrame);
                        }

                        let rejoin = leave.command_options.rejoin();
                        log::warn!(
                            "[NWK] leave requested by network: src={:?} dst={:?} rejoin={} remove_children={}",
                            command_frame.header.source,
                            destination,
                            rejoin,
                            leave.command_options.remove_children()
                        );
                        // State cleanup is the caller's responsibility via
                        // nlme.leave() or nlme.rejoin() — do NOT clear state
                        // here. Removing the unconditional clear_join_state()
                        // call is the direct fix for the field failure where
                        // leave(rejoin=true) was wiping the network key.
                        return Err(NetworkError::LeaveRequested { rejoin });
                    }
                }
                Err(NetworkError::InvalidFrame)
            }
            NwkFrame::Reserved(header) | NwkFrame::InterPan(header) => {
                log::debug!(
                    "[NWK] poll_nwk_data: skipping non-data NWK frame type={:?} src={:?} dst={:?}",
                    header.frame_control.frame_type(),
                    header.source,
                    header.destination
                );
                Err(NetworkError::InvalidFrame)
            }
        }
    }

    /// Broadcast an NWK data frame (§3.6.5).
    ///
    /// Wraps `payload` in a NWK header addressed to `destination` and
    /// transmits it as a MAC broadcast.
    ///
    /// When `secure` is true the NWK frame is encrypted with the
    /// active network key.
    pub async fn broadcast_data(
        &mut self,
        destination: ShortAddress,
        secure: bool,
        payload: &[u8],
    ) -> Result<(), NetworkError> {
        let panid = self.nib().panid();
        let total_len = self.build_nwk_data_frame(destination, secure, payload)?;
        let mac_dest = Address::Short(PanId(panid), MacShortAddress(destination.0));
        self.mac
            .transmit_data(mac_dest, &self.buf[..total_len])
            .await?;
        Ok(())
    }

    /// Send an NWK data frame to a specific destination (§3.6.3).
    ///
    /// Wraps `payload` in a NWK header addressed to `destination` and
    /// transmits it via the parent (for end devices) or directly.
    ///
    /// When `secure` is true the NWK frame is encrypted with the
    /// active network key.
    pub async fn send_data(
        &mut self,
        destination: ShortAddress,
        secure: bool,
        payload: &[u8],
    ) -> Result<(), NetworkError> {
        let total_len = self.build_nwk_data_frame(destination, secure, payload)?;
        // end devices route via parent
        let mac_dest = self.parent_address()?;
        self.mac
            .transmit_data(mac_dest, &self.buf[..total_len])
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::future::Future;

    use zigbee_mac::AssociationStatus;
    use zigbee_mac::mlme::AssociationResponse;
    use zigbee_mac::mlme::MacError;
    use zigbee_mac::mlme::ScanResult;
    use zigbee_mac::mlme::ScanType;
    use zigbee_types::ByteArray;

    use super::*;
    use crate::aps::aib;
    use crate::aps::aib::AibStorage;
    use crate::nwk::frame::command::leave::CommandOptions as LeaveCommandOptions;
    use crate::nwk::frame::command::leave::Leave;
    use crate::nwk::frame::command::network_status::NetworkStatus;
    use crate::nwk::frame::command::network_status::NetworkStatusCode;
    use crate::nwk::nib::NetworkSecurityMaterialDescriptor;
    use crate::nwk::nib::NibStorage;
    use crate::security::SecurityContext;

    // -------------------------------------------------------------------
    // Minimal async block_on — the mock futures resolve immediately so a
    // single poll is sufficient.
    // -------------------------------------------------------------------

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
            fn set_channel(
                &mut self,
                channel: u8,
                pan_id: ShortAddress,
            ) -> Result<(), MacError>;
            async fn associate(
                &mut self,
                channel: u8,
                dest: Address,
                capabilities: zigbee_mac::CapabilityInformation,
            ) -> Result<AssociationResponse, MacError>;
            async fn poll_data(
                &mut self,
                coord_address: Address,
                buf: &mut [u8],
            ) -> Result<(usize, u8), MacError>;
            async fn transmit_data(
                &mut self,
                dest: Address,
                payload: &[u8],
            ) -> Result<(), MacError>;
            fn sync(
                &mut self,
                request: MlmeSyncRequest,
            ) -> Result<(), MacError>;
            fn reset(&mut self, set_default_pib: bool) -> Result<(), MacError>;
        }
    }

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    /// Create a default `NwkNeighbor` pre-filled for parent selection.
    fn make_neighbor(pan_id: u16, short_addr: u16, epid: u64, lqi: u8, depth: u8) -> NwkNeighbor {
        NwkNeighbor {
            network_address: ShortAddress(short_addr),
            extended_address: IeeeAddress(0),
            device_type: if short_addr == 0 {
                DeviceType::Coordinator
            } else {
                DeviceType::Router
            },
            rx_on_when_idle: false,
            end_device_configuration: 0,
            relationship: 0x03,
            transmit_failure: 0,
            lqi,
            outgoing_cost: 0,
            age: 0,
            keepalive_received: false,
            extended_pan_id: IeeeAddress(epid),
            logical_channel: 11,
            depth,
            permit_joining: true,
            potential_parent: 1,
            router_capacity: true,
            end_device_capacity: true,
            update_id: 0,
            pan_id,
        }
    }

    fn make_nlme(mac: MockMlme) -> (std::sync::MutexGuard<'static, ()>, Nlme<MockMlme>) {
        use crate::nwk::nib;
        let guard = nib::TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        nib::try_init(NibStorage::default());
        nib::reset();
        aib::try_init(AibStorage::default());
        aib::reset();
        // reset() only writes fields with explicit defaults; clear vec fields manually.
        nib::get_ref().set_neighbor_table(StorageVec::new());
        nib::get_ref().set_security_material_set(StorageVec::new());
        (guard, Nlme::new(mac))
    }

    fn default_join_request(epid: u64) -> NlmeJoinRequest {
        NlmeJoinRequest {
            extended_pan_id: IeeeAddress(epid),
            rejoin_network: RejoinNetwork::Association,
            capability_information: CapabilityInformation(0x80),
            security_enabled: false,
        }
    }

    fn default_rejoin_request(epid: u64) -> NlmeRejoinRequest {
        NlmeRejoinRequest {
            extended_pan_id: IeeeAddress(epid),
            capability_information: CapabilityInformation(0x80),
            secure: true,
            scan: RejoinScan::SameChannel,
        }
    }

    fn install_test_network_state(nlme: &Nlme<MockMlme>, epid: u64) {
        nlme.nib().set_network_address(0x5af5);
        nlme.nib().set_panid(0xabcd);
        nlme.nib().set_extended_panid(epid);
        nlme.nib().set_logical_channel(11);
        nlme.nib()
            .set_capability_information(CapabilityInformation(0x80));
        nlme.nib().set_active_key_seq_number(0);

        let mut parent = make_neighbor(0xabcd, 0x0000, epid, 255, 0);
        parent.relationship = relationship::PARENT;
        let mut table = StorageVec::new();
        table.push(parent).unwrap();
        nlme.nib().set_neighbor_table(table);

        let mut security = StorageVec::new();
        security
            .push(NetworkSecurityMaterialDescriptor {
                key_seq_number: 0,
                outgoing_frame_counter: 0,
                incoming_frame_counter_set: StorageVec::new(),
                key: ByteArray([0xab; 16]),
                network_key_type: 0x01,
            })
            .unwrap();
        nlme.nib().set_security_material_set(security);
    }

    fn assert_secured_rejoin_request_to(dest: &Address, payload: &[u8], parent_addr: u16) -> bool {
        if *dest != Address::Short(PanId(0xabcd), MacShortAddress(parent_addr)) {
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
            && command_frame.header.destination == ShortAddress(parent_addr)
            && command_frame.header.source == ShortAddress(0x5af5)
            && matches!(command_frame.command, NwkCommand::RejoinRequest(_))
    }

    fn scanned_rejoin_request() -> NlmeRejoinRequest {
        NlmeRejoinRequest {
            extended_pan_id: IeeeAddress(0x1122),
            capability_information: CapabilityInformation(0x80),
            secure: true,
            scan: RejoinScan::Channels {
                channels: 11..27,
                duration: 3,
            },
        }
    }

    fn scan_result<const N: usize>(
        descriptors: [zigbee_mac::mlme::PanDescriptor; N],
    ) -> ScanResult {
        let mut pan_descriptor = zigbee_mac::mlme::PanDescriptorList::new();
        for descriptor in descriptors {
            pan_descriptor.push(descriptor).unwrap();
        }
        ScanResult {
            scan_type: ScanType::Active,
            pan_descriptor,
        }
    }

    fn scan_parent(
        pan_id: u16,
        short_addr: u16,
        epid: u64,
        channel: u8,
        lqi: u8,
    ) -> zigbee_mac::mlme::PanDescriptor {
        zigbee_mac::mlme::PanDescriptor::new(
            channel,
            pan_id,
            short_addr,
            true,
            IeeeAddress(epid),
            lqi,
        )
    }

    fn write_secured_rejoin_response(buf: &mut [u8], addr: u16, status: u8) -> usize {
        let frame_control = NwkFrameControl(0)
            .set_frame_type(NwkFrameType::NwkCommand)
            .set_protocol_version(2)
            .set_discover_route(DiscoverRoute::Suppress)
            .set_security_flag(true);
        let header = NwkHeader {
            frame_control,
            destination: ShortAddress(0x5af5),
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
                network_address: ShortAddress(addr),
                status,
            }),
        });
        SecurityContext::get()
            .encrypt_nwk_frame_in_place(frame, buf)
            .unwrap()
    }

    fn write_nwk_command(
        buf: &mut [u8],
        source: u16,
        destination: u16,
        secure: bool,
        command: NwkCommand<'_>,
    ) -> usize {
        let frame_control = NwkFrameControl(0)
            .set_frame_type(NwkFrameType::NwkCommand)
            .set_protocol_version(2)
            .set_discover_route(DiscoverRoute::Suppress)
            .set_security_flag(secure);
        let header = NwkHeader {
            frame_control,
            destination: ShortAddress(destination),
            source: ShortAddress(source),
            radius: 30,
            sequence_number: 0x56,
            destination_ieee: None,
            source_ieee: None,
            multicast_control: None,
            source_route_subframe: None,
        };
        if secure {
            let frame = NwkFrame::NwkCommand(NwkCommandFrame { header, command });
            SecurityContext::get()
                .encrypt_nwk_frame_in_place(frame, buf)
                .unwrap()
        } else {
            let offset = &mut 0usize;
            buf.write_with(offset, header, ()).unwrap();
            buf.write_with(offset, command, ()).unwrap();
            *offset
        }
    }

    fn write_secured_leave_request(buf: &mut [u8], destination: u16, rejoin: bool) -> usize {
        let options = LeaveCommandOptions(0).set_request(true).set_rejoin(rejoin);
        write_nwk_command(
            buf,
            0x0000,
            destination,
            true,
            NwkCommand::Leave(Leave {
                command_options: options,
            }),
        )
    }

    fn write_unsecured_leave_request(buf: &mut [u8], destination: u16, rejoin: bool) -> usize {
        let options = LeaveCommandOptions(0).set_request(true).set_rejoin(rejoin);
        write_nwk_command(
            buf,
            0x0000,
            destination,
            false,
            NwkCommand::Leave(Leave {
                command_options: options,
            }),
        )
    }

    fn write_secured_network_status(buf: &mut [u8], destination: u16) -> usize {
        write_nwk_command(
            buf,
            0x0000,
            destination,
            true,
            NwkCommand::NetworkStatus(NetworkStatus {
                status_code: NetworkStatusCode::AddressConflict,
                destination_address: ShortAddress(destination),
            }),
        )
    }

    fn assert_secured_rejoin_request(dest: &Address, payload: &[u8]) -> bool {
        if *dest != Address::Short(PanId(0xabcd), MacShortAddress(0x0000)) {
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
            && command_frame.header.source == ShortAddress(0x5af5)
            && matches!(
                command_frame.command,
                NwkCommand::RejoinRequest(req) if req.capability_information.0 == 0x80
            )
    }

    // -------------------------------------------------------------------
    // select_parent_candidates tests
    // -------------------------------------------------------------------

    #[test]
    fn select_parent_no_neighbors() {
        let (_guard, nlme) = make_nlme(MockMlme::new());
        let candidates = nlme.select_parent_candidates(IeeeAddress(0x1234), false);
        assert!(candidates.is_empty());
    }

    #[test]
    fn select_parent_filters_by_extended_pan_id() {
        let (_guard, nlme) = make_nlme(MockMlme::new());

        let mut table = StorageVec::new();
        // neighbor on the correct network
        table
            .push(make_neighbor(0xAAAA, 0x0000, 0x1234, 200, 0))
            .unwrap();
        // neighbor on a different network
        table
            .push(make_neighbor(0xBBBB, 0x0001, 0x9999, 200, 0))
            .unwrap();
        nlme.nib().set_neighbor_table(table);

        let candidates = nlme.select_parent_candidates(IeeeAddress(0x1234), false);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0], 0);
    }

    #[test]
    fn select_parent_filters_by_link_cost() {
        let (_guard, nlme) = make_nlme(MockMlme::new());

        let mut table = StorageVec::new();
        // good LQI => low cost => eligible
        table
            .push(make_neighbor(0xAAAA, 0x0000, 0x1234, 200, 0))
            .unwrap();
        // bad LQI => high cost => filtered out
        table
            .push(make_neighbor(0xAAAA, 0x0001, 0x1234, 10, 0))
            .unwrap();
        nlme.nib().set_neighbor_table(table);

        let candidates = nlme.select_parent_candidates(IeeeAddress(0x1234), false);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0], 0);
    }

    #[test]
    fn select_parent_filters_by_end_device_capacity() {
        let (_guard, nlme) = make_nlme(MockMlme::new());

        let mut table = StorageVec::new();
        let mut n = make_neighbor(0xAAAA, 0x0000, 0x1234, 200, 0);
        n.end_device_capacity = false;
        table.push(n).unwrap();
        nlme.nib().set_neighbor_table(table);

        let candidates = nlme.select_parent_candidates(IeeeAddress(0x1234), false);
        assert!(candidates.is_empty());
    }

    #[test]
    fn select_parent_filters_by_router_capacity() {
        let (_guard, nlme) = make_nlme(MockMlme::new());

        let mut table = StorageVec::new();
        let mut n = make_neighbor(0xAAAA, 0x0000, 0x1234, 200, 0);
        n.router_capacity = false;
        table.push(n).unwrap();
        nlme.nib().set_neighbor_table(table);

        let candidates = nlme.select_parent_candidates(IeeeAddress(0x1234), true);
        assert!(candidates.is_empty());
    }

    #[test]
    fn select_parent_sorts_by_depth_for_stack_profile_1() {
        let (_guard, nlme) = make_nlme(MockMlme::new());
        nlme.nib().set_stack_profile(1);

        let mut table = StorageVec::new();
        table
            .push(make_neighbor(0xAAAA, 0x0000, 0x1234, 200, 3))
            .unwrap();
        table
            .push(make_neighbor(0xAAAA, 0x0001, 0x1234, 200, 1))
            .unwrap();
        table
            .push(make_neighbor(0xAAAA, 0x0002, 0x1234, 200, 2))
            .unwrap();
        nlme.nib().set_neighbor_table(table);

        let candidates = nlme.select_parent_candidates(IeeeAddress(0x1234), false);
        assert_eq!(candidates.len(), 3);
        // sorted: depth 1 (idx 1), depth 2 (idx 2), depth 3 (idx 0)
        assert_eq!(candidates[0], 1);
        assert_eq!(candidates[1], 2);
        assert_eq!(candidates[2], 0);
    }

    #[test]
    fn select_parent_filters_not_permitting_join() {
        let (_guard, nlme) = make_nlme(MockMlme::new());

        let mut table = StorageVec::new();
        let mut n = make_neighbor(0xAAAA, 0x0000, 0x1234, 200, 0);
        n.permit_joining = false;
        table.push(n).unwrap();
        nlme.nib().set_neighbor_table(table);

        let candidates = nlme.select_parent_candidates(IeeeAddress(0x1234), false);
        assert!(candidates.is_empty());
    }

    #[test]
    fn select_parent_filters_non_potential_parent() {
        let (_guard, nlme) = make_nlme(MockMlme::new());

        let mut table = StorageVec::new();
        let mut n = make_neighbor(0xAAAA, 0x0000, 0x1234, 200, 0);
        n.potential_parent = 0;
        table.push(n).unwrap();
        nlme.nib().set_neighbor_table(table);

        let candidates = nlme.select_parent_candidates(IeeeAddress(0x1234), false);
        assert!(candidates.is_empty());
    }

    #[test]
    fn select_parent_prefers_most_recent_update_id() {
        let (_guard, nlme) = make_nlme(MockMlme::new());

        let mut table = StorageVec::new();
        let mut n1 = make_neighbor(0xAAAA, 0x0000, 0x1234, 200, 0);
        n1.update_id = 5;
        table.push(n1).unwrap();
        let mut n2 = make_neighbor(0xAAAA, 0x0001, 0x1234, 200, 0);
        n2.update_id = 3;
        table.push(n2).unwrap();
        nlme.nib().set_neighbor_table(table);

        let candidates = nlme.select_parent_candidates(IeeeAddress(0x1234), false);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0], 0);
    }

    // -------------------------------------------------------------------
    // join() integration tests (using MockMlme)
    // -------------------------------------------------------------------

    #[test]
    fn join_successful_association() {
        let mut mac = MockMlme::new();
        mac.expect_associate().returning(|_, _, _| {
            Ok(AssociationResponse {
                device_address: IeeeAddress(0),
                association_address: ShortAddress(0x1234),
                status: AssociationStatus::Successful,
            })
        });

        let (_guard, mut nlme) = make_nlme(mac);

        let mut table = StorageVec::new();
        table
            .push(make_neighbor(0xAAAA, 0x0000, 0xDEAD, 200, 0))
            .unwrap();
        nlme.nib().set_neighbor_table(table);

        let confirm = block_on(nlme.join(default_join_request(0xDEAD)));

        assert_eq!(confirm.status, NlmeJoinStatus::Success);
        assert_eq!(confirm.network_address.0, 0x1234);
        assert_eq!(confirm.extended_pan_id.0, 0xDEAD);
        assert_eq!(confirm.channel, 11);

        assert_eq!(nlme.nib().network_address(), 0x1234);
        assert_eq!(nlme.nib().extended_panid(), 0xDEAD);
        assert_eq!(nlme.nib().panid(), 0xAAAA);
        assert_eq!(nlme.nib().update_id(), 0);

        let table = nlme.nib().neighbor_table();
        assert_eq!(table[0].relationship, 0x00);
    }

    #[test]
    fn join_sets_nwk_update_id_from_parent() {
        let mut mac = MockMlme::new();
        mac.expect_associate().returning(|_, _, _| {
            Ok(AssociationResponse {
                device_address: IeeeAddress(0),
                association_address: ShortAddress(0x1234),
                status: AssociationStatus::Successful,
            })
        });

        let (_guard, mut nlme) = make_nlme(mac);

        let mut n = make_neighbor(0xAAAA, 0x0000, 0xDEAD, 200, 0);
        n.update_id = 7;
        let mut table = StorageVec::new();
        table.push(n).unwrap();
        nlme.nib().set_neighbor_table(table);

        let confirm = block_on(nlme.join(default_join_request(0xDEAD)));
        assert_eq!(confirm.status, NlmeJoinStatus::Success);
        assert_eq!(nlme.nib().update_id(), 7);
    }

    #[test]
    fn join_fails_when_no_candidates() {
        let mac = MockMlme::new();
        let (_guard, mut nlme) = make_nlme(mac);
        nlme.nib().set_neighbor_table(StorageVec::new());
        let confirm = block_on(nlme.join(default_join_request(0xDEAD)));
        assert_eq!(confirm.status, NlmeJoinStatus::NotPermitted);
    }

    #[test]
    fn join_fails_when_already_joined() {
        let mac = MockMlme::new();
        let (_guard, mut nlme) = make_nlme(mac);
        nlme.nib().set_network_address(0x0001);

        let confirm = block_on(nlme.join(default_join_request(0xDEAD)));
        assert_eq!(confirm.status, NlmeJoinStatus::InvalidRequest);
    }

    #[test]
    fn join_skips_capacity_rejected_parent_tries_next() {
        let mut mac = MockMlme::new();
        let mut seq = mockall::Sequence::new();
        mac.expect_associate()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _, _| {
                Ok(AssociationResponse {
                    device_address: IeeeAddress(0),
                    association_address: ShortAddress(0),
                    status: AssociationStatus::NetworkAtCapacity,
                })
            });
        mac.expect_associate()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _, _| {
                Ok(AssociationResponse {
                    device_address: IeeeAddress(0),
                    association_address: ShortAddress(0x5678),
                    status: AssociationStatus::Successful,
                })
            });

        let (_guard, mut nlme) = make_nlme(mac);

        let mut table = StorageVec::new();
        table
            .push(make_neighbor(0xAAAA, 0x0000, 0xDEAD, 200, 0))
            .unwrap();
        table
            .push(make_neighbor(0xAAAA, 0x0001, 0xDEAD, 200, 0))
            .unwrap();
        nlme.nib().set_neighbor_table(table);

        let confirm = block_on(nlme.join(default_join_request(0xDEAD)));
        assert_eq!(confirm.status, NlmeJoinStatus::Success);
        assert_eq!(confirm.network_address.0, 0x5678);

        // After join, retain keeps only the parent; the rejected candidate is
        // discarded.
        let table = nlme.nib().neighbor_table();
        assert_eq!(table.len(), 1, "only parent should remain after join");
        assert_eq!(table[0].relationship, relationship::PARENT);
    }

    #[test]
    fn join_all_candidates_rejected() {
        let mut mac = MockMlme::new();
        mac.expect_associate().returning(|_, _, _| {
            Ok(AssociationResponse {
                device_address: IeeeAddress(0),
                association_address: ShortAddress(0),
                status: AssociationStatus::AccessDenied,
            })
        });

        let (_guard, mut nlme) = make_nlme(mac);

        let mut table = StorageVec::new();
        table
            .push(make_neighbor(0xAAAA, 0x0000, 0xDEAD, 200, 0))
            .unwrap();
        nlme.nib().set_neighbor_table(table);

        let confirm = block_on(nlme.join(default_join_request(0xDEAD)));
        assert_eq!(confirm.status, NlmeJoinStatus::PanAccessDenied);
        assert_eq!(confirm.network_address.0, 0xffff);
    }

    #[test]
    fn join_mac_error_reported() {
        let mut mac = MockMlme::new();
        mac.expect_associate()
            .returning(|_, _, _| Err(MacError::NoAck));

        let (_guard, mut nlme) = make_nlme(mac);

        let mut table = StorageVec::new();
        table
            .push(make_neighbor(0xAAAA, 0x0000, 0xDEAD, 200, 0))
            .unwrap();
        nlme.nib().set_neighbor_table(table);

        let confirm = block_on(nlme.join(default_join_request(0xDEAD)));
        assert_eq!(confirm.status, NlmeJoinStatus::MacError);
    }

    #[test]
    fn leave_without_rejoin_clears_network_state_but_preserves_outgoing_counter() {
        let mut mac = MockMlme::new();
        mac.expect_transmit_data().returning(|_, _| Ok(()));
        let (_guard, mut nlme) = make_nlme(mac);
        install_test_network_state(&nlme, 0x1122);
        let mut security = nlme.nib().security_material_set();
        security[0].outgoing_frame_counter = 7;
        nlme.nib().set_security_material_set(security);
        nlme.nib().set_outgoing_frame_counter(3);

        let confirm = block_on(nlme.leave(&NlmeLeaveRequest {
            rejoin: false,
            remove_children: false,
            source: LeaveSource::Local,
        }));

        assert_eq!(confirm.status, NlmeLeaveStatus::Success);
        assert_eq!(nlme.nib().network_address(), 0xffff);
        assert_eq!(nlme.nib().panid(), 0xffff);
        assert_eq!(nlme.nib().extended_panid(), 0);
        assert!(nlme.nib().neighbor_table().is_empty());
        assert!(nlme.nib().security_material_set().is_empty());
        // Counter was 7; sending the Leave frame increments it to 8, which is
        // then preserved by clear_network_state_for_permanent_leave.
        assert_eq!(nlme.nib().outgoing_frame_counter(), 8);
    }

    #[test]
    fn poll_nwk_data_ignores_unsecured_leave_request() {
        let mut mac = MockMlme::new();
        mac.expect_poll_data().returning(|_, buf| {
            let len = write_unsecured_leave_request(buf, 0x5af5, true);
            Ok((len, 200))
        });

        let (_guard, mut nlme) = make_nlme(mac);
        install_test_network_state(&nlme, 0x1122);
        let mut buf = [0u8; 128];

        let err = block_on(nlme.poll_nwk_data(&mut buf, 1)).unwrap_err();

        assert!(matches!(err, NetworkError::InvalidFrame));
        assert_eq!(nlme.nib().network_address(), 0x5af5);
        assert_eq!(nlme.nib().security_material_set().len(), 1);
    }

    #[test]
    fn poll_nwk_data_accepts_secured_leave_rejoin_request() {
        let mut mac = MockMlme::new();
        mac.expect_poll_data().returning(|_, buf| {
            let len = write_secured_leave_request(buf, 0x5af5, true);
            Ok((len, 200))
        });

        let (_guard, mut nlme) = make_nlme(mac);
        install_test_network_state(&nlme, 0x1122);
        let mut buf = [0u8; 128];

        let err = block_on(nlme.poll_nwk_data(&mut buf, 1)).unwrap_err();

        assert!(matches!(err, NetworkError::LeaveRequested { rejoin: true }));
        assert_eq!(nlme.nib().network_address(), 0x5af5);
        assert_eq!(nlme.nib().security_material_set().len(), 1);
    }

    #[test]
    fn join_stale_neighbors_removed_after_success() {
        let mut mac = MockMlme::new();
        mac.expect_associate().returning(|_, _, _| {
            Ok(AssociationResponse {
                device_address: IeeeAddress(0),
                association_address: ShortAddress(0x1234),
                status: AssociationStatus::Successful,
            })
        });

        let (_guard, mut nlme) = make_nlme(mac);

        // Two neighbors on the same network — only the chosen parent should survive.
        let mut table = StorageVec::new();
        table
            .push(make_neighbor(0xAAAA, 0x0000, 0xDEAD, 200, 0))
            .unwrap();
        table
            .push(make_neighbor(0xAAAA, 0x0001, 0xDEAD, 180, 1))
            .unwrap();
        nlme.nib().set_neighbor_table(table);

        let confirm = block_on(nlme.join(default_join_request(0xDEAD)));
        assert_eq!(confirm.status, NlmeJoinStatus::Success);

        let table = nlme.nib().neighbor_table();
        assert_eq!(table.len(), 1, "only parent should remain");
        assert_eq!(table[0].relationship, relationship::PARENT);
    }

    #[test]
    fn join_invalid_rejoin_network() {
        let mac = MockMlme::new();
        let (_guard, mut nlme) = make_nlme(mac);

        let mut req = default_join_request(0xDEAD);
        req.rejoin_network = RejoinNetwork::Orphan;

        let confirm = block_on(nlme.join(req));
        assert_eq!(confirm.status, NlmeJoinStatus::InvalidRequest);
    }

    #[test]
    fn leave_rejoin_preserves_network_security_state() {
        let (_guard, mut nlme) = make_nlme(MockMlme::new());
        install_test_network_state(&nlme, 0x1122_3344_5566_7788);
        let before_key = nlme.nib().security_material_set()[0].key;
        let before_counter = nlme.nib().security_material_set()[0].outgoing_frame_counter;

        let confirm = block_on(nlme.leave(&NlmeLeaveRequest {
            rejoin: true,
            remove_children: false,
            source: LeaveSource::NetworkRequest {
                source: ShortAddress(0x0000),
            },
        }));

        assert_eq!(confirm.status, NlmeLeaveStatus::Success);
        assert_eq!(nlme.nib().network_address(), 0x5af5);
        assert_eq!(nlme.nib().panid(), 0xabcd);
        assert_eq!(nlme.nib().extended_panid(), 0x1122_3344_5566_7788);
        assert_eq!(nlme.nib().logical_channel(), 11);
        let security = nlme.nib().security_material_set();
        assert_eq!(security.len(), 1);
        assert_eq!(security[0].key, before_key);
        assert_eq!(security[0].outgoing_frame_counter, before_counter);
    }

    #[test]
    fn nlme_rejoin_success_updates_parent() {
        let mut mac = MockMlme::new();
        mac.expect_transmit_data()
            .withf(assert_secured_rejoin_request)
            .returning(|_, _| Ok(()));
        mac.expect_poll_data().returning(|_, buf| {
            let len = write_secured_rejoin_response(buf, 0x9c5d, 0);
            Ok((len, 200))
        });

        let (_guard, mut nlme) = make_nlme(mac);
        install_test_network_state(&nlme, 0x1122);
        let mut table = nlme.nib().neighbor_table();
        table[0].relationship = relationship::NONE;
        table[0].transmit_failure = 5;
        table[0].age = 9;
        table[0].extended_pan_id = IeeeAddress(0);
        table[0].logical_channel = 0xff;
        table[0].update_id = 0xff;
        table[0].pan_id = 0xffff;
        table[0].relationship = relationship::PARENT;
        nlme.nib().set_neighbor_table(table);
        nlme.nib().set_update_id(6);

        let confirm = block_on(nlme.rejoin(default_rejoin_request(0x1122)));

        assert_eq!(confirm.status, NlmeJoinStatus::Success);
        let table = nlme.nib().neighbor_table();
        assert_eq!(table[0].relationship, relationship::PARENT);
        assert_eq!(table[0].transmit_failure, 0);
        assert_eq!(table[0].age, 0);
        assert_eq!(table[0].extended_pan_id, IeeeAddress(0x1122));
        assert_eq!(table[0].logical_channel, 11);
        assert_eq!(table[0].update_id, 6);
        assert_eq!(table[0].pan_id, 0xabcd);
    }

    #[test]
    fn rejoin_scan_selects_same_epid_parent() {
        let mut mac = MockMlme::new();
        mac.expect_scan_network()
            .withf(|ty, channels, duration| {
                *ty == ScanType::Active && channels.clone() == (11..27) && *duration == 3
            })
            .returning(|_, _, _| {
                Ok(scan_result([
                    scan_parent(0xabcd, 0x0001, 0x1122, 15, 180),
                    scan_parent(0xabcd, 0x0002, 0x9999, 15, 255),
                    scan_parent(0xbeef, 0x0003, 0x1122, 15, 255),
                ]))
            });
        mac.expect_set_channel()
            .withf(|channel, pan_id| *channel == 15 && *pan_id == ShortAddress(0xabcd))
            .returning(|_, _| Ok(()));
        mac.expect_transmit_data()
            .withf(|dest, payload| assert_secured_rejoin_request_to(dest, payload, 0x0001))
            .returning(|_, _| Ok(()));
        mac.expect_poll_data()
            .withf(|coord_address, _| {
                *coord_address == Address::Short(PanId(0xabcd), MacShortAddress(0x0001))
            })
            .returning(|_, buf| {
                let len = write_secured_rejoin_response(buf, 0x9c5d, 0);
                Ok((len, 180))
            });

        let (_guard, mut nlme) = make_nlme(mac);
        install_test_network_state(&nlme, 0x1122);

        let confirm = block_on(nlme.rejoin(scanned_rejoin_request()));

        assert_eq!(confirm.status, NlmeJoinStatus::Success);
        assert_eq!(confirm.network_address, ShortAddress(0x9c5d));
        assert_eq!(confirm.channel, 15);
        assert_eq!(nlme.nib().network_address(), 0x9c5d);
        assert_eq!(nlme.nib().logical_channel(), 15);
        let table = nlme.nib().neighbor_table();
        assert_eq!(
            table
                .iter()
                .find(|n| n.relationship == relationship::PARENT)
                .unwrap()
                .network_address,
            ShortAddress(0x0001)
        );
    }

    #[test]
    fn rejoin_scan_ignores_other_epid() {
        let mut mac = MockMlme::new();
        mac.expect_scan_network()
            .returning(|_, _, _| Ok(scan_result([scan_parent(0xabcd, 0x0001, 0x9999, 15, 255)])));

        let (_guard, mut nlme) = make_nlme(mac);
        install_test_network_state(&nlme, 0x1122);
        nlme.nib().set_neighbor_table(StorageVec::new());
        let confirm = block_on(nlme.rejoin(scanned_rejoin_request()));

        assert_eq!(confirm.status, NlmeJoinStatus::NotPermitted);
        assert_eq!(nlme.nib().network_address(), 0x5af5);
        assert_eq!(nlme.nib().logical_channel(), 11);
        assert_eq!(nlme.nib().security_material_set().len(), 1);
    }

    #[test]
    fn rejoin_scan_prefers_better_link_cost() {
        let mut mac = MockMlme::new();
        mac.expect_scan_network().returning(|_, _, _| {
            Ok(scan_result([
                scan_parent(0xabcd, 0x0001, 0x1122, 15, 120),
                scan_parent(0xabcd, 0x0002, 16, 16, 220),
                scan_parent(0xabcd, 0x0003, 0x1122, 17, 220),
            ]))
        });
        mac.expect_set_channel()
            .withf(|channel, pan_id| *channel == 17 && *pan_id == ShortAddress(0xabcd))
            .returning(|_, _| Ok(()));
        mac.expect_transmit_data()
            .withf(|dest, payload| assert_secured_rejoin_request_to(dest, payload, 0x0003))
            .returning(|_, _| Ok(()));
        mac.expect_poll_data()
            .withf(|coord_address, _| {
                *coord_address == Address::Short(PanId(0xabcd), MacShortAddress(0x0003))
            })
            .returning(|_, buf| {
                let len = write_secured_rejoin_response(buf, 0x9c5d, 0);
                Ok((len, 220))
            });

        let (_guard, mut nlme) = make_nlme(mac);
        install_test_network_state(&nlme, 0x1122);

        let confirm = block_on(nlme.rejoin(scanned_rejoin_request()));

        assert_eq!(confirm.status, NlmeJoinStatus::Success);
        assert_eq!(confirm.channel, 17);
        assert_eq!(
            nlme.nib()
                .neighbor_table()
                .iter()
                .find(|n| n.relationship == relationship::PARENT)
                .unwrap()
                .network_address,
            ShortAddress(0x0003)
        );
    }
    #[test]
    fn nlme_rejoin_rejects_missing_network_key() {
        let (_guard, mut nlme) = make_nlme(MockMlme::new());
        install_test_network_state(&nlme, 0x1122);
        nlme.nib().set_security_material_set(StorageVec::new());

        let confirm = block_on(nlme.rejoin(default_rejoin_request(0x1122)));

        assert_eq!(confirm.status, NlmeJoinStatus::InvalidRequest);
        assert_eq!(nlme.nib().network_address(), 0x5af5);
    }

    #[test]
    fn nlme_rejoin_rejects_mismatched_epid() {
        let (_guard, mut nlme) = make_nlme(MockMlme::new());
        install_test_network_state(&nlme, 0x1122);

        let confirm = block_on(nlme.rejoin(default_rejoin_request(0x3344)));

        assert_eq!(confirm.status, NlmeJoinStatus::InvalidRequest);
        assert_eq!(nlme.nib().network_address(), 0x5af5);
    }

    #[test]
    fn nlme_rejoin_rejects_unknown_channel() {
        let (_guard, mut nlme) = make_nlme(MockMlme::new());
        install_test_network_state(&nlme, 0x1122);
        nlme.nib().set_logical_channel(0xff);

        let confirm = block_on(nlme.rejoin(default_rejoin_request(0x1122)));

        assert_eq!(confirm.status, NlmeJoinStatus::InvalidRequest);
        assert_eq!(nlme.nib().network_address(), 0x5af5);
    }

    #[test]
    fn nlme_rejoin_sends_secured_rejoin_request_and_updates_short_address() {
        let mut mac = MockMlme::new();
        mac.expect_transmit_data()
            .withf(assert_secured_rejoin_request)
            .returning(|_, _| Ok(()));
        mac.expect_poll_data().returning(|_, buf| {
            let len = write_secured_rejoin_response(buf, 0x9c5d, 0);
            Ok((len, 200))
        });

        let (_guard, mut nlme) = make_nlme(mac);
        install_test_network_state(&nlme, 0x1122);

        let confirm = block_on(nlme.rejoin(default_rejoin_request(0x1122)));

        assert_eq!(confirm.status, NlmeJoinStatus::Success);
        assert_eq!(confirm.network_address, ShortAddress(0x9c5d));
        assert_eq!(nlme.nib().network_address(), 0x9c5d);
        assert_eq!(nlme.nib().security_material_set().len(), 1);
    }

    #[test]
    fn nlme_rejoin_nonzero_status_fails_without_clearing_keys() {
        let mut mac = MockMlme::new();
        mac.expect_transmit_data()
            .withf(assert_secured_rejoin_request)
            .returning(|_, _| Ok(()));
        mac.expect_poll_data().returning(|_, buf| {
            let len = write_secured_rejoin_response(buf, 0x9c5d, 1);
            Ok((len, 200))
        });

        let (_guard, mut nlme) = make_nlme(mac);
        install_test_network_state(&nlme, 0x1122);
        let original_key = nlme.nib().security_material_set()[0].key;

        let confirm = block_on(nlme.rejoin(default_rejoin_request(0x1122)));

        assert_eq!(confirm.status, NlmeJoinStatus::NotPermitted);
        assert_eq!(nlme.nib().network_address(), 0x5af5);
        assert_eq!(nlme.nib().security_material_set()[0].key, original_key);
    }

    #[test]
    fn join_dispatches_nwk_rejoin_to_rejoin_path() {
        let mut mac = MockMlme::new();
        mac.expect_transmit_data()
            .withf(assert_secured_rejoin_request)
            .returning(|_, _| Ok(()));
        mac.expect_poll_data().returning(|_, buf| {
            let len = write_secured_rejoin_response(buf, 0x9c5d, 0);
            Ok((len, 200))
        });

        let (_guard, mut nlme) = make_nlme(mac);
        install_test_network_state(&nlme, 0x1122);
        let mut request = default_join_request(0x1122);
        request.rejoin_network = RejoinNetwork::NwkRejoin;
        request.security_enabled = true;

        let confirm = block_on(nlme.join(request));

        assert_eq!(confirm.status, NlmeJoinStatus::Success);
        assert_eq!(nlme.nib().network_address(), 0x9c5d);
    }

    // -------------------------------------------------------------------
    // NLME-SYNC tests
    // -------------------------------------------------------------------

    #[test]
    fn sync_tunes_to_parent_channel_and_pan() {
        let mut mac = MockMlme::new();
        mac.expect_sync()
            .withf(|req| req.logical_channel == 11 && req.pan_id == ShortAddress(0xabcd))
            .once()
            .returning(|_| Ok(()));

        let (_guard, mut nlme) = make_nlme(mac);
        install_test_network_state(&nlme, 0x1122);

        let confirm = nlme.sync(NlmeSyncRequest { track_beacon: true });

        assert_eq!(confirm.status, NlmeSyncStatus::Success);
    }

    #[test]
    fn sync_returns_no_sync_when_no_parent() {
        let mac = MockMlme::new();
        let (_guard, mut nlme) = make_nlme(mac);
        nlme.nib().set_neighbor_table(StorageVec::new());

        let confirm = nlme.sync(NlmeSyncRequest {
            track_beacon: false,
        });

        assert_eq!(confirm.status, NlmeSyncStatus::NoSynchronization);
    }

    // -------------------------------------------------------------------
    // NLME-RESET tests
    // -------------------------------------------------------------------

    #[test]
    fn cold_reset_clears_network_state() {
        let mut mac = MockMlme::new();
        mac.expect_reset()
            .withf(|&set_default_pib| set_default_pib)
            .once()
            .returning(|_| Ok(()));

        let (_guard, mut nlme) = make_nlme(mac);
        install_test_network_state(&nlme, 0x1122);

        let confirm = nlme.reset(&NlmeResetRequest { warm_start: false });

        assert_eq!(confirm.status, NlmeResetStatus::Success);
        assert_eq!(nlme.nib().network_address(), 0xffff);
        assert_eq!(nlme.nib().panid(), 0xffff);
        assert_eq!(nlme.nib().extended_panid(), 0);
        assert!(nlme.nib().neighbor_table().is_empty());
        assert!(nlme.nib().security_material_set().is_empty());
    }

    #[test]
    fn warm_reset_preserves_network_state() {
        let mut mac = MockMlme::new();
        mac.expect_reset()
            .withf(|&set_default_pib| !set_default_pib)
            .once()
            .returning(|_| Ok(()));

        let (_guard, mut nlme) = make_nlme(mac);
        install_test_network_state(&nlme, 0x1122);

        let confirm = nlme.reset(&NlmeResetRequest { warm_start: true });

        assert_eq!(confirm.status, NlmeResetStatus::Success);
        // Network state preserved.
        assert_eq!(nlme.nib().network_address(), 0x5af5);
        assert_eq!(nlme.nib().extended_panid(), 0x1122);
        assert!(!nlme.nib().security_material_set().is_empty());
    }

    #[test]
    fn reset_mac_error_propagates() {
        let mut mac = MockMlme::new();
        mac.expect_reset()
            .once()
            .returning(|_| Err(MacError::NoData));

        let (_guard, mut nlme) = make_nlme(mac);
        install_test_network_state(&nlme, 0x1122);

        let confirm = nlme.reset(&NlmeResetRequest { warm_start: false });

        assert_eq!(confirm.status, NlmeResetStatus::MacError);
        // State unchanged on MAC error.
        assert_eq!(nlme.nib().network_address(), 0x5af5);
    }

    // -------------------------------------------------------------------
    // NLME-ED-SCAN test
    // -------------------------------------------------------------------

    #[test]
    fn ed_scan_returns_mac_error_when_not_supported() {
        let mac = MockMlme::new();
        let (_guard, nlme) = make_nlme(mac);
        install_test_network_state(&nlme, 0x1122);

        let confirm = nlme.ed_scan(&NlmeEdScanRequest {
            channel_list: 11..27,
            scan_duration: 3,
        });

        assert_eq!(confirm.status, NlmeJoinStatus::MacError);
        assert!(confirm.energy_detect_list.is_empty());
    }

    // -------------------------------------------------------------------
    // NLME-LEAVE M4 tests
    // -------------------------------------------------------------------

    fn assert_leave_command(dest: &Address, payload: &[u8], expect_rejoin: bool) -> bool {
        if *dest != Address::Short(PanId(0xabcd), MacShortAddress(0x0000)) {
            return false;
        }
        let mut frame_buf = [0u8; 256];
        frame_buf[..payload.len()].copy_from_slice(payload);
        let Ok(NwkFrame::NwkCommand(cmd_frame)) =
            SecurityContext::get().decrypt_nwk_frame_in_place(&mut frame_buf[..payload.len()])
        else {
            return false;
        };
        let NwkCommand::Leave(leave) = cmd_frame.command else {
            return false;
        };
        !leave.command_options.request()
            && leave.command_options.rejoin() == expect_rejoin
            && cmd_frame.header.frame_control.security_flag()
    }

    #[test]
    fn local_leave_sends_nwk_leave_command_to_parent() {
        let mut mac = MockMlme::new();
        mac.expect_transmit_data()
            .withf(|dest, payload| assert_leave_command(dest, payload, false))
            .once()
            .returning(|_, _| Ok(()));

        let (_guard, mut nlme) = make_nlme(mac);
        install_test_network_state(&nlme, 0x1122);

        let confirm = block_on(nlme.leave(&NlmeLeaveRequest {
            rejoin: false,
            remove_children: false,
            source: LeaveSource::Local,
        }));

        assert_eq!(confirm.status, NlmeLeaveStatus::Success);
        assert_eq!(nlme.nib().network_address(), 0xffff);
    }

    #[test]
    fn local_leave_with_rejoin_sets_rejoin_flag_in_nwk_command() {
        let mut mac = MockMlme::new();
        mac.expect_transmit_data()
            .withf(|dest, payload| assert_leave_command(dest, payload, true))
            .once()
            .returning(|_, _| Ok(()));

        let (_guard, mut nlme) = make_nlme(mac);
        install_test_network_state(&nlme, 0x1122);

        let confirm = block_on(nlme.leave(&NlmeLeaveRequest {
            rejoin: true,
            remove_children: false,
            source: LeaveSource::Local,
        }));

        assert_eq!(confirm.status, NlmeLeaveStatus::Success);
        // rejoin=true: state preserved
        assert_eq!(nlme.nib().network_address(), 0x5af5);
        assert_eq!(nlme.nib().security_material_set().len(), 1);
    }

    #[test]
    fn network_initiated_leave_skips_nwk_transmit() {
        // MockMlme has no transmit_data expectation — would panic if called.
        let mac = MockMlme::new();
        let (_guard, mut nlme) = make_nlme(mac);
        install_test_network_state(&nlme, 0x1122);

        let confirm = block_on(nlme.leave(&NlmeLeaveRequest {
            rejoin: false,
            remove_children: false,
            source: LeaveSource::NetworkRequest {
                source: ShortAddress(0x0000),
            },
        }));

        assert_eq!(confirm.status, NlmeLeaveStatus::Success);
        assert_eq!(nlme.nib().network_address(), 0xffff);
    }

    #[test]
    fn permanent_leave_clears_aps_binding_table() {
        use zigbee_types::BindingEntry;

        use crate::aps::aib;

        let mut mac = MockMlme::new();
        mac.expect_transmit_data().returning(|_, _| Ok(()));
        let (_guard, mut nlme) = make_nlme(mac);
        install_test_network_state(&nlme, 0x1122);

        // Populate the binding table so we can verify it gets cleared.
        let mut table = aib::get_ref().binding_table();
        table
            .push(BindingEntry {
                src_endpoint: 1,
                cluster_id: 0x0006,
                dst_short_addr: 0x1234,
                dst_endpoint: 1,
                profile_id: 0x0104,
            })
            .unwrap();
        aib::get_ref().set_binding_table(table);
        assert_eq!(aib::get_ref().binding_table().len(), 1);

        let confirm = block_on(nlme.leave(&NlmeLeaveRequest {
            rejoin: false,
            remove_children: false,
            source: LeaveSource::Local,
        }));

        assert_eq!(confirm.status, NlmeLeaveStatus::Success);
        assert!(aib::get_ref().binding_table().is_empty());
    }

    #[test]
    fn leave_transmit_failure_still_clears_state() {
        let mut mac = MockMlme::new();
        mac.expect_transmit_data()
            .returning(|_, _| Err(MacError::NoAck));
        let (_guard, mut nlme) = make_nlme(mac);
        install_test_network_state(&nlme, 0x1122);

        let confirm = block_on(nlme.leave(&NlmeLeaveRequest {
            rejoin: false,
            remove_children: false,
            source: LeaveSource::Local,
        }));

        assert_eq!(confirm.status, NlmeLeaveStatus::Success);
        assert_eq!(nlme.nib().network_address(), 0xffff);
    }
}
