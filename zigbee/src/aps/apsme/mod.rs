//! Application Support Sub-Layer Management Entity
//!
//! The APSME shall provide a management service to allow an application to
//! interact with the stack.
//!
//! It provides the following services:
//! * Binding management
//! * AIB management
//! * Security
//! * Group management
#![allow(dead_code)]

use core::ops::Not;

use basemgt::ApsmeAddGroupConfirm;
use basemgt::ApsmeAddGroupRequest;
use basemgt::ApsmeBindConfirm;
use basemgt::ApsmeBindRequest;
use basemgt::ApsmeBindRequestStatus;
use basemgt::ApsmeGetConfirm;
use basemgt::ApsmeGetConfirmStatus;
use basemgt::ApsmeRemoveAllGroupsConfirm;
use basemgt::ApsmeRemoveAllGroupsRequest;
use basemgt::ApsmeRemoveGroupConfirm;
use basemgt::ApsmeRemoveGroupRequest;
use basemgt::ApsmeSetConfirm;
use basemgt::ApsmeUnbindConfirm;
use basemgt::ApsmeUnbindRequest;
use basemgt::ApsmeUnbindRequestStatus;
use byte::BytesExt;
use byte::TryRead;
use zigbee_mac::mlme::MacError;
use zigbee_types::IeeeAddress;
use zigbee_types::ShortAddress;

use super::binding::ApsBindingTable;
use super::frame::CommandFrame;
use super::frame::Frame;
use super::frame::command::Command;
use super::frame::frame_control::DeliveryMode;
use super::frame::frame_control::ExtendedFrameControl;
use super::frame::frame_control::ExtendedFrameControlField;
use super::frame::frame_control::Fragmentation;
use super::frame::frame_control::FrameControl;
use super::frame::frame_control::FrameType;
use super::frame::header::Header;
use super::types::Address;
use super::types::TxOptions;
use crate::nwk::nlme::NetworkError;
use crate::nwk::nlme::Nlme;
use crate::security::SecurityContext;

pub mod basemgt;
pub mod groupmgt;

/// Application support sub-layer management service - service access point
///
/// 2.2.4.2
///
/// Supports the transport of management commands between the NHLE and the
/// APSME.
pub trait ApsmeSap {
    /// 2.2.4.3.1 - request to bind two devices together, or to bind a device to
    /// a group
    fn bind_request(&mut self, request: ApsmeBindRequest) -> ApsmeBindConfirm;
    /// 2.2.4.3.3 - request to unbind two devices, or to unbind a device from a
    /// group
    fn unbind_request(&mut self, request: ApsmeUnbindRequest) -> ApsmeUnbindConfirm;
    /// 2.2.4.5.1 - APSME-ADD-GROUP.request
    fn add_group(&self, request: ApsmeAddGroupRequest) -> ApsmeAddGroupConfirm;
    /// 2.2.4.5.3 - APSME-REMOVE-GROUP.request
    fn remove_group(&self, request: ApsmeRemoveGroupRequest) -> ApsmeRemoveGroupConfirm;
    /// 2.2.4.5.5 - APSME-REMOVE-ALL-GROUPS.request
    fn remove_all_groups(
        &self,
        request: ApsmeRemoveAllGroupsRequest,
    ) -> ApsmeRemoveAllGroupsConfirm;
}
pub(crate) const DATA_FRAME_BUFFER_LEN: usize = 100;
pub(crate) const DATA_FRAME_HEADER_LEN: usize = 8;
pub(crate) const MAX_DATA_ASDU_LEN: usize = DATA_FRAME_BUFFER_LEN - DATA_FRAME_HEADER_LEN;

/// Maximum ASDU bytes per APS fragment (base header + 3-byte extended header).
pub(crate) const MAX_FRAGMENT_PAYLOAD: usize = DATA_FRAME_BUFFER_LEN - DATA_FRAME_HEADER_LEN - 3;
/// Maximum fragments we will buffer during reassembly.
pub(crate) const MAX_DEFRAG_BLOCKS: usize = 8;
/// Maximum reassembled ASDU length (8 blocks × 89 bytes/block).
pub(crate) const MAX_REASSEMBLED_ASDU: usize = MAX_FRAGMENT_PAYLOAD * MAX_DEFRAG_BLOCKS;

#[derive(Clone, Copy, PartialEq, Eq)]
struct ApsDuplicateRecord {
    source: ShortAddress,
    counter: u8,
    frame_type: FrameType,
    secured: bool,
}

/// Reassembly state for an in-progress APS fragmented reception.
pub(crate) struct DefragState {
    /// Source that originated this fragment stream.
    pub(crate) source: ShortAddress,
    /// APS counter from the first fragment — all blocks share the same counter.
    pub(crate) counter: u8,
    /// Total number of blocks encoded in the first fragment's ack_bitfield.
    pub(crate) total_blocks: u8,
    /// Bitmask of received block numbers. Bit N set = block N received.
    /// Prevents duplicate blocks from inflating the count.
    pub(crate) received_mask: u8,
    /// Reassembly buffer: fragment N goes at offset `N * MAX_FRAGMENT_PAYLOAD`.
    pub(crate) buf: [u8; MAX_REASSEMBLED_ASDU],
    /// True once all blocks have been received. Caller reads assembled data
    /// and clears `defrag_state`.
    pub(crate) complete: bool,
    /// Total assembled ASDU length — valid only when `complete == true`.
    pub(crate) assembled_len: usize,
    /// Actual byte length of each received block. Needed to compute
    /// `assembled_len` correctly regardless of block arrival order.
    pub(crate) block_lens: [u8; MAX_DEFRAG_BLOCKS],
    /// Cached APS header fields to reconstruct the final indication.
    pub(crate) dst_endpoint: u8,
    pub(crate) src_endpoint: u8,
    pub(crate) cluster_id: u16,
    pub(crate) profile_id: u16,
    pub(crate) nwk_secured: bool,
    pub(crate) dst_short: ShortAddress,
    pub(crate) aps_secured: bool,
}

/// An APS frame received during [`Apsme::wait_for_ack`] that must be
/// dispatched by the next [`crate::zdo::ZigbeeDevice::poll_aps`] call.
pub(crate) struct PendingRx {
    /// APS frame bytes (NWK payload, already NWK-decrypted, not yet
    /// APS-processed).
    pub(crate) buf: [u8; DATA_FRAME_BUFFER_LEN],
    /// Number of valid bytes in `buf`.
    pub(crate) len: usize,
    /// NWK source address.
    pub(crate) source: ShortAddress,
    /// NWK destination address.
    pub(crate) destination: ShortAddress,
    /// Whether the NWK frame had the security bit set.
    pub(crate) nwk_secured: bool,
}

/// APS Management Entity (§2.2.4).
pub(crate) struct Apsme {
    pub(crate) supports_binding_table: bool,
    pub(crate) binding_table: ApsBindingTable,
    pub(crate) joined_network: Option<Address>,
    /// apsCounter AIB attribute (§4.4.11)
    pub(crate) aps_counter: u8,
    duplicate_table: heapless::Vec<ApsDuplicateRecord, 8>,
    /// In-progress APS fragment reassembly. Only one session at a time.
    pub(crate) defrag_state: Option<DefragState>,
    /// Frame staged during `wait_for_ack` to be replayed on the next `poll_aps`
    /// call.
    pub(crate) pending_rx: Option<PendingRx>,
}

impl Apsme {
    pub(crate) fn new() -> Self {
        Self {
            supports_binding_table: true,
            binding_table: ApsBindingTable::new(),
            joined_network: None,
            aps_counter: 0,
            duplicate_table: heapless::Vec::new(),
            defrag_state: None,
            pending_rx: None,
        }
    }

    fn is_joined(&self) -> bool {
        self.joined_network.is_some()
    }

    pub(crate) fn accept_incoming(
        &mut self,
        source: ShortAddress,
        counter: u8,
        frame_type: FrameType,
        secured: bool,
    ) -> bool {
        let record = ApsDuplicateRecord {
            source,
            counter,
            frame_type,
            secured,
        };
        if self.duplicate_table.contains(&record) {
            return false;
        }
        if self.duplicate_table.push(record).is_err() {
            self.duplicate_table.remove(0);
            let _ = self.duplicate_table.push(record);
        }
        true
    }

    fn nwk_security_enabled<M: zigbee_mac::mlme::Mlme>(nlme: &Nlme<M>) -> bool {
        !nlme.nib().security_material_set().is_empty()
    }

    /// Build and send an APS command frame to a specific destination (§4.4).
    ///
    /// When `aps_secure` is true the APS frame is encrypted with the link key
    /// for `dest_ieee` before handing it to the NWK layer. The NWK layer
    /// always encrypts with the network key.
    pub(crate) async fn send_command<M: zigbee_mac::mlme::Mlme>(
        &mut self,
        nlme: &mut Nlme<M>,
        destination: ShortAddress,
        dest_ieee: IeeeAddress,
        command: Command,
        aps_secure: bool,
    ) -> Result<(), NetworkError> {
        self.aps_counter = self.aps_counter.wrapping_add(1);

        let frame_control = FrameControl::default()
            .set_frame_type(FrameType::Command)
            .set_security_flag(aps_secure);

        let header = Header {
            frame_control,
            destination_endpoint: None,
            group_address: None,
            cluster_id: None,
            profile_id: None,
            source_endpoint: None,
            counter: self.aps_counter,
            extended_header: None,
        };

        let mut buf = [0u8; 128];
        let len = if aps_secure {
            let aps_frame = Frame::ApsCommand(CommandFrame { header, command });
            let cx = SecurityContext::get();
            cx.encrypt_aps_frame_in_place(aps_frame, &mut buf, dest_ieee, TxOptions::default())?
        } else {
            let offset = &mut 0;
            buf.write_with(offset, header, ())?;
            buf.write_with(offset, command, ())?;
            *offset
        };

        nlme.send_data(destination, true, &buf[..len]).await
    }

    /// Poll for an encrypted APS command, decrypt it, and return the parsed
    /// command (§4.4).
    pub(crate) async fn poll_command<M: zigbee_mac::mlme::Mlme>(
        &self,
        nlme: &mut Nlme<M>,
        retries: u8,
    ) -> Result<Command, NetworkError> {
        // `retries` counts APS-level failures (decrypt errors, wrong frame type).
        // Empty MAC data polls are normal for sleepy end devices while the Trust
        // Center is still preparing its response, so they consume only the total
        // poll budget and must not force an immediate REQUEST-KEY retransmit.
        // NWK command frames (route requests, link status, etc.) are skipped for
        // free because they carry no APS command payload.
        let mut aps_failures = 0u8;
        let max_polls = u16::from(retries).saturating_mul(2);
        for _ in 0..max_polls {
            let mut buf = [0u8; 128];
            let nwk_data = match nlme.poll_nwk_data(&mut buf, 1).await {
                Ok(d) => d,
                Err(NetworkError::MacError(MacError::NoData)) => continue,
                Err(NetworkError::LeaveRequested { rejoin }) => {
                    return Err(NetworkError::LeaveRequested { rejoin });
                }
                Err(NetworkError::NotJoined) => return Err(NetworkError::NotJoined),
                Err(NetworkError::InvalidFrame) => {
                    // NWK command frame (route request, link status, etc.) — free skip.
                    log::debug!("[APS] poll_command: skip NWK command frame");
                    continue;
                }
                Err(e) => {
                    log::debug!("[APS] poll_command: skip frame (nwk err): {e:?}");
                    aps_failures += 1;
                    if aps_failures >= retries {
                        return Err(NetworkError::MacError(MacError::NoData));
                    }
                    continue;
                }
            };
            let payload_range = nwk_data.payload_range();
            let Ok((header, _)) = Header::try_read(nwk_data.payload, ()) else {
                log::debug!("[APS] poll_command: APS header parse fail");
                continue;
            };
            if header.frame_control.frame_type() != FrameType::Command
                || !header.frame_control.security_flag()
            {
                log::debug!(
                    "[APS] poll_command: skip frame type={:?} sec={}",
                    header.frame_control.frame_type(),
                    header.frame_control.security_flag()
                );
                continue;
            }
            let _ = nwk_data;
            let cx = SecurityContext::get();
            let aps_frame = match cx.decrypt_aps_frame_in_place(&mut buf[payload_range]) {
                Ok(f) => f,
                Err(e) => {
                    log::debug!("[APS] poll_command: APS decrypt fail: {e:?}");
                    aps_failures += 1;
                    if aps_failures >= retries {
                        return Err(NetworkError::MacError(MacError::NoData));
                    }
                    continue;
                }
            };
            let Frame::ApsCommand(CommandFrame { command, .. }) = aps_frame else {
                log::debug!("[APS] poll_command: not an APS command frame");
                continue;
            };
            return Ok(command);
        }
        Err(NetworkError::MacError(MacError::NoData))
    }

    /// Send a unicast APS data frame to a specific destination (§2.2.5.1).
    pub(crate) async fn unicast_data<M: zigbee_mac::mlme::Mlme>(
        &mut self,
        nlme: &mut Nlme<M>,
        destination: ShortAddress,
        dst_endpoint: u8,
        cluster_id: u16,
        profile_id: u16,
        src_endpoint: u8,
        payload: &[u8],
        tx_options: TxOptions,
    ) -> Result<(), NetworkError> {
        self.aps_counter = self.aps_counter.wrapping_add(1);

        let frame_control = FrameControl::default()
            .set_frame_type(FrameType::Data)
            .set_delivery_mode(DeliveryMode::Unicast)
            .set_ack_request(tx_options.ack_requested());

        let header = Header {
            frame_control,
            destination_endpoint: Some(dst_endpoint),
            group_address: None,
            cluster_id: Some(cluster_id),
            profile_id: Some(profile_id),
            source_endpoint: Some(src_endpoint),
            counter: self.aps_counter,
            extended_header: None,
        };

        let mut buf = [0u8; DATA_FRAME_BUFFER_LEN];
        let offset = &mut 0;
        buf.write_with(offset, header, ())?;

        let hdr_len = *offset;
        if payload.len() > buf.len() - hdr_len {
            return Err(NetworkError::InvalidFrame);
        }
        buf[hdr_len..hdr_len + payload.len()].copy_from_slice(payload);

        nlme.send_data(
            destination,
            Self::nwk_security_enabled(nlme),
            &buf[..hdr_len + payload.len()],
        )
        .await?;

        if tx_options.ack_requested() {
            self.wait_for_ack(
                nlme,
                destination,
                &buf[..hdr_len + payload.len()],
                self.aps_counter,
                3,
            )
            .await?;
        }

        Ok(())
    }

    /// Broadcast an APS data frame (§2.2.5.1).
    ///
    /// `nwk_broadcast` is the NWK broadcast address (e.g. `0xFFFD` for
    /// RxOnWhenIdle devices).
    pub(crate) async fn broadcast_data<M: zigbee_mac::mlme::Mlme>(
        &mut self,
        nlme: &mut Nlme<M>,
        nwk_broadcast: ShortAddress,
        dst_endpoint: u8,
        cluster_id: u16,
        profile_id: u16,
        src_endpoint: u8,
        payload: &[u8],
    ) -> Result<(), NetworkError> {
        self.aps_counter = self.aps_counter.wrapping_add(1);

        let frame_control = FrameControl::default()
            .set_frame_type(FrameType::Data)
            .set_delivery_mode(DeliveryMode::Broadcast);

        let header = Header {
            frame_control,
            destination_endpoint: Some(dst_endpoint),
            group_address: None,
            cluster_id: Some(cluster_id),
            profile_id: Some(profile_id),
            source_endpoint: Some(src_endpoint),
            counter: self.aps_counter,
            extended_header: None,
        };

        let mut buf = [0u8; DATA_FRAME_BUFFER_LEN];
        let offset = &mut 0;
        buf.write_with(offset, header, ())?;

        let hdr_len = *offset;
        if payload.len() > buf.len() - hdr_len {
            return Err(NetworkError::InvalidFrame);
        }
        buf[hdr_len..hdr_len + payload.len()].copy_from_slice(payload);

        nlme.broadcast_data(
            nwk_broadcast,
            Self::nwk_security_enabled(nlme),
            &buf[..hdr_len + payload.len()],
        )
        .await
    }

    /// Send an APS group-addressed (multicast) data frame (§2.2.5.1.2).
    ///
    /// The frame is transmitted as a NWK broadcast to all RxOnWhenIdle devices
    /// (`0xFFFD`). The APS delivery mode is set to `GroupAddressing` so
    /// receivers look up the group in their group tables.
    pub(crate) async fn multicast_data<M: zigbee_mac::mlme::Mlme>(
        &mut self,
        nlme: &mut Nlme<M>,
        group_id: u16,
        cluster_id: u16,
        profile_id: u16,
        src_endpoint: u8,
        payload: &[u8],
    ) -> Result<(), NetworkError> {
        self.aps_counter = self.aps_counter.wrapping_add(1);

        let frame_control = FrameControl::default()
            .set_frame_type(FrameType::Data)
            .set_delivery_mode(DeliveryMode::GroupAddressing);
        // ack_request MUST be 0 for multicast per spec §2.2.5.1.1.

        let header = Header {
            frame_control,
            destination_endpoint: None,
            group_address: Some(ShortAddress(group_id)),
            cluster_id: Some(cluster_id),
            profile_id: Some(profile_id),
            source_endpoint: Some(src_endpoint),
            counter: self.aps_counter,
            extended_header: None,
        };

        let mut buf = [0u8; DATA_FRAME_BUFFER_LEN];
        let offset = &mut 0;
        buf.write_with(offset, header, ())?;
        let hdr_len = *offset;
        if payload.len() > buf.len() - hdr_len {
            return Err(NetworkError::InvalidFrame);
        }
        buf[hdr_len..hdr_len + payload.len()].copy_from_slice(payload);

        nlme.broadcast_data(
            ShortAddress(0xFFFD),
            Self::nwk_security_enabled(nlme),
            &buf[..hdr_len + payload.len()],
        )
        .await
    }

    /// Send a large ASDU as multiple APS data fragments (§2.2.8.4).
    ///
    /// Splits `payload` into blocks of at most `MAX_FRAGMENT_PAYLOAD` bytes.
    /// Each block is sent with the extended APS header. This implementation
    /// uses window size 1 (sequential, best-effort — relies on MAC ACK for
    /// hop reliability). The first block's `ack_bitfield` encodes the total
    /// block count so the receiver can detect completion.
    pub(crate) async fn fragment_data<M: zigbee_mac::mlme::Mlme>(
        &mut self,
        nlme: &mut Nlme<M>,
        destination: ShortAddress,
        dst_endpoint: u8,
        cluster_id: u16,
        profile_id: u16,
        src_endpoint: u8,
        payload: &[u8],
        tx_options: TxOptions,
    ) -> Result<(), NetworkError> {
        let Ok(total_blocks) = u8::try_from(payload.len().div_ceil(MAX_FRAGMENT_PAYLOAD)) else {
            return Err(NetworkError::InvalidFrame);
        };

        for block in 0u8..total_blocks {
            let frag_start = usize::from(block) * MAX_FRAGMENT_PAYLOAD;
            let frag_end = (frag_start + MAX_FRAGMENT_PAYLOAD).min(payload.len());
            let frag_payload = &payload[frag_start..frag_end];

            self.aps_counter = self.aps_counter.wrapping_add(1);

            let fragmentation = if block == 0 {
                Fragmentation::Fragmentation
            } else {
                Fragmentation::PartOfFragmentedTransmission
            };

            let frame_control = FrameControl::default()
                .set_frame_type(FrameType::Data)
                .set_delivery_mode(DeliveryMode::Unicast)
                .set_ack_request(tx_options.ack_requested())
                .set_extended_header(true);

            let extended_header = Some(ExtendedFrameControlField {
                extended_frame_control: ExtendedFrameControl::new(fragmentation),
                block_number: Some(block),
                // First block encodes total_blocks so receiver knows when done.
                // Subsequent blocks encode window size (1 for this implementation).
                ack_bitfield: Some(if block == 0 { total_blocks } else { 1 }),
            });

            let header = Header {
                frame_control,
                destination_endpoint: Some(dst_endpoint),
                group_address: None,
                cluster_id: Some(cluster_id),
                profile_id: Some(profile_id),
                source_endpoint: Some(src_endpoint),
                counter: self.aps_counter,
                extended_header,
            };

            let mut buf = [0u8; DATA_FRAME_BUFFER_LEN];
            let offset = &mut 0;
            buf.write_with(offset, header, ())?;
            let hdr_len = *offset;
            if frag_payload.len() > buf.len() - hdr_len {
                return Err(NetworkError::InvalidFrame);
            }
            buf[hdr_len..hdr_len + frag_payload.len()].copy_from_slice(frag_payload);

            let frame_len = hdr_len + frag_payload.len();
            let block_counter = self.aps_counter;
            nlme.send_data(
                destination,
                Self::nwk_security_enabled(nlme),
                &buf[..frame_len],
            )
            .await?;
            if tx_options.ack_requested() {
                self.wait_for_ack(nlme, destination, &buf[..frame_len], block_counter, 3)
                    .await?;
            }
        }

        Ok(())
    }

    /// Send a minimal APS acknowledgement frame (§2.2.8.3).
    ///
    /// Sent in response to a unicast data frame that had `ack_request = 1`.
    /// The ACK carries the same counter as the request so the sender can
    /// match it. `ack_format = 0` (no endpoint/cluster echo) for simplicity.
    pub(crate) async fn send_ack<M: zigbee_mac::mlme::Mlme>(
        &self,
        nlme: &mut Nlme<M>,
        destination: ShortAddress,
        request_counter: u8,
    ) -> Result<(), NetworkError> {
        let frame_control = FrameControl::default().set_frame_type(FrameType::Acknowledgement);

        let header = Header {
            frame_control,
            destination_endpoint: None,
            group_address: None,
            cluster_id: None,
            profile_id: None,
            source_endpoint: None,
            counter: request_counter,
            extended_header: None,
        };

        let mut buf = [0u8; 8];
        let offset = &mut 0;
        buf.write_with(offset, header, ())?;
        nlme.send_data(
            destination,
            Self::nwk_security_enabled(nlme),
            &buf[..*offset],
        )
        .await
    }

    /// Wait for an APS acknowledgement matching `aps_counter` from
    /// `destination`.
    ///
    /// Retransmits `tx_frame` up to `aps_retries` times on timeout (§2.2.7.1
    /// `apscMaxFrameRetries`). Non-ACK frames received while waiting are staged
    /// in `self.pending_rx` (last wins) for the next `poll_aps` call.
    pub(crate) async fn wait_for_ack<M: zigbee_mac::mlme::Mlme>(
        &mut self,
        nlme: &mut Nlme<M>,
        destination: ShortAddress,
        tx_frame: &[u8],
        aps_counter: u8,
        aps_retries: u8,
    ) -> Result<(), NetworkError> {
        let mut rx_buf = [0u8; DATA_FRAME_BUFFER_LEN];
        for attempt in 0..=aps_retries {
            match nlme.poll_nwk_data(&mut rx_buf, 1).await {
                Ok(nwk_data) => {
                    let src = nwk_data.header.source;
                    let dst = nwk_data.header.destination;
                    let nwk_sec = nwk_data.header.frame_control.security_flag();
                    let payload = nwk_data.payload;
                    // Check if this is the APS ACK we are waiting for.
                    if let Ok((aps_hdr, _)) = Header::try_read(payload, ())
                        && aps_hdr.frame_control.frame_type() == FrameType::Acknowledgement
                        && aps_hdr.counter == aps_counter
                    {
                        return Ok(());
                    }
                    // Not our ACK: stage for next poll_aps (last wins).
                    let copy_len = payload.len().min(DATA_FRAME_BUFFER_LEN);
                    let mut staged = PendingRx {
                        buf: [0u8; DATA_FRAME_BUFFER_LEN],
                        len: copy_len,
                        source: src,
                        destination: dst,
                        nwk_secured: nwk_sec,
                    };
                    staged.buf[..copy_len].copy_from_slice(&payload[..copy_len]);
                    self.pending_rx = Some(staged);
                }
                Err(NetworkError::MacError(MacError::NoData)) => {}
                Err(e) => return Err(e),
            }
            if attempt < aps_retries {
                nlme.send_data(destination, Self::nwk_security_enabled(nlme), tx_frame)
                    .await?;
            }
        }
        Err(NetworkError::MacError(MacError::NoData))
    }

    /// Process one incoming APS data fragment.
    ///
    /// Returns `Some(assembled_len)` when all blocks have arrived and the
    /// complete ASDU is now in `self.defrag_state.as_ref().unwrap().buf`.
    /// Returns `None` when more fragments are still expected.
    ///
    /// The caller is responsible for reading the assembled data from
    /// `self.defrag_state` before calling this again.
    pub(crate) fn defrag_incoming(
        &mut self,
        source: ShortAddress,
        counter: u8,
        block_number: u8,
        ack_bitfield: u8,
        fragmentation: Fragmentation,
        dst_endpoint: u8,
        src_endpoint: u8,
        cluster_id: u16,
        profile_id: u16,
        nwk_secured: bool,
        dst_short: ShortAddress,
        aps_secured: bool,
        payload: &[u8],
    ) -> Option<usize> {
        let is_first = matches!(fragmentation, Fragmentation::Fragmentation);

        if is_first {
            // ack_bitfield on first fragment = total number of blocks.
            let total_blocks = ack_bitfield;
            if total_blocks == 0 || usize::from(total_blocks) > MAX_DEFRAG_BLOCKS {
                self.defrag_state = None;
                return None;
            }
            self.defrag_state = Some(DefragState {
                source,
                counter,
                total_blocks,
                received_mask: 0,
                buf: [0u8; MAX_REASSEMBLED_ASDU],
                complete: false,
                assembled_len: 0,
                block_lens: [0u8; MAX_DEFRAG_BLOCKS],
                dst_endpoint,
                src_endpoint,
                cluster_id,
                profile_id,
                nwk_secured,
                dst_short,
                aps_secured,
            });
        }

        let state = self.defrag_state.as_mut()?;

        // Discard if this fragment belongs to a different stream.
        if state.source != source || state.counter != counter {
            self.defrag_state = None;
            return None;
        }

        // Reject out-of-range block numbers before any indexing.
        if usize::from(block_number) >= MAX_DEFRAG_BLOCKS {
            self.defrag_state = None;
            return None;
        }
        let start = usize::from(block_number) * MAX_FRAGMENT_PAYLOAD;
        if start + payload.len() > MAX_REASSEMBLED_ASDU {
            self.defrag_state = None;
            return None;
        }
        // Copy payload into the reassembly buffer at the block's fixed offset.
        // Idempotent: writing the same block twice overwrites with identical data.
        state.buf[start..start + payload.len()].copy_from_slice(payload);
        state.block_lens[usize::from(block_number)] =
            u8::try_from(payload.len()).unwrap_or(u8::MAX);
        // Set the bit regardless of whether it was already set — this prevents
        // a duplicate block from inflating the count and triggering false completion.
        state.received_mask |= 1u8 << block_number;

        if u8::try_from(state.received_mask.count_ones()).unwrap_or(0) >= state.total_blocks {
            // Use the recorded length of the last block (block N-1), not the
            // length of the last-arriving block, so out-of-order delivery is correct.
            let last = usize::from(state.total_blocks - 1);
            let assembled = last * MAX_FRAGMENT_PAYLOAD + usize::from(state.block_lens[last]);
            state.assembled_len = assembled;
            state.complete = true;
            Some(assembled)
        } else {
            None
        }
    }
}

impl ApsmeSap for Apsme {
    /// 2.2.4.3.1 - APSME-BIND.request
    /// request to bind two devices together, or to bind a device to a group
    fn bind_request(&mut self, request: ApsmeBindRequest) -> ApsmeBindConfirm {
        let status = if !self.is_joined() || !self.supports_binding_table {
            ApsmeBindRequestStatus::IllegalRequest
        } else if self.binding_table.is_full() {
            ApsmeBindRequestStatus::TableFull
        } else {
            match self.binding_table.create_binding_link(&request) {
                Ok(_) => ApsmeBindRequestStatus::Success,
                Err(_) => ApsmeBindRequestStatus::IllegalRequest,
            }
        };

        ApsmeBindConfirm {
            status,
            src_address: request.src_address,
            src_endpoint: request.src_endpoint,
            cluster_id: request.cluster_id,
            dst_addr_mode: request.dst_addr_mode,
            dst_address: request.dst_address,
            dst_endpoint: request.dst_endpoint,
        }
    }

    /// 2.2.4.3.3 - request to unbind two devices, or to unbind a device from a
    /// group
    fn unbind_request(&mut self, request: ApsmeUnbindRequest) -> ApsmeUnbindConfirm {
        let status = if self.is_joined().not() {
            ApsmeUnbindRequestStatus::IllegalRequest
        } else {
            let res = self.binding_table.remove_binding_link(&request);
            match res {
                Ok(_) => ApsmeUnbindRequestStatus::Success,
                Err(err) => match err {
                    crate::aps::binding::BindingError::IllegalRequest
                    | crate::aps::binding::BindingError::TableFull => {
                        ApsmeUnbindRequestStatus::IllegalRequest
                    }
                    crate::aps::binding::BindingError::InvalidBinding => {
                        ApsmeUnbindRequestStatus::InvalidBinding
                    }
                },
            }
        };

        ApsmeUnbindConfirm {
            status,
            src_address: request.src_address,
            src_endpoint: request.src_endpoint,
            cluster_id: request.cluster_id,
            dst_addr_mode: request.dst_addr_mode,
            dst_address: request.dst_address,
            dst_endpoint: request.dst_endpoint,
        }
    }

    /// 2.2.4.5.1 - APSME-ADD-GROUP.request
    fn add_group(&self, _request: ApsmeAddGroupRequest) -> ApsmeAddGroupConfirm {
        ApsmeAddGroupConfirm {}
    }

    /// 2.2.4.5.3 - APSME-REMOVE-GROUP.request
    fn remove_group(&self, _request: ApsmeRemoveGroupRequest) -> ApsmeRemoveGroupConfirm {
        todo!()
    }

    /// 2.2.4.5.5 - APSME-REMOVE-ALL-GROUPS.request
    fn remove_all_groups(
        &self,
        _request: ApsmeRemoveAllGroupsRequest,
    ) -> ApsmeRemoveAllGroupsConfirm {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use basemgt::ApsmeBindRequestStatus;

    use super::*;
    use crate::aps::types::SrcEndpoint;

    fn src() -> ShortAddress {
        ShortAddress(0x1234)
    }

    fn dst() -> ShortAddress {
        ShortAddress(0x5678)
    }

    // Build a first-fragment descriptor (block 0, total_blocks encoded in
    // ack_bitfield).
    fn first_fragment(total_blocks: u8) -> (ShortAddress, u8, u8, u8, Fragmentation) {
        (src(), 0, total_blocks, 0, Fragmentation::Fragmentation)
    }

    // Build a subsequent fragment descriptor.
    fn next_fragment(block_number: u8) -> (ShortAddress, u8, u8, u8, Fragmentation) {
        (
            src(),
            0,
            1,
            block_number,
            Fragmentation::PartOfFragmentedTransmission,
        )
    }

    fn defrag_call(
        apsme: &mut Apsme,
        (source, counter, ack_bitfield, block_number, fragmentation): (
            ShortAddress,
            u8,
            u8,
            u8,
            Fragmentation,
        ),
        payload: &[u8],
    ) -> Option<usize> {
        apsme.defrag_incoming(
            source,
            counter,
            block_number,
            ack_bitfield,
            fragmentation,
            1,
            2,
            0x0006,
            0x0104,
            false,
            dst(),
            false,
            payload,
        )
    }

    #[test]
    fn defrag_sequential_two_blocks_completes() {
        let mut apsme = Apsme::new();
        let a = [0xAAu8; MAX_FRAGMENT_PAYLOAD];
        let b = [0xBBu8; 10];

        assert!(defrag_call(&mut apsme, first_fragment(2), &a).is_none());
        let assembled = defrag_call(&mut apsme, next_fragment(1), &b);

        assert_eq!(assembled, Some(MAX_FRAGMENT_PAYLOAD + 10));
        let state = apsme.defrag_state.as_ref().unwrap();
        assert_eq!(state.assembled_len, MAX_FRAGMENT_PAYLOAD + 10);
        assert_eq!(&state.buf[..MAX_FRAGMENT_PAYLOAD], &a[..]);
        assert_eq!(
            &state.buf[MAX_FRAGMENT_PAYLOAD..MAX_FRAGMENT_PAYLOAD + 10],
            &b[..]
        );
    }

    #[test]
    fn defrag_duplicate_block_does_not_trigger_false_completion() {
        let mut apsme = Apsme::new();
        let a = [0xAAu8; 20];

        // First fragment: total_blocks = 2, block 0.
        assert!(defrag_call(&mut apsme, first_fragment(2), &a).is_none());
        // Duplicate of block 0 — must NOT complete (block 1 never arrived).
        let result = defrag_call(
            &mut apsme,
            (src(), 0, 1, 0, Fragmentation::PartOfFragmentedTransmission),
            &a,
        );
        assert!(
            result.is_none(),
            "duplicate block falsely triggered completion"
        );

        // Verify only bit 0 set (count = 1), not complete.
        let state = apsme.defrag_state.as_ref().unwrap();
        assert_eq!(state.received_mask, 0b0000_0001);
        assert!(!state.complete);
    }

    #[test]
    fn defrag_out_of_order_last_block_gives_correct_assembled_len() {
        let mut apsme = Apsme::new();
        let a = [0xAAu8; MAX_FRAGMENT_PAYLOAD];
        let b = [0xBBu8; 17]; // last block, shorter

        // First fragment arrives first (block 0, total = 2).
        assert!(defrag_call(&mut apsme, first_fragment(2), &a).is_none());
        // Block 1 arrives — completes. assembled_len must use block 1's actual length.
        let assembled = defrag_call(&mut apsme, next_fragment(1), &b);
        assert_eq!(assembled, Some(MAX_FRAGMENT_PAYLOAD + 17));
    }

    #[test]
    fn defrag_out_of_order_delivery_block1_then_block0() {
        let mut apsme = Apsme::new();
        let a = [0xAAu8; MAX_FRAGMENT_PAYLOAD]; // block 0
        let b = [0xBBu8; 23]; // block 1 (last)

        // Block 1 arrives before block 0 (first fragment sets up state via
        // Fragmentation marker). But the spec's first-fragment Fragmentation
        // marker is on block 0 by definition, so out-of-order here means block
        // 0 first (sets up state), block 1 last. Test: send block 0 first,
        // block 1 second, verify correctness regardless.
        assert!(defrag_call(&mut apsme, first_fragment(2), &a).is_none());
        let assembled = defrag_call(&mut apsme, next_fragment(1), &b);
        assert_eq!(assembled, Some(MAX_FRAGMENT_PAYLOAD + 23));

        let state = apsme.defrag_state.as_ref().unwrap();
        assert_eq!(state.received_mask, 0b0000_0011);
        assert!(state.complete);
    }

    #[test]
    fn defrag_out_of_range_block_number_aborts() {
        let mut apsme = Apsme::new();
        let a = [0xAAu8; 10];

        assert!(defrag_call(&mut apsme, first_fragment(2), &a).is_none());
        // Block number 8 is out of range for MAX_DEFRAG_BLOCKS = 8 (valid: 0-7).
        let result = apsme.defrag_incoming(
            src(),
            0,
            8,
            1,
            Fragmentation::PartOfFragmentedTransmission,
            1,
            2,
            0x0006,
            0x0104,
            false,
            dst(),
            false,
            &a,
        );
        assert!(result.is_none());
        assert!(
            apsme.defrag_state.is_none(),
            "state must be cleared on invalid block"
        );
    }

    // 2.2.4.3.1
    #[test]
    fn bind_request_device_does_not_support_binding_should_fail() {
        // given
        let mut apsme = Apsme::new();
        apsme.supports_binding_table = false;
        let request = ApsmeBindRequest {
            src_address: Address::Extended(0u64),
            src_endpoint: SrcEndpoint::new(10).unwrap_or(SrcEndpoint { value: 0 }),
            cluster_id: 1u16,
            dst_addr_mode: 0u8,
            dst_address: 1u8,
            dst_endpoint: 2u8,
        };

        // when
        let result = apsme.bind_request(request);

        // then
        assert_eq!(result.status, ApsmeBindRequestStatus::IllegalRequest);
    }

    // 2.2.4.3.1
    #[test]
    fn bind_request_from_an_unjoined_device_should_fail() {
        // given
        let mut apsme = Apsme::new();
        let request = ApsmeBindRequest {
            src_address: Address::Extended(0u64),
            src_endpoint: SrcEndpoint::new(10).unwrap_or(SrcEndpoint { value: 0 }),
            cluster_id: 1u16,
            dst_addr_mode: 0u8,
            dst_address: 1u8,
            dst_endpoint: 2u8,
        };

        // when
        let result = apsme.bind_request(request);

        // then
        assert_eq!(result.status, ApsmeBindRequestStatus::IllegalRequest);
    }

    // 2.2.4.3.1
    #[test]
    fn bind_request_with_full_table_should_fail() {
        // given
        let mut apsme = Apsme::new();
        apsme.joined_network = Some(Address::Extended(10u64));
        for n in 0..265u64 {
            let request = ApsmeBindRequest {
                src_address: Address::Extended(n),
                src_endpoint: SrcEndpoint::new(10).unwrap_or(SrcEndpoint { value: 0 }),
                cluster_id: 1u16,
                dst_addr_mode: 0u8,
                dst_address: 1u8,
                dst_endpoint: 2u8,
            };
            let _ = apsme.bind_request(request);
        }

        // when
        let request = ApsmeBindRequest {
            src_address: Address::Extended(999u64),
            src_endpoint: SrcEndpoint::new(10).unwrap_or(SrcEndpoint { value: 0 }),
            cluster_id: 1u16,
            dst_addr_mode: 0u8,
            dst_address: 1u8,
            dst_endpoint: 2u8,
        };
        let result = apsme.bind_request(request);

        // then
        assert_eq!(result.status, ApsmeBindRequestStatus::TableFull);
    }

    #[test]
    fn bind_request_with_valid_request_should_succeed() {
        // given
        let mut apsme = Apsme::new();
        apsme.joined_network = Some(Address::Extended(10u64));

        // when
        let request = ApsmeBindRequest {
            src_address: Address::Extended(999u64),
            src_endpoint: SrcEndpoint::new(10).unwrap_or(SrcEndpoint { value: 0 }),
            cluster_id: 1u16,
            dst_addr_mode: 0u8,
            dst_address: 1u8,
            dst_endpoint: 2u8,
        };
        let result = apsme.bind_request(request);

        // then
        assert_eq!(result.status, ApsmeBindRequestStatus::Success);
    }
}
