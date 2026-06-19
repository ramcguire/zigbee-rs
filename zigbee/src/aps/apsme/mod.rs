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
use zigbee_types::IeeeAddress;
use zigbee_types::ShortAddress;

use super::binding::ApsBindingTable;
use super::frame::CommandFrame;
use super::frame::Frame;
use super::frame::command::Command;
use super::frame::frame_control::DeliveryMode;
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

#[derive(Clone, Copy, PartialEq, Eq)]
struct ApsDuplicateRecord {
    source: ShortAddress,
    counter: u8,
    frame_type: FrameType,
    secured: bool,
}

/// APS Management Entity (§2.2.4).
pub(crate) struct Apsme {
    pub(crate) supports_binding_table: bool,
    pub(crate) binding_table: ApsBindingTable,
    pub(crate) joined_network: Option<Address>,
    /// apsCounter AIB attribute (§4.4.11)
    pub(crate) aps_counter: u8,
    duplicate_table: heapless::Vec<ApsDuplicateRecord, 8>,
}

impl Apsme {
    pub(crate) fn new() -> Self {
        Self {
            supports_binding_table: true,
            binding_table: ApsBindingTable::new(),
            joined_network: None,
            aps_counter: 0,
            duplicate_table: heapless::Vec::new(),
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
        if self.duplicate_table.iter().any(|entry| *entry == record) {
            return false;
        }
        if self.duplicate_table.push(record).is_err() {
            self.duplicate_table.remove(0);
            let _ = self.duplicate_table.push(record);
        }
        true
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
        let mut buf = [0u8; 128];
        let nwk_data = nlme.poll_nwk_data(&mut buf, retries).await?;
        let payload_range = nwk_data.payload_range();
        let (header, _) = Header::try_read(nwk_data.payload, ())?;
        if header.frame_control.frame_type() != FrameType::Command
            || !header.frame_control.security_flag()
        {
            return Err(NetworkError::ParseError);
        }
        drop(nwk_data);
        let cx = SecurityContext::get();
        let aps_frame = cx.decrypt_aps_frame_in_place(&mut buf[payload_range])?;

        let Frame::ApsCommand(CommandFrame { command, .. }) = aps_frame else {
            return Err(NetworkError::ParseError);
        };

        Ok(command)
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

        nlme.send_data(destination, false, &buf[..hdr_len + payload.len()])
            .await
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

        nlme.broadcast_data(nwk_broadcast, false, &buf[..hdr_len + payload.len()])
            .await
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
