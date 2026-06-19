use byte::TryRead;
use config::Config;
use zigbee_types::IeeeAddress;
use zigbee_types::ShortAddress;

pub mod config;
pub mod device_annce;
pub mod discovery;
use zigbee_types::StorageVec;

use crate::apl::descriptors::node_descriptor::LogicalType;
use crate::aps::aib;
use crate::aps::aib::DeviceKeyPairDescriptor;
use crate::aps::aib::KeyAttribute;
use crate::aps::aib::LinkKeyType;
use crate::aps::apsde::ApsDeliveryMode;
use crate::aps::apsde::Apsde;
use crate::aps::apsde::ApsdeSapConfirmStatus;
use crate::aps::apsde::ApsdeSapIndication;
use crate::aps::apsde::ApsdeSapIndicationStatus;
use crate::aps::apsde::ApsdeSapRequest;
use crate::aps::apsde::SecurityStatus;
use crate::aps::apsde::data_frame_to_indication;
use crate::aps::apsde::parse_data_indication_parts;
use crate::aps::apsme::Apsme;
use crate::aps::frame::CommandFrame;
use crate::aps::frame::Frame;
use crate::aps::frame::command::Command;
use crate::aps::frame::command::TransportKey;
use crate::aps::frame::frame_control::DeliveryMode;
use crate::aps::frame::frame_control::Fragmentation;
use crate::aps::frame::frame_control::FrameType;
use crate::aps::frame::header::Header;
use crate::aps::types::Address;
use crate::aps::types::DstAddrMode;
use crate::aps::types::SrcAddrMode;
use crate::aps::types::SrcEndpoint;
use crate::nwk::nib;
use crate::nwk::nib::NetworkSecurityMaterialDescriptor;
use crate::nwk::nlme::NetworkError;
use crate::nwk::nlme::Nlme;
use crate::security::SecurityContext;
use crate::zdp::client_services::discovery as zdp_discovery;

/// Provides an interface between the application object, the device profile and
/// the APS.
pub struct ZigbeeDevice {
    config: Config,
    apsme: Apsme,
    /// ZDP transaction sequence number (§2.4.2), independent of the APS
    /// counter.
    zdp_seq: u8,
}

/// zigbee network
pub struct ZigBeeNetwork {}

/// One APS frame received by the ZDO ingress path.
pub enum ZigbeeDevicePoll<'a> {
    Data(ApsdeSapIndication<'a>),
    Command(Command),
    /// Received an APS ACK frame — informational, no application action needed.
    Ack,
    /// Received an APS data fragment; more fragments expected.
    FragmentDeferred,
    /// All fragments of an APS fragmented transmission have been received.
    /// Call [`ZigbeeDevice::take_defrag_indication`] to retrieve the assembled
    /// ASDU.
    FragmentComplete,
}

impl ZigbeeDevice {
    /// Creates a new instance.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            apsme: Apsme::new(),
            zdp_seq: 0,
        }
    }

    /// Configures the device.
    pub fn configure(&self, _config: Config) {}

    /// Indicates if the device is connected to a zigbee network.
    pub fn is_connected(&self) -> bool {
        false // TODO: check connection state
    }

    pub fn logical_type(&self) -> LogicalType {
        self.config.device_type
    }

    pub fn send_keep_alive(&self) {}

    pub fn send_data(&self, _input: &[u8]) {}
    fn next_zdp_seq(&mut self) -> u8 {
        self.zdp_seq = self.zdp_seq.wrapping_add(1);
        self.zdp_seq
    }

    /// Device discovery is exposed as explicit non-blocking ZDP request sends.
    ///
    /// Use [`Self::send_nwk_addr_req`] or [`Self::send_ieee_addr_req`] and poll
    /// for the corresponding response in the BDB event loop.
    pub fn start_device_discovery(&self) {}

    /// 2.1.3.2 - Service Discovery
    /// is the process whereby the capabilities of a given device are discovered
    /// by other devices.
    pub fn start_service_discovery(&self) {}

    pub async fn send_nwk_addr_req<M: zigbee_mac::mlme::Mlme>(
        &mut self,
        nlme: &mut Nlme<M>,
        request: zdp_discovery::NWKAddrReq,
    ) -> Result<(), NetworkError> {
        let zdp_seq = self.next_zdp_seq();
        discovery::send_nwk_addr_req(nlme, &mut self.apsme, zdp_seq, request).await
    }

    pub async fn send_ieee_addr_req<M: zigbee_mac::mlme::Mlme>(
        &mut self,
        nlme: &mut Nlme<M>,
        destination: ShortAddress,
        request: zdp_discovery::IeeeAddrReq,
    ) -> Result<(), NetworkError> {
        let zdp_seq = self.next_zdp_seq();
        discovery::send_ieee_addr_req(nlme, &mut self.apsme, zdp_seq, destination, request).await
    }

    pub async fn send_node_desc_req<M: zigbee_mac::mlme::Mlme>(
        &mut self,
        nlme: &mut Nlme<M>,
        destination: ShortAddress,
        request: zdp_discovery::NodeDescReq,
    ) -> Result<(), NetworkError> {
        let zdp_seq = self.next_zdp_seq();
        discovery::send_node_desc_req(nlme, &mut self.apsme, zdp_seq, destination, request).await
    }

    pub async fn send_simple_desc_req<M: zigbee_mac::mlme::Mlme>(
        &mut self,
        nlme: &mut Nlme<M>,
        destination: ShortAddress,
        request: zdp_discovery::SimpleDescReq,
    ) -> Result<(), NetworkError> {
        let zdp_seq = self.next_zdp_seq();
        discovery::send_simple_desc_req(nlme, &mut self.apsme, zdp_seq, destination, request).await
    }

    pub async fn send_active_ep_req<M: zigbee_mac::mlme::Mlme>(
        &mut self,
        nlme: &mut Nlme<M>,
        destination: ShortAddress,
        request: zdp_discovery::ActiveEpReq,
    ) -> Result<(), NetworkError> {
        let zdp_seq = self.next_zdp_seq();
        discovery::send_active_ep_req(nlme, &mut self.apsme, zdp_seq, destination, request).await
    }

    pub async fn send_match_desc_req<M: zigbee_mac::mlme::Mlme>(
        &mut self,
        nlme: &mut Nlme<M>,
        destination: ShortAddress,
        request: &zdp_discovery::MatchDescReq,
    ) -> Result<(), NetworkError> {
        let zdp_seq = self.next_zdp_seq();
        discovery::send_match_desc_req(nlme, &mut self.apsme, zdp_seq, destination, request).await
    }

    /// Broadcast a ZDO Device_annce (§2.4.3.1.11).
    pub async fn device_annce<M: zigbee_mac::mlme::Mlme>(
        &mut self,
        nlme: &mut Nlme<M>,
        annce: device_annce::DeviceAnnce,
    ) -> Result<(), NetworkError> {
        let zdp_seq = self.next_zdp_seq();
        device_annce::broadcast(nlme, &mut self.apsme, zdp_seq, annce).await
    }

    /// Send an un-fragmented APS data frame through this device's APSDE state.
    pub async fn send_aps_data<M: zigbee_mac::mlme::Mlme>(
        &mut self,
        nlme: &mut Nlme<M>,
        destination: ShortAddress,
        dst_endpoint: u8,
        profile_id: u16,
        cluster_id: u16,
        src_endpoint: u8,
        asdu: &[u8],
    ) -> Result<(), NetworkError> {
        let src_endpoint =
            SrcEndpoint::new(src_endpoint).map_err(|_| NetworkError::InvalidFrame)?;
        let request = ApsdeSapRequest::new_unicast(
            destination,
            dst_endpoint,
            profile_id,
            cluster_id,
            src_endpoint,
            asdu,
        );
        let confirm = Apsde::data_request(&mut self.apsme, nlme, request).await;
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

    /// Poll one APS frame without losing command/data frames to the wrong
    /// parser.
    #[allow(clippy::too_many_lines)]
    pub async fn poll_aps<'a, M: zigbee_mac::mlme::Mlme>(
        &mut self,
        nlme: &mut Nlme<M>,
        buf: &'a mut [u8],
        retries: u8,
    ) -> Result<ZigbeeDevicePoll<'a>, NetworkError> {
        let buf_ptr = buf.as_mut_ptr();

        // Drain any frame staged during wait_for_ack before polling for new data.
        let (source, destination, nwk_secured, aps_start, aps_len) =
            if let Some(pending) = self.apsme.pending_rx.take() {
                let len = pending.len.min(buf.len());
                buf[..len].copy_from_slice(&pending.buf[..len]);
                (
                    pending.source,
                    pending.destination,
                    pending.nwk_secured,
                    0usize,
                    len,
                )
            } else {
                let nwk_data = nlme.poll_nwk_data(buf, retries).await?;
                let payload_range = nwk_data.payload_range();
                let src = nwk_data.header.source;
                let dst = nwk_data.header.destination;
                let sec = nwk_data.header.frame_control.security_flag();
                let start = payload_range.start;
                let len = payload_range.len();
                let _ = nwk_data;
                (src, dst, sec, start, len)
            };

        // Parse just the APS frame type and security flag from a scoped shared
        // reference so the borrow ends before any in-place mutation below.
        // Also extract all extended-header fields needed for the unsecured path
        // so that we never need to re-borrow buf after this block.
        let (frame_type, aps_secured_flag, hdr_len, counter, ack_request, delivery_mode, ext_frag) = {
            // SAFETY: all borrows into buf ended above (nwk_data dropped;
            // pending_rx copy completed). buf_ptr was captured before any borrow.
            let frame_ro: &[u8] =
                unsafe { core::slice::from_raw_parts(buf_ptr.add(aps_start), aps_len) };
            let (header, h) = Header::try_read(frame_ro, ())?;
            let ft = header.frame_control.frame_type();
            let sec = header.frame_control.security_flag();
            let ctr = header.counter;
            let ack = header.frame_control.ack_request();
            let dm = header.frame_control.delivery_mode();
            let ext: Option<(u8, u8, Fragmentation, u8, u8, u16, u16)> =
                header.extended_header.as_ref().and_then(|ext| {
                    if ext.extended_frame_control.is_fragmented() {
                        Some((
                            ext.block_number.unwrap_or(0),
                            ext.ack_bitfield.unwrap_or(0),
                            ext.extended_frame_control.fragmentation(),
                            header.destination_endpoint.unwrap_or(0),
                            header.source_endpoint.unwrap_or(0),
                            header.cluster_id.unwrap_or(0),
                            header.profile_id.unwrap_or(0),
                        ))
                    } else {
                        None
                    }
                });
            (ft, sec, h, ctr, ack, dm, ext)
            // frame_ro and header dropped here — no active borrows on buf
        };

        match frame_type {
            FrameType::Data => {
                if aps_secured_flag {
                    // SAFETY: scoped block above dropped all shared borrows into buf.
                    // buf_ptr was captured before any borrow and points into memory
                    // valid for 'a.
                    let aps_buf =
                        unsafe { core::slice::from_raw_parts_mut(buf_ptr.add(aps_start), aps_len) };
                    let frame = SecurityContext::get().decrypt_aps_frame_in_place(aps_buf)?;
                    let Frame::Data(data) = frame else {
                        return Err(NetworkError::InvalidFrame);
                    };
                    if !self.apsme.accept_incoming(
                        source,
                        data.header.counter,
                        FrameType::Data,
                        true,
                    ) {
                        return Err(NetworkError::InvalidFrame);
                    }

                    if data.header.frame_control.ack_request()
                        && data.header.frame_control.delivery_mode() == DeliveryMode::Unicast
                    {
                        let _ = self.apsme.send_ack(nlme, source, data.header.counter).await;
                    }

                    // Fragment reassembly path (APS-secured).
                    if let Some(ref ext_hdr) = data.header.extended_header
                        && ext_hdr.extended_frame_control.is_fragmented()
                    {
                        let block_number = ext_hdr.block_number.unwrap_or(0);
                        let ack_bitfield = ext_hdr.ack_bitfield.unwrap_or(0);
                        let fragmentation = ext_hdr.extended_frame_control.fragmentation();
                        let dst_ep = data.header.destination_endpoint.unwrap_or(0);
                        let src_ep = data.header.source_endpoint.unwrap_or(0);
                        let cluster_id = data.header.cluster_id.unwrap_or(0);
                        let profile_id = data.header.profile_id.unwrap_or(0);
                        let ctr = data.header.counter;
                        let mut frag_local = [0u8; crate::aps::apsme::MAX_FRAGMENT_PAYLOAD];
                        let copy_len = data
                            .payload
                            .len()
                            .min(crate::aps::apsme::MAX_FRAGMENT_PAYLOAD);
                        frag_local[..copy_len].copy_from_slice(&data.payload[..copy_len]);
                        let _ = data;
                        let assembled = self.apsme.defrag_incoming(
                            source,
                            ctr,
                            block_number,
                            ack_bitfield,
                            fragmentation,
                            dst_ep,
                            src_ep,
                            cluster_id,
                            profile_id,
                            nwk_secured,
                            destination,
                            true,
                            &frag_local[..copy_len],
                        );
                        return Ok(if assembled.is_some() {
                            ZigbeeDevicePoll::FragmentComplete
                        } else {
                            ZigbeeDevicePoll::FragmentDeferred
                        });
                    }

                    Ok(ZigbeeDevicePoll::Data(data_frame_to_indication(
                        source,
                        destination,
                        nwk_secured,
                        &data,
                    )?))
                } else {
                    if !self
                        .apsme
                        .accept_incoming(source, counter, FrameType::Data, false)
                    {
                        return Err(NetworkError::InvalidFrame);
                    }

                    if ack_request && delivery_mode == DeliveryMode::Unicast {
                        let _ = self.apsme.send_ack(nlme, source, counter).await;
                    }

                    // Fragment reassembly path (unsecured). All APS header fields
                    // were extracted above before any borrow of buf ended, so we
                    // can safely re-borrow a subslice for the payload copy.
                    if let Some((
                        block_number,
                        ack_bitfield,
                        fragmentation,
                        dst_ep,
                        src_ep,
                        cluster_id,
                        profile_id,
                    )) = ext_frag
                    {
                        let mut frag_local = [0u8; crate::aps::apsme::MAX_FRAGMENT_PAYLOAD];
                        let copy_len = {
                            // SAFETY: no active borrows on buf[aps_start..] at this
                            // point — scoped block above dropped frame_ro/header.
                            let frag_src: &[u8] = unsafe {
                                core::slice::from_raw_parts(
                                    buf_ptr.add(aps_start + hdr_len),
                                    aps_len.saturating_sub(hdr_len),
                                )
                            };
                            let n = frag_src.len().min(crate::aps::apsme::MAX_FRAGMENT_PAYLOAD);
                            frag_local[..n].copy_from_slice(&frag_src[..n]);
                            n
                            // frag_src borrow ends here
                        };
                        let assembled = self.apsme.defrag_incoming(
                            source,
                            counter,
                            block_number,
                            ack_bitfield,
                            fragmentation,
                            dst_ep,
                            src_ep,
                            cluster_id,
                            profile_id,
                            nwk_secured,
                            destination,
                            false,
                            &frag_local[..copy_len],
                        );
                        return Ok(if assembled.is_some() {
                            ZigbeeDevicePoll::FragmentComplete
                        } else {
                            ZigbeeDevicePoll::FragmentDeferred
                        });
                    }

                    // Non-fragmented unsecured data. Return a slice into buf with
                    // lifetime 'a so the caller can borrow the ASDU without copying.
                    // SAFETY: no borrows on buf[aps_start..] exist at this point.
                    let aps_payload: &'a [u8] =
                        unsafe { core::slice::from_raw_parts(buf_ptr.add(aps_start), aps_len) };
                    Ok(ZigbeeDevicePoll::Data(parse_data_indication_parts(
                        source,
                        destination,
                        nwk_secured,
                        aps_payload,
                    )?))
                }
            }
            FrameType::Command => {
                if !aps_secured_flag {
                    return Err(NetworkError::SecurityError(
                        crate::security::SecurityError::InvalidData,
                    ));
                }
                // SAFETY: same as secured Data arm above.
                let aps_buf =
                    unsafe { core::slice::from_raw_parts_mut(buf_ptr.add(aps_start), aps_len) };
                let frame = SecurityContext::get().decrypt_aps_frame_in_place(aps_buf)?;
                let Frame::ApsCommand(CommandFrame { header, command }) = frame else {
                    return Err(NetworkError::InvalidFrame);
                };
                if !self
                    .apsme
                    .accept_incoming(source, header.counter, FrameType::Command, true)
                {
                    return Err(NetworkError::InvalidFrame);
                }
                Ok(ZigbeeDevicePoll::Command(command))
            }
            FrameType::Acknowledgement => Ok(ZigbeeDevicePoll::Ack),
            FrameType::InterPan => Err(NetworkError::InvalidFrame),
        }
    }

    /// Security Manager: poll for a Transport-Key command and install the
    /// network key and Trust Center link key entry (§4.4.10).
    pub async fn poll_transport_key<M: zigbee_mac::mlme::Mlme>(
        &mut self,
        nlme: &mut Nlme<M>,
    ) -> Result<(), NetworkError> {
        // Loop up to 5 times: each iteration polls for one MAC frame and
        // skips non-TRANSPORT-KEY frames (NWK commands, regular APS data,
        // decrypt failures) rather than failing immediately.  This mirrors
        // poll_command's drain-loop approach and handles coordinators that
        // queue NWK command frames before the NWK key delivery.
        for _ in 0..5u8 {
            let mut buf = [0u8; 128];
            let nwk_data = match nlme.poll_nwk_data(&mut buf, 1).await {
                Ok(d) => d,
                Err(e) => {
                    log::debug!("[ZDO] poll_transport_key: skip frame ({e:?})");
                    continue;
                }
            };
            let payload_range = nwk_data.payload_range();
            let Ok((header, _)) = Header::try_read(nwk_data.payload, ()) else {
                log::debug!("[ZDO] poll_transport_key: APS header parse fail");
                continue;
            };
            if header.frame_control.frame_type() != FrameType::Command
                || !header.frame_control.security_flag()
            {
                log::debug!(
                    "[ZDO] poll_transport_key: skip non-cmd/unencrypted APS (type={:?})",
                    header.frame_control.frame_type()
                );
                continue;
            }
            let _ = nwk_data;
            let cx = SecurityContext::get();
            let aps_frame = match cx.decrypt_aps_frame_in_place(&mut buf[payload_range]) {
                Ok(f) => f,
                Err(e) => {
                    log::debug!("[ZDO] poll_transport_key: APS decrypt fail: {e:?}");
                    continue;
                }
            };
            let Frame::ApsCommand(CommandFrame {
                command: Command::TransportKey(transport_key),
                ..
            }) = aps_frame
            else {
                log::debug!("[ZDO] poll_transport_key: not a TRANSPORT-KEY, skipping");
                continue;
            };
            install_transport_key(transport_key)?;
            return Ok(());
        }
        Err(NetworkError::NoTransportKey)
    }

    /// Security Manager: build and send an APS command frame (§4.4).
    ///
    /// Delegates to APSME which owns `apsCounter` (§4.4.11). When
    /// `aps_secure` is true the frame is APS-encrypted with the link key for
    /// `dest_ieee`; the NWK layer always applies network-key encryption.
    pub async fn send_aps_command<M: zigbee_mac::mlme::Mlme>(
        &mut self,
        nlme: &mut Nlme<M>,
        destination: ShortAddress,
        dest_ieee: IeeeAddress,
        command: Command,
        aps_secure: bool,
    ) -> Result<(), NetworkError> {
        self.apsme
            .send_command(nlme, destination, dest_ieee, command, aps_secure)
            .await
    }

    /// Borrow the completed fragment-reassembly result without copying the
    /// ASDU.
    ///
    /// Call after `poll_aps` returns `ZigbeeDevicePoll::FragmentComplete`.
    /// Returns `None` if no completed reassembly is available.
    /// Call [`Self::clear_defrag`] once the indication has been fully
    /// processed.
    pub fn peek_defrag_indication(&self) -> Option<ApsdeSapIndication<'_>> {
        let state = self.apsme.defrag_state.as_ref()?;
        if !state.complete {
            return None;
        }
        Some(ApsdeSapIndication {
            dst_addr_mode: DstAddrMode::Network,
            dst_address: Address::Network(state.dst_short.0),
            dst_endpoint: state.dst_endpoint,
            src_addr_mode: SrcAddrMode::Short,
            src_address: Address::Network(state.source.0),
            src_endpoint: state.src_endpoint,
            profile_id: state.profile_id,
            cluster_id: state.cluster_id,
            asdu: &state.buf[..state.assembled_len],
            delivery: ApsDeliveryMode::Unicast,
            status: ApsdeSapIndicationStatus::Success,
            security_status: if state.aps_secured {
                SecurityStatus::SecuredLinkKey
            } else if state.nwk_secured {
                SecurityStatus::SecuredNwkKey
            } else {
                SecurityStatus::Unsecured
            },
            link_quality: 0,
            rx_time: 0,
        })
    }

    /// Clear the completed fragment-reassembly state.
    ///
    /// Call after [`Self::peek_defrag_indication`] and after the indication
    /// has been fully dispatched, so the slot is available for the next
    /// fragmented transmission.
    pub fn clear_defrag(&mut self) {
        self.apsme.defrag_state = None;
    }

    /// Security Manager: poll for an incoming APS command (§4.4).
    ///
    /// Delegates to APSME which decrypts the NWK and APS layers.
    pub async fn poll_aps_command<M: zigbee_mac::mlme::Mlme>(
        &mut self,
        nlme: &mut Nlme<M>,
        retries: u8,
    ) -> Result<Command, NetworkError> {
        self.apsme.poll_command(nlme, retries).await
    }
}

impl Default for ZigbeeDevice {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

pub fn install_transport_key(transport_key: TransportKey) -> Result<(), NetworkError> {
    match transport_key {
        TransportKey::StandardNetworkKey(nwk_key) => {
            log::debug!("[ZDO] received network key {:02x?}", nwk_key.key);

            let aib = aib::get_ref();
            aib.set_trust_center_address(nwk_key.source_address);
            let mut key_set = aib.device_key_pair_set();
            if !key_set
                .iter()
                .any(|k| k.device_address == nwk_key.source_address)
            {
                key_set
                    .push(DeviceKeyPairDescriptor {
                        device_address: nwk_key.source_address,
                        key_attributes: KeyAttribute::ProvisionalKey,
                        link_key: zigbee_types::ByteArray(crate::security::TRUST_CENTER_LINK_KEY),
                        outgoing_frame_counter: 0,
                        incoming_frame_counter: 0,
                        link_key_type: LinkKeyType::GlobalLinkKey,
                    })
                    .map_err(|_| NetworkError::InvalidFrame)?;
                aib.set_device_key_pair_set(key_set);
            }

            let nib = nib::get_ref();
            let mut sec_material = nib.security_material_set();
            sec_material.clear();
            sec_material
                .push(NetworkSecurityMaterialDescriptor {
                    key_seq_number: nwk_key.sequence_number,
                    outgoing_frame_counter: 0,
                    incoming_frame_counter_set: StorageVec::new(),
                    key: nwk_key.key,
                    network_key_type: 0x01,
                })
                .map_err(|_| NetworkError::InvalidFrame)?;
            nib.set_security_material_set(sec_material);
            nib.set_active_key_seq_number(nwk_key.sequence_number);
            Ok(())
        }
        TransportKey::ApplicationLinkKey(_) | TransportKey::TrustCenterLinkKey(_) => Ok(()),
        TransportKey::Reserved(_) => Err(NetworkError::NoTransportKey),
    }
}
