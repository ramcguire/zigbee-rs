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
use crate::aps::apsde::Apsde;
use crate::aps::apsde::ApsdeSapConfirmStatus;
use crate::aps::apsde::ApsdeSapIndication;
use crate::aps::apsde::ApsdeSapRequest;
use crate::aps::apsde::data_frame_to_indication;
use crate::aps::apsde::parse_data_indication_parts;
use crate::aps::apsme::Apsme;
use crate::aps::frame::CommandFrame;
use crate::aps::frame::Frame;
use crate::aps::frame::command::Command;
use crate::aps::frame::command::TransportKey;
use crate::aps::frame::frame_control::FrameType;
use crate::aps::frame::header::Header;
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

    /// Send an unfragmented APS data frame through this device's APSDE state.
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
    pub async fn poll_aps<'a, M: zigbee_mac::mlme::Mlme>(
        &mut self,
        nlme: &mut Nlme<M>,
        buf: &'a mut [u8],
        retries: u8,
    ) -> Result<ZigbeeDevicePoll<'a>, NetworkError> {
        let buf_ptr = buf.as_mut_ptr();
        let nwk_data = nlme.poll_nwk_data(buf, retries).await?;
        let payload_range = nwk_data.payload_range();
        let source = nwk_data.header.source;
        let destination = nwk_data.header.destination;
        let nwk_secured = nwk_data.header.frame_control.security_flag();
        let (header, _) = Header::try_read(nwk_data.payload, ())?;
        match header.frame_control.frame_type() {
            FrameType::Data => {
                if header.frame_control.security_flag() {
                    drop(nwk_data);
                    // SAFETY: `payload_range` was produced by parsing `buf`, and
                    // `nwk_data` is dropped before in-place APS decrypt.
                    let aps_buf = unsafe {
                        core::slice::from_raw_parts_mut(
                            buf_ptr.add(payload_range.start),
                            payload_range.len(),
                        )
                    };
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
                    Ok(ZigbeeDevicePoll::Data(data_frame_to_indication(
                        source,
                        destination,
                        nwk_secured,
                        data,
                    )?))
                } else {
                    if !self
                        .apsme
                        .accept_incoming(source, header.counter, FrameType::Data, false)
                    {
                        return Err(NetworkError::InvalidFrame);
                    }
                    Ok(ZigbeeDevicePoll::Data(parse_data_indication_parts(
                        source,
                        destination,
                        nwk_secured,
                        nwk_data.payload,
                    )?))
                }
            }
            FrameType::Command => {
                if !header.frame_control.security_flag() {
                    return Err(NetworkError::SecurityError(
                        crate::security::SecurityError::InvalidData,
                    ));
                }
                drop(nwk_data);
                // SAFETY: `payload_range` was produced by parsing `buf`, and
                // `nwk_data` is dropped before in-place APS decrypt.
                let aps_buf = unsafe {
                    core::slice::from_raw_parts_mut(
                        buf_ptr.add(payload_range.start),
                        payload_range.len(),
                    )
                };
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
            FrameType::Acknowledgement | FrameType::InterPan => Err(NetworkError::InvalidFrame),
        }
    }

    /// Security Manager: poll for a Transport-Key command and install the
    /// network key and Trust Center link key entry (§4.4.10).
    pub async fn poll_transport_key<M: zigbee_mac::mlme::Mlme>(
        &mut self,
        nlme: &mut Nlme<M>,
    ) -> Result<(), NetworkError> {
        let mut buf = [0u8; 128];
        let nwk_data = nlme.poll_nwk_data(&mut buf, 5).await?;
        let payload_range = nwk_data.payload_range();
        let (header, _) = Header::try_read(nwk_data.payload, ())?;
        if header.frame_control.frame_type() != FrameType::Command
            || !header.frame_control.security_flag()
        {
            return Err(NetworkError::NoTransportKey);
        }
        drop(nwk_data);
        let cx = SecurityContext::get();
        let aps_frame = cx.decrypt_aps_frame_in_place(&mut buf[payload_range])?;

        let Frame::ApsCommand(CommandFrame {
            command: Command::TransportKey(transport_key),
            ..
        }) = aps_frame
        else {
            return Err(NetworkError::NoTransportKey);
        };

        install_transport_key(transport_key)?;

        Ok(())
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
