use crate::cluster_server::ClusterServer;
use crate::cluster_server::CommandResult;
use crate::frame::Status;
use crate::types::descriptors::AccessFlags;
use crate::types::descriptors::AttrInfo;
use crate::types::descriptors::encode_attr;
use crate::types::error::AttrError;
use crate::types::error::ZclError;
use crate::types::ids::AttributeId;
use crate::types::ids::ClusterId;
use crate::types::ids::CommandId;
use crate::types::ids::TypeId;

/// ZCL On/Off cluster (0x0006), Strategy 1.
///
/// State is changed by commands (On/Off/Toggle); the `on_off` attribute is
/// read-only from ZCL. The application may read `on_off` directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OnOffServer {
    /// Attribute 0x0000 — `OnOff` (Boolean).
    pub on_off: bool,
}

impl OnOffServer {
    pub const fn new(initial: bool) -> Self {
        Self { on_off: initial }
    }
}

impl Default for OnOffServer {
    fn default() -> Self {
        Self::new(false)
    }
}

impl ClusterServer for OnOffServer {
    const CLUSTER_ID: ClusterId = ClusterId::new(0x0006);

    fn read_attribute(
        &self,
        id: AttributeId,
        buf: &mut [u8],
    ) -> Result<(TypeId, usize), AttrError> {
        match id.0 {
            0x0000 => Ok(encode_attr::<bool>(self.on_off, buf)?),
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }

    fn check_write_attribute(
        &self,
        id: AttributeId,
        _type_id: TypeId,
        _data: &[u8],
    ) -> Result<(), AttrError> {
        match id.0 {
            0x0000 => Err(AttrError::ReadOnly),
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }

    fn write_attribute(
        &mut self,
        id: AttributeId,
        _type_id: TypeId,
        _data: &[u8],
    ) -> Result<(), AttrError> {
        match id.0 {
            0x0000 => Err(AttrError::ReadOnly),
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }

    fn handle_command(
        &mut self,
        id: CommandId,
        _payload: &[u8],
        _buf: &mut [u8],
    ) -> Result<CommandResult, ZclError> {
        match id.0 {
            0x00 => {
                self.on_off = false;
                Ok(CommandResult::DefaultResponse(Status::Success))
            }
            0x01 => {
                self.on_off = true;
                Ok(CommandResult::DefaultResponse(Status::Success))
            }
            0x02 => {
                self.on_off = !self.on_off;
                Ok(CommandResult::DefaultResponse(Status::Success))
            }
            _ => Ok(CommandResult::DefaultResponse(Status::UnsupCommand)),
        }
    }

    fn attribute_list() -> &'static [AttrInfo] {
        static LIST: [AttrInfo; 1] = [AttrInfo {
            id: AttributeId::new(0x0000),
            type_id: TypeId::Boolean,
            access: AccessFlags::READ,
        }];
        &LIST
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::cluster_server::DeliveryMode;
    use crate::cluster_server::DispatchContext;
    use crate::cluster_server::zcl_cluster_dispatch;
    use crate::frame::IncomingZclFrame;
    use crate::frame::Status;

    fn unicast() -> DispatchContext {
        DispatchContext {
            delivery: DeliveryMode::Unicast,
        }
    }

    #[test]
    fn on_off_attribute_reads_false_initially() {
        let server = OnOffServer::new(false);
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Boolean);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x00);
    }

    #[test]
    fn on_command_sets_on_off_true() {
        let mut server = OnOffServer::new(false);
        let result = server
            .handle_command(CommandId(0x01), &[], &mut [])
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::Success)
        ));
        assert!(server.on_off);
    }

    #[test]
    fn off_command_sets_on_off_false() {
        let mut server = OnOffServer::new(true);
        let result = server
            .handle_command(CommandId(0x00), &[], &mut [])
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::Success)
        ));
        assert!(!server.on_off);
    }

    #[test]
    fn toggle_command_flips_state() {
        let mut server = OnOffServer::new(false);
        let _ = server.handle_command(CommandId(0x02), &[], &mut []);
        assert!(server.on_off);
        let _ = server.handle_command(CommandId(0x02), &[], &mut []);
        assert!(!server.on_off);
    }

    #[test]
    fn unknown_command_returns_unsup() {
        let mut server = OnOffServer::new(false);
        let result = server
            .handle_command(CommandId(0xFF), &[], &mut [])
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::UnsupCommand)
        ));
    }

    #[test]
    fn write_attribute_returns_read_only() {
        let mut server = OnOffServer::new(false);
        assert_eq!(
            server.write_attribute(AttributeId::new(0x0000), TypeId::Boolean, &[0x01]),
            Err(AttrError::ReadOnly)
        );
    }

    #[test]
    fn dispatch_on_command_sends_default_response() {
        // cluster-specific On command, seq=5
        let req: &[u8] = &[0x01, 0x05, 0x01]; // cluster-specific | disable-DR=0, seq, On
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = OnOffServer::new(false);
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf).unwrap();

        assert_eq!(n, 5); // DefaultResponse is 5 bytes
        assert_eq!(buf[2], 0x0b); // DefaultResponse command id
        assert_eq!(buf[4], Status::Success as u8);
        assert!(server.on_off);
    }

    #[test]
    fn dispatch_toggle_command_flips_state() {
        let req: &[u8] = &[0x01, 0x06, 0x02]; // Toggle
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = OnOffServer::new(true);
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf).unwrap();
        assert_eq!(n, 5);
        assert!(!server.on_off);
    }
}
