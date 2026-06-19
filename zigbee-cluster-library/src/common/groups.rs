use heapless::Vec;

use crate::cluster_server::ClusterServer;
use crate::cluster_server::CommandResult;
use crate::cluster_server::DispatchContext;
use crate::cluster_server::DispatchEffects;
use crate::cluster_server::GroupEffect;
use crate::frame::Status;
use crate::types::bitmaps::Bitmap8;
use crate::types::descriptors::AttrInfo;
use crate::types::descriptors::encode_attr;
use crate::types::error::AttrError;
use crate::types::error::ZclError;
use crate::types::ids::AttributeId;
use crate::types::ids::ClusterId;
use crate::types::ids::CommandId;
use crate::types::ids::TypeId;

/// One entry in the group membership table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupEntry {
    pub id: u16,
    /// Group name set by the coordinator after join/rejoin.
    /// Intentionally non-persistent: ZCL spec §3.6 does not require persistence
    /// and the coordinator re-sends names after every join.
    pub name: [u8; 16],
    pub name_len: u8,
}

impl GroupEntry {
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// ZCL Groups cluster (0x0004).
///
/// `N` is the maximum group membership count.
///
/// Set `identifying = true` to mirror the active `IdentifyServer` state so
/// `AddGroupIfIdentifying` (0x05) works correctly.
pub struct GroupsServer<const N: usize> {
    /// Attribute 0x0000 — `NameSupport` (Bitmap8, R). Bit 7: names are stored.
    pub name_support: u8,
    /// Mirrors `IdentifyServer::is_identifying()`. Set by the application.
    pub identifying: bool,
    groups: Vec<GroupEntry, N>,
    pending_effect: GroupEffect,
}

impl<const N: usize> GroupsServer<N> {
    pub const fn new(name_support: u8) -> Self {
        Self {
            name_support: name_support | 0x80,
            identifying: false,
            groups: Vec::new(),
            pending_effect: GroupEffect::None,
        }
    }

    pub fn is_member(&self, group_id: u16) -> bool {
        self.groups.iter().any(|g| g.id == group_id)
    }

    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    pub fn capacity_remaining(&self) -> u8 {
        u8::try_from(N - self.groups.len()).unwrap_or(u8::MAX)
    }

    pub fn groups(&self) -> &[GroupEntry] {
        &self.groups
    }

    fn find_index(&self, group_id: u16) -> Option<usize> {
        self.groups.iter().position(|g| g.id == group_id)
    }

    fn add(&mut self, group_id: u16, name: &[u8]) -> Status {
        if group_id == 0x0000 {
            return Status::InvalidField;
        }
        if name.len() > 16 {
            return Status::InvalidField;
        }
        if self.find_index(group_id).is_some() {
            return Status::Success;
        }
        if self.groups.is_full() {
            return Status::InsufficientSpace;
        }
        let name_len = u8::try_from(name.len()).unwrap_or(16);
        let mut entry = GroupEntry {
            id: group_id,
            name: [0u8; 16],
            name_len,
        };
        entry.name[..name.len()].copy_from_slice(name);
        let _ = self.groups.push(entry);
        Status::Success
    }
}

impl<const N: usize> Default for GroupsServer<N> {
    fn default() -> Self {
        Self::new(0x00)
    }
}

fn parse_group_id(payload: &[u8]) -> Option<u16> {
    payload.get(..2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn parse_group_and_name(payload: &[u8]) -> Option<(u16, &[u8])> {
    let group_id = parse_group_id(payload)?;
    let name_len = *payload.get(2)? as usize;
    let name = payload.get(3..3 + name_len)?;
    Some((group_id, name))
}

fn write_status_and_group(
    buf: &mut [u8],
    status: Status,
    group_id: u16,
) -> Result<usize, ZclError> {
    if buf.len() < 3 {
        return Err(ZclError::BufferTooSmall);
    }
    buf[0] = status as u8;
    let b = group_id.to_le_bytes();
    buf[1] = b[0];
    buf[2] = b[1];
    Ok(3)
}

impl<const N: usize> ClusterServer for GroupsServer<N> {
    const CLUSTER_ID: ClusterId = ClusterId::new(0x0004);

    fn read_attribute(
        &self,
        id: AttributeId,
        buf: &mut [u8],
    ) -> Result<(TypeId, usize), AttrError> {
        match id.0 {
            0x0000 => Ok(encode_attr::<Bitmap8<u8>>(self.name_support, buf)?),
            0xFFFD => Ok(encode_attr::<u16>(3, buf)?),
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }

    read_only_attrs![0x0000 | 0xFFFD];

    #[allow(clippy::too_many_lines)]
    fn handle_command(
        &mut self,
        id: CommandId,
        payload: &[u8],
        _ctx: DispatchContext,
        buf: &mut [u8],
    ) -> Result<CommandResult, ZclError> {
        match id.0 {
            // AddGroup → AddGroupResponse (0x00)
            0x00 => {
                let (group_id, name) =
                    parse_group_and_name(payload).ok_or(ZclError::InsufficientBytes)?;
                let status = self.add(group_id, name);
                if status == Status::Success {
                    self.pending_effect = GroupEffect::Added(group_id);
                }
                let len = write_status_and_group(buf, status, group_id)?;
                Ok(CommandResult::Payload {
                    command_id: CommandId::new(0x00),
                    len,
                })
            }
            // ViewGroup → ViewGroupResponse (0x01)
            0x01 => {
                let group_id = parse_group_id(payload).ok_or(ZclError::InsufficientBytes)?;
                if let Some(idx) = self.find_index(group_id) {
                    let entry = &self.groups[idx];
                    let name_len = entry.name_len as usize;
                    let needed = 4 + name_len;
                    if buf.len() < needed {
                        return Err(ZclError::BufferTooSmall);
                    }
                    buf[0] = Status::Success as u8;
                    let b = group_id.to_le_bytes();
                    buf[1] = b[0];
                    buf[2] = b[1];
                    buf[3] = entry.name_len;
                    buf[4..4 + name_len].copy_from_slice(&entry.name[..name_len]);
                    Ok(CommandResult::Payload {
                        command_id: CommandId::new(0x01),
                        len: needed,
                    })
                } else {
                    if buf.len() < 4 {
                        return Err(ZclError::BufferTooSmall);
                    }
                    buf[0] = Status::NotFound as u8;
                    let b = group_id.to_le_bytes();
                    buf[1] = b[0];
                    buf[2] = b[1];
                    buf[3] = 0x00; // empty name
                    Ok(CommandResult::Payload {
                        command_id: CommandId::new(0x01),
                        len: 4,
                    })
                }
            }
            // GetGroupMembership → GetGroupMembershipResponse (0x02)
            0x02 => {
                let count = *payload.first().ok_or(ZclError::InsufficientBytes)?;
                if count > 0 && payload.len() < 1 + usize::from(count) * 2 {
                    return Err(ZclError::InsufficientBytes);
                }
                let capacity = self.capacity_remaining();
                // Response: [capacity, out_count, gid0_lo, gid0_hi, ...]
                if buf.len() < 2 {
                    return Err(ZclError::BufferTooSmall);
                }
                buf[0] = capacity;
                let mut out_count: u8 = 0;
                if count == 0 {
                    for g in &self.groups {
                        let off = 2 + out_count as usize * 2;
                        if off + 2 > buf.len() {
                            return Err(ZclError::BufferTooSmall);
                        }
                        let b = g.id.to_le_bytes();
                        buf[off] = b[0];
                        buf[off + 1] = b[1];
                        out_count += 1;
                    }
                } else {
                    let requested = payload.get(1..).unwrap_or(&[]);
                    let mut req_off = 0;
                    while req_off + 2 <= requested.len() {
                        let req_id =
                            u16::from_le_bytes([requested[req_off], requested[req_off + 1]]);
                        req_off += 2;
                        if self.is_member(req_id) {
                            let off = 2 + out_count as usize * 2;
                            if off + 2 > buf.len() {
                                return Err(ZclError::BufferTooSmall);
                            }
                            let b = req_id.to_le_bytes();
                            buf[off] = b[0];
                            buf[off + 1] = b[1];
                            out_count += 1;
                        }
                    }
                }
                buf[1] = out_count;
                let len = 2 + out_count as usize * 2;
                Ok(CommandResult::Payload {
                    command_id: CommandId::new(0x02),
                    len,
                })
            }
            // RemoveGroup → RemoveGroupResponse (0x03)
            0x03 => {
                let group_id = parse_group_id(payload).ok_or(ZclError::InsufficientBytes)?;
                let status = if let Some(idx) = self.find_index(group_id) {
                    self.groups.swap_remove(idx);
                    self.pending_effect = GroupEffect::Removed(group_id);
                    Status::Success
                } else {
                    Status::NotFound
                };
                let len = write_status_and_group(buf, status, group_id)?;
                Ok(CommandResult::Payload {
                    command_id: CommandId::new(0x03),
                    len,
                })
            }
            // RemoveAllGroups → DefaultResponse(Success)
            0x04 => {
                self.groups.clear();
                self.pending_effect = GroupEffect::AllRemoved;
                Ok(CommandResult::DefaultResponse(Status::Success))
            }
            // AddGroupIfIdentifying → DefaultResponse(Success)
            0x05 => {
                if self.identifying
                    && let Some((group_id, name)) = parse_group_and_name(payload)
                    && self.add(group_id, name) == Status::Success
                {
                    self.pending_effect = GroupEffect::Added(group_id);
                }
                Ok(CommandResult::DefaultResponse(Status::Success))
            }
            _ => Ok(CommandResult::DefaultResponse(Status::UnsupCommand)),
        }
    }

    fn take_dispatch_effects(&mut self) -> DispatchEffects {
        DispatchEffects {
            group: core::mem::replace(&mut self.pending_effect, GroupEffect::None),
            ..Default::default()
        }
    }

    fn attribute_list() -> &'static [AttrInfo] {
        attr_list![(0x0000, Bitmap8, READ), (0xFFFD, Uint16, READ),]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_server::zcl_cluster_dispatch;
    use crate::frame::IncomingZclFrame;

    fn unicast() -> DispatchContext {
        DispatchContext::unicast(0, None)
    }

    fn broadcast() -> DispatchContext {
        DispatchContext::broadcast(0)
    }

    type Server = GroupsServer<4>;

    // ---- attribute tests ----

    #[test]
    fn name_support_reads_as_bitmap8() {
        let server = Server::new(0x80);
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Bitmap8);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x80);
    }

    #[test]
    fn unknown_attribute_returns_unsupported() {
        let server = Server::default();
        let mut buf = [0u8; 4];
        assert_eq!(
            server.read_attribute(AttributeId::new(0x0001), &mut buf),
            Err(AttrError::UnsupportedAttribute)
        );
    }

    #[test]
    fn write_attribute_returns_read_only() {
        let mut server = Server::default();
        assert_eq!(
            server.write_attribute(AttributeId::new(0x0000), TypeId::Bitmap8, &[0x00]),
            Err(AttrError::ReadOnly)
        );
    }

    #[test]
    fn cluster_revision_reads_rev8_value_and_is_read_only() {
        let mut server = Server::default();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0xFFFD), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 3);
        assert_eq!(
            server.write_attribute(AttributeId::new(0xFFFD), TypeId::Uint16, &[3, 0]),
            Err(AttrError::ReadOnly)
        );
    }

    #[test]
    fn attribute_list_has_two_entries() {
        assert_eq!(Server::attribute_list().len(), 2);
    }

    #[test]
    fn attribute_list_places_cluster_revision_after_name_support() {
        let attrs = Server::attribute_list();
        assert_eq!(attrs[0].id, AttributeId::new(0x0000));
        assert_eq!(attrs[1].id, AttributeId::new(0xFFFD));
    }

    // ---- membership helpers ----

    #[test]
    fn new_server_has_no_members() {
        let server = Server::default();
        assert!(!server.is_member(0x0001));
        assert_eq!(server.group_count(), 0);
        assert_eq!(server.capacity_remaining(), 4);
    }

    #[test]
    fn new_always_advertises_name_support() {
        let server = Server::new(0x00);
        assert_eq!(server.name_support, 0x80);
    }

    // ---- AddGroup (0x00) ----

    #[test]
    fn add_group_success() {
        let mut server = Server::default();
        let mut buf = [0u8; 16];
        // payload: group_id=0x0001 LE + name_len=3 + "Foo"
        let payload: &[u8] = &[0x01, 0x00, 0x03, b'F', b'o', b'o'];
        let result = server
            .handle_command(CommandId::new(0x00), payload, unicast(), &mut buf)
            .unwrap();
        assert!(
            matches!(result, CommandResult::Payload { command_id, len: 3 } if command_id == CommandId::new(0x00))
        );
        assert_eq!(buf[0], Status::Success as u8);
        assert_eq!(u16::from_le_bytes([buf[1], buf[2]]), 0x0001);
        assert!(server.is_member(0x0001));
    }

    #[test]
    fn add_group_duplicate_returns_duplicate_exists() {
        let mut server = Server::default();
        let payload: &[u8] = &[0x01, 0x00, 0x00];
        server
            .handle_command(CommandId::new(0x00), payload, unicast(), &mut [0u8; 8])
            .unwrap();
        let mut buf = [0u8; 8];
        let result = server
            .handle_command(CommandId::new(0x00), payload, unicast(), &mut buf)
            .unwrap();
        assert!(matches!(result, CommandResult::Payload { .. }));
        assert_eq!(buf[0], Status::Success as u8);
    }

    #[test]
    fn add_group_zero_id_returns_invalid_field() {
        let mut server = Server::default();
        let payload: &[u8] = &[0x00, 0x00, 0x00];
        let mut buf = [0u8; 8];
        let result = server
            .handle_command(CommandId::new(0x00), payload, unicast(), &mut buf)
            .unwrap();
        assert_eq!(buf[0], Status::InvalidField as u8);
        assert!(matches!(result, CommandResult::Payload { .. }));
    }

    #[test]
    fn add_group_rejects_name_longer_than_sixteen_bytes() {
        let mut server = Server::default();
        let payload: &[u8] = b"\x01\x00\x11abcdefghijklmnopq";
        let mut buf = [0u8; 8];
        let result = server
            .handle_command(CommandId::new(0x00), payload, unicast(), &mut buf)
            .unwrap();
        assert!(matches!(result, CommandResult::Payload { .. }));
        assert_eq!(buf[0], Status::InvalidField as u8);
        assert!(!server.is_member(0x0001));
    }

    #[test]
    fn add_group_table_full_returns_insufficient_space() {
        let mut server = Server::default();
        let mut buf = [0u8; 8];
        for i in 1u16..=4 {
            let b = i.to_le_bytes();
            let payload = [b[0], b[1], 0x00];
            server
                .handle_command(CommandId::new(0x00), &payload, unicast(), &mut buf)
                .unwrap();
        }
        let payload: &[u8] = &[0x05, 0x00, 0x00];
        let result = server
            .handle_command(CommandId::new(0x00), payload, unicast(), &mut buf)
            .unwrap();
        assert_eq!(buf[0], Status::InsufficientSpace as u8);
        assert!(matches!(result, CommandResult::Payload { .. }));
    }

    // ---- ViewGroup (0x01) ----

    #[test]
    fn view_group_found_returns_success_with_name() {
        let mut server = Server::default();
        let add_payload: &[u8] = &[0x02, 0x00, 0x03, b'B', b'a', b'r'];
        server
            .handle_command(CommandId::new(0x00), add_payload, unicast(), &mut [0u8; 8])
            .unwrap();

        let view_payload: &[u8] = &[0x02, 0x00];
        let mut buf = [0u8; 16];
        let result = server
            .handle_command(CommandId::new(0x01), view_payload, unicast(), &mut buf)
            .unwrap();
        assert!(
            matches!(result, CommandResult::Payload { command_id, len: 7 } if command_id == CommandId::new(0x01))
        );
        assert_eq!(buf[0], Status::Success as u8);
        assert_eq!(u16::from_le_bytes([buf[1], buf[2]]), 0x0002);
        assert_eq!(buf[3], 3); // name_len
        assert_eq!(&buf[4..7], b"Bar");
    }

    #[test]
    fn view_group_not_found_returns_not_found() {
        let mut server = Server::default();
        let payload: &[u8] = &[0x99, 0x00];
        let mut buf = [0u8; 8];
        let result = server
            .handle_command(CommandId::new(0x01), payload, unicast(), &mut buf)
            .unwrap();
        assert!(
            matches!(result, CommandResult::Payload { command_id, len: 4 } if command_id == CommandId::new(0x01))
        );
        assert_eq!(buf[0], Status::NotFound as u8);
        assert_eq!(u16::from_le_bytes([buf[1], buf[2]]), 0x0099);
        assert_eq!(buf[3], 0); // empty name
    }

    // ---- GetGroupMembership (0x02) ----

    #[test]
    fn get_group_membership_count_zero_returns_all() {
        let mut server = Server::default();
        let mut buf = [0u8; 16];
        for i in [0x0001u16, 0x0002, 0x0003] {
            let b = i.to_le_bytes();
            server
                .handle_command(
                    CommandId::new(0x00),
                    &[b[0], b[1], 0x00],
                    unicast(),
                    &mut buf,
                )
                .unwrap();
        }
        let payload: &[u8] = &[0x00]; // count=0 → all
        let result = server
            .handle_command(CommandId::new(0x02), payload, unicast(), &mut buf)
            .unwrap();
        assert!(
            matches!(result, CommandResult::Payload { command_id, len: 8 } if command_id == CommandId::new(0x02))
        );
        assert_eq!(buf[0], 1); // capacity=4-3=1
        assert_eq!(buf[1], 3); // out_count
    }

    #[test]
    fn get_group_membership_filters_present_ids() {
        let mut server = Server::default();
        let mut buf = [0u8; 16];
        server
            .handle_command(
                CommandId::new(0x00),
                &[0x01, 0x00, 0x00],
                unicast(),
                &mut buf,
            )
            .unwrap();

        // Request [0x0001, 0x0002] — only 0x0001 is present
        let payload: &[u8] = &[0x02, 0x01, 0x00, 0x02, 0x00];
        let result = server
            .handle_command(CommandId::new(0x02), payload, unicast(), &mut buf)
            .unwrap();
        assert!(
            matches!(result, CommandResult::Payload { command_id, len: 4 } if command_id == CommandId::new(0x02))
        );
        assert_eq!(buf[1], 1); // out_count=1
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), 0x0001);
    }

    #[test]
    fn get_group_membership_rejects_truncated_requested_ids() {
        let mut server = Server::default();
        let mut buf = [0u8; 16];
        assert!(matches!(
            server.handle_command(
                CommandId::new(0x02),
                &[0x02, 0x01, 0x00],
                unicast(),
                &mut buf
            ),
            Err(ZclError::InsufficientBytes)
        ));
    }

    // ---- RemoveGroup (0x03) ----

    #[test]
    fn remove_group_found_returns_success() {
        let mut server = Server::default();
        let mut buf = [0u8; 8];
        server
            .handle_command(
                CommandId::new(0x00),
                &[0x05, 0x00, 0x00],
                unicast(),
                &mut buf,
            )
            .unwrap();
        assert!(server.is_member(0x0005));

        let result = server
            .handle_command(CommandId::new(0x03), &[0x05, 0x00], unicast(), &mut buf)
            .unwrap();
        assert!(
            matches!(result, CommandResult::Payload { command_id, len: 3 } if command_id == CommandId::new(0x03))
        );
        assert_eq!(buf[0], Status::Success as u8);
        assert!(!server.is_member(0x0005));
    }

    #[test]
    fn remove_group_not_found_returns_not_found() {
        let mut server = Server::default();
        let mut buf = [0u8; 8];
        let result = server
            .handle_command(CommandId::new(0x03), &[0x42, 0x00], unicast(), &mut buf)
            .unwrap();
        assert_eq!(buf[0], Status::NotFound as u8);
        assert!(matches!(result, CommandResult::Payload { .. }));
    }

    // ---- RemoveAllGroups (0x04) ----

    #[test]
    fn remove_all_groups_clears_table() {
        let mut server = Server::default();
        let mut buf = [0u8; 8];
        server
            .handle_command(
                CommandId::new(0x00),
                &[0x01, 0x00, 0x00],
                unicast(),
                &mut buf,
            )
            .unwrap();
        server
            .handle_command(
                CommandId::new(0x00),
                &[0x02, 0x00, 0x00],
                unicast(),
                &mut buf,
            )
            .unwrap();
        assert_eq!(server.group_count(), 2);

        let result = server
            .handle_command(CommandId::new(0x04), &[], unicast(), &mut buf)
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::Success)
        ));
        assert_eq!(server.group_count(), 0);
    }

    #[test]
    fn remove_all_groups_broadcast_suppresses_response() {
        let mut server = Server::default();
        let mut buf = [0u8; 64];
        // ZCL header: frame control (0x01=cluster-specific), seq(1), cmd(0x04)
        let req: &[u8] = &[0x01, 0x00, 0x04];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let n = zcl_cluster_dispatch(&mut server, &frame, broadcast(), &mut buf)
            .unwrap()
            .response_len;
        assert_eq!(n, 0); // broadcast → suppress DefaultResponse
    }

    // ---- AddGroupIfIdentifying (0x05) ----

    #[test]
    fn add_group_if_identifying_while_identifying_adds_group() {
        let mut server = Server {
            identifying: true,
            ..Server::default()
        };
        let mut buf = [0u8; 8];
        let result = server
            .handle_command(
                CommandId::new(0x05),
                &[0x07, 0x00, 0x00],
                unicast(),
                &mut buf,
            )
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::Success)
        ));
        assert!(server.is_member(0x0007));
    }

    #[test]
    fn add_group_if_identifying_while_not_identifying_skips_add() {
        let mut server = Server::default();
        let mut buf = [0u8; 8];
        let result = server
            .handle_command(
                CommandId::new(0x05),
                &[0x07, 0x00, 0x00],
                unicast(),
                &mut buf,
            )
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::Success)
        ));
        assert!(!server.is_member(0x0007));
    }

    // ---- dispatch integration ----

    #[test]
    fn dispatch_read_name_support() {
        let mut server = Server::new(0x80);
        let mut buf = [0u8; 32];
        // ZCL ReadAttributes: frame_ctrl=0x00, seq=1, cmd=0x00, attr_id=0x0000
        let req: &[u8] = &[0x00, 0x01, 0x00, 0x00, 0x00];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;
        // header(3) + attr_id(2) + status(1) + type_id(1) + value(1) = 8
        assert_eq!(n, 8);
        assert_eq!(buf[5], 0x00); // Success
        assert_eq!(buf[6], TypeId::Bitmap8.as_u8());
        assert_eq!(buf[7], 0x80);
    }

    #[test]
    fn dispatch_add_group_returns_payload_response() {
        let mut server = Server::default();
        let mut buf = [0u8; 32];
        // ZCL cluster-specific: frame_ctrl=0x01, seq=1, cmd=0x00, payload=[gid=0x0001,
        // name_len=0]
        let req: &[u8] = &[0x01, 0x02, 0x00, 0x01, 0x00, 0x00];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;
        assert!(n >= 3 + 3); // hdr(3) + status(1) + gid(2)
        assert_eq!(buf[3], Status::Success as u8);
        assert_eq!(u16::from_le_bytes([buf[4], buf[5]]), 0x0001);
    }

    #[test]
    fn unknown_command_returns_unsup_command() {
        let mut server = Server::default();
        let mut buf = [0u8; 16];
        let result = server
            .handle_command(CommandId::new(0xFF), &[], unicast(), &mut buf)
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::UnsupCommand)
        ));
    }

    // --- GroupEffect / take_dispatch_effects ---

    #[test]
    fn add_group_emits_added_effect() {
        let mut server = Server::default();
        let mut buf = [0u8; 32];
        let req: &[u8] = &[0x01, 0x01, 0x00, 0x01, 0x00, 0x00];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let outcome = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf).unwrap();
        assert_eq!(outcome.effects.group, GroupEffect::Added(0x0001));
    }

    #[test]
    fn add_group_duplicate_still_emits_added_effect() {
        // AddGroup returns Success even for duplicates; BDB deduplicates before
        // touching AIB.
        let mut server = Server::default();
        let mut buf = [0u8; 32];
        let req: &[u8] = &[0x01, 0x01, 0x00, 0x01, 0x00, 0x00];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf).unwrap();
        let outcome = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf).unwrap();
        assert_eq!(outcome.effects.group, GroupEffect::Added(0x0001));
    }

    #[test]
    fn remove_group_found_emits_removed_effect() {
        let mut server = Server::default();
        let mut buf = [0u8; 32];
        // add first
        server
            .handle_command(
                CommandId::new(0x00),
                &[0x01, 0x00, 0x00],
                unicast(),
                &mut buf,
            )
            .unwrap();
        // remove
        let remove: &[u8] = &[0x01, 0x02, 0x03, 0x01, 0x00];
        let (frame, _) = IncomingZclFrame::decode(remove).unwrap();
        let outcome = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf).unwrap();
        assert_eq!(outcome.effects.group, GroupEffect::Removed(0x0001));
    }

    #[test]
    fn remove_group_not_found_emits_no_effect() {
        let mut server = Server::default();
        let mut buf = [0u8; 32];
        let remove: &[u8] = &[0x01, 0x02, 0x03, 0x01, 0x00];
        let (frame, _) = IncomingZclFrame::decode(remove).unwrap();
        let outcome = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf).unwrap();
        assert_eq!(outcome.effects.group, GroupEffect::None);
    }

    #[test]
    fn remove_all_groups_emits_all_removed_effect() {
        let mut server = Server::default();
        let mut buf = [0u8; 32];
        let req: &[u8] = &[0x01, 0x03, 0x04];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let outcome = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf).unwrap();
        assert_eq!(outcome.effects.group, GroupEffect::AllRemoved);
    }

    #[test]
    fn effect_is_drained_after_read() {
        let mut server = Server::default();
        let mut buf = [0u8; 32];
        let req: &[u8] = &[0x01, 0x01, 0x00, 0x01, 0x00, 0x00];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf).unwrap();
        // second call returns empty effects (effect was already consumed)
        let req2: &[u8] = &[0x01, 0x02, 0x04]; // RemoveAllGroups (no queued effect yet)
        let (frame2, _) = IncomingZclFrame::decode(req2).unwrap();
        let outcome = zcl_cluster_dispatch(&mut server, &frame2, unicast(), &mut buf).unwrap();
        // This will be AllRemoved from the RemoveAllGroups, confirming the Add effect
        // was drained
        assert_eq!(outcome.effects.group, GroupEffect::AllRemoved);
    }
}
