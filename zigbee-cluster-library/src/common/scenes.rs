use heapless::Vec;

use crate::cluster_server::ClusterServer;
use crate::cluster_server::CommandResult;
use crate::cluster_server::DispatchContext;
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

/// One entry in the scene table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SceneEntry<const EXTENSION_BYTES: usize = 64> {
    pub group_id: u16,
    pub scene_id: u8,
    pub transition_time: u16,
    pub name: [u8; 16],
    pub name_len: u8,
    extension_bytes: Vec<u8, EXTENSION_BYTES>,
}

impl<const EXTENSION_BYTES: usize> SceneEntry<EXTENSION_BYTES> {
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    pub fn extension_bytes(&self) -> &[u8] {
        &self.extension_bytes
    }
}

/// ZCL Scenes cluster (0x0005).
///
/// `N` is the maximum scene table size.
/// `EXTENSION_BYTES` is the maximum stored extension-field-set payload per
/// scene.
///
/// Poll `last_recalled_scene()` after each `RecallScene` command and use
/// `last_recalled_entry()` or `last_recalled_extension_bytes()` to apply stored
/// extension-field sets in application code.
pub struct ScenesServer<const N: usize, const EXTENSION_BYTES: usize = 64> {
    /// Attribute 0x0004 — `NameSupport` (Bitmap8, R). Bit 7: names stored.
    pub name_support: u8,
    /// Attribute 0x0001 — `CurrentScene` (Uint8, R).
    pub current_scene: u8,
    /// Attribute 0x0002 — `CurrentGroup` (Uint16, R).
    pub current_group: u16,
    /// Attribute 0x0003 — `SceneValid` (Boolean, R).
    pub scene_valid: bool,
    scenes: Vec<SceneEntry<EXTENSION_BYTES>, N>,
    last_recalled: Option<(u16, u8)>,
}

impl<const N: usize, const EXTENSION_BYTES: usize> ScenesServer<N, EXTENSION_BYTES> {
    pub const fn new(name_support: u8) -> Self {
        Self {
            name_support,
            current_scene: 0,
            current_group: 0,
            scene_valid: false,
            scenes: Vec::new(),
            last_recalled: None,
        }
    }

    pub fn scene_count(&self) -> u8 {
        u8::try_from(self.scenes.len()).unwrap_or(u8::MAX)
    }

    pub fn capacity_remaining(&self) -> u8 {
        u8::try_from(N - self.scenes.len()).unwrap_or(u8::MAX)
    }

    pub fn scenes(&self) -> &[SceneEntry<EXTENSION_BYTES>] {
        &self.scenes
    }

    /// Returns the (`group_id`, `scene_id`) of the last recalled scene, if any.
    /// Cleared by the next `RecallScene` call.
    pub fn last_recalled_scene(&self) -> Option<(u16, u8)> {
        self.last_recalled
    }

    /// Returns the entry for the last recalled scene, if any.
    pub fn last_recalled_entry(&self) -> Option<&SceneEntry<EXTENSION_BYTES>> {
        let (group_id, scene_id) = self.last_recalled?;
        self.find_index(group_id, scene_id)
            .map(|idx| &self.scenes[idx])
    }

    /// Returns extension-field-set bytes for the last recalled scene, if any.
    pub fn last_recalled_extension_bytes(&self) -> Option<&[u8]> {
        self.last_recalled_entry().map(SceneEntry::extension_bytes)
    }

    /// Clear the `last_recalled` marker after the application has handled it.
    pub fn consume_recall(&mut self) {
        self.last_recalled = None;
    }

    fn find_index(&self, group_id: u16, scene_id: u8) -> Option<usize> {
        self.scenes
            .iter()
            .position(|s| s.group_id == group_id && s.scene_id == scene_id)
    }

    fn upsert(
        &mut self,
        group_id: u16,
        scene_id: u8,
        transition_time: u16,
        name: &[u8],
        extension_bytes: &[u8],
    ) -> Status {
        if name.len() > 16 || extension_bytes.len() > EXTENSION_BYTES {
            return Status::InvalidField;
        }

        let name_len = u8::try_from(name.len()).unwrap_or(16);
        if let Some(idx) = self.find_index(group_id, scene_id) {
            let e = &mut self.scenes[idx];
            e.transition_time = transition_time;
            e.name_len = name_len;
            e.name = [0u8; 16];
            e.name[..name.len()].copy_from_slice(name);
            e.extension_bytes.clear();
            let _ = e.extension_bytes.extend_from_slice(extension_bytes);
            Status::Success
        } else if self.scenes.is_full() {
            Status::InsufficientSpace
        } else {
            let mut entry = SceneEntry {
                group_id,
                scene_id,
                transition_time,
                name: [0u8; 16],
                name_len,
                extension_bytes: Vec::new(),
            };
            entry.name[..name.len()].copy_from_slice(name);
            let _ = entry.extension_bytes.extend_from_slice(extension_bytes);
            let _ = self.scenes.push(entry);
            Status::Success
        }
    }

    fn remove_for_group(&mut self, group_id: u16) {
        self.scenes.retain(|s| s.group_id != group_id);
    }

    fn invalidate_if_current(&mut self, group_id: u16, scene_id: u8) {
        if self.current_group == group_id && self.current_scene == scene_id {
            self.scene_valid = false;
        }
    }
}

impl<const N: usize, const EXTENSION_BYTES: usize> Default for ScenesServer<N, EXTENSION_BYTES> {
    fn default() -> Self {
        Self::new(0x00)
    }
}

fn parse_group_and_scene(payload: &[u8]) -> Option<(u16, u8)> {
    let group_id = u16::from_le_bytes([*payload.first()?, *payload.get(1)?]);
    let scene_id = *payload.get(2)?;
    Some((group_id, scene_id))
}

type AddSceneFields<'a> = (u16, u8, u16, &'a [u8], &'a [u8]);
fn parse_add_scene(payload: &[u8]) -> Option<AddSceneFields<'_>> {
    if payload.len() < 6 {
        return None;
    }
    let group_id = u16::from_le_bytes([payload[0], payload[1]]);
    let scene_id = payload[2];
    let transition_time = u16::from_le_bytes([payload[3], payload[4]]);
    let name_len = payload[5] as usize;
    let extension_start = 6 + name_len;
    if payload.len() < extension_start {
        return None;
    }
    Some((
        group_id,
        scene_id,
        transition_time,
        &payload[6..extension_start],
        &payload[extension_start..],
    ))
}

fn write_status_group_scene(
    buf: &mut [u8],
    status: Status,
    group_id: u16,
    scene_id: u8,
) -> Result<usize, ZclError> {
    if buf.len() < 4 {
        return Err(ZclError::BufferTooSmall);
    }
    buf[0] = status as u8;
    let b = group_id.to_le_bytes();
    buf[1] = b[0];
    buf[2] = b[1];
    buf[3] = scene_id;
    Ok(4)
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

impl<const N: usize, const EXTENSION_BYTES: usize> ClusterServer
    for ScenesServer<N, EXTENSION_BYTES>
{
    const CLUSTER_ID: ClusterId = ClusterId::new(0x0005);

    fn read_attribute(
        &self,
        id: AttributeId,
        buf: &mut [u8],
    ) -> Result<(TypeId, usize), AttrError> {
        match id.0 {
            0x0000 => Ok(encode_attr::<u8>(self.scene_count(), buf)?),
            0x0001 => Ok(encode_attr::<u8>(self.current_scene, buf)?),
            0x0002 => Ok(encode_attr::<u16>(self.current_group, buf)?),
            0x0003 => Ok(encode_attr::<bool>(self.scene_valid, buf)?),
            0x0004 => Ok(encode_attr::<Bitmap8<u8>>(self.name_support, buf)?),
            0xFFFD => Ok(encode_attr::<u16>(1, buf)?),
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }

    read_only_attrs![0x0000..=0x0004 | 0xFFFD];

    #[allow(clippy::too_many_lines)]
    fn handle_command(
        &mut self,
        id: CommandId,
        payload: &[u8],
        _ctx: DispatchContext,
        buf: &mut [u8],
    ) -> Result<CommandResult, ZclError> {
        match id.0 {
            // AddScene → AddSceneResponse (0x00)
            0x00 => {
                let (group_id, scene_id, transition_time, name, extension_bytes) =
                    parse_add_scene(payload).ok_or(ZclError::InsufficientBytes)?;
                let status =
                    self.upsert(group_id, scene_id, transition_time, name, extension_bytes);
                let len = write_status_group_scene(buf, status, group_id, scene_id)?;
                Ok(CommandResult::Payload {
                    command_id: CommandId::new(0x00),
                    len,
                })
            }
            // ViewScene → ViewSceneResponse (0x01)
            0x01 => {
                let (group_id, scene_id) =
                    parse_group_and_scene(payload).ok_or(ZclError::InsufficientBytes)?;
                if let Some(idx) = self.find_index(group_id, scene_id) {
                    let e = &self.scenes[idx];
                    let name_len = e.name_len as usize;
                    let extension_len = e.extension_bytes.len();
                    // status(1) + group_id(2) + scene_id(1) + transition_time(2) + name_len(1)
                    // + name + extension field sets
                    let needed = 7 + name_len + extension_len;
                    if buf.len() < needed {
                        return Err(ZclError::BufferTooSmall);
                    }
                    buf[0] = Status::Success as u8;
                    let gb = group_id.to_le_bytes();
                    buf[1] = gb[0];
                    buf[2] = gb[1];
                    buf[3] = scene_id;
                    let tb = e.transition_time.to_le_bytes();
                    buf[4] = tb[0];
                    buf[5] = tb[1];
                    buf[6] = e.name_len;
                    buf[7..7 + name_len].copy_from_slice(&e.name[..name_len]);
                    buf[7 + name_len..needed].copy_from_slice(&e.extension_bytes);
                    Ok(CommandResult::Payload {
                        command_id: CommandId::new(0x01),
                        len: needed,
                    })
                } else {
                    // status(1) + group_id(2) + scene_id(1) + transition_time(2) + name_len(1)
                    if buf.len() < 7 {
                        return Err(ZclError::BufferTooSmall);
                    }
                    buf[0] = Status::NotFound as u8;
                    let gb = group_id.to_le_bytes();
                    buf[1] = gb[0];
                    buf[2] = gb[1];
                    buf[3] = scene_id;
                    buf[4] = 0;
                    buf[5] = 0; // transition_time = 0
                    buf[6] = 0; // empty name
                    Ok(CommandResult::Payload {
                        command_id: CommandId::new(0x01),
                        len: 7,
                    })
                }
            }
            // RemoveScene → RemoveSceneResponse (0x02)
            0x02 => {
                let (group_id, scene_id) =
                    parse_group_and_scene(payload).ok_or(ZclError::InsufficientBytes)?;
                let status = if let Some(idx) = self.find_index(group_id, scene_id) {
                    self.scenes.swap_remove(idx);
                    self.invalidate_if_current(group_id, scene_id);
                    Status::Success
                } else {
                    Status::NotFound
                };
                let len = write_status_group_scene(buf, status, group_id, scene_id)?;
                Ok(CommandResult::Payload {
                    command_id: CommandId::new(0x02),
                    len,
                })
            }
            // RemoveAllScenes → RemoveAllScenesResponse (0x03)
            0x03 => {
                let group_id = payload
                    .get(..2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .ok_or(ZclError::InsufficientBytes)?;
                self.remove_for_group(group_id);
                if self.current_group == group_id {
                    self.scene_valid = false;
                }
                let len = write_status_and_group(buf, Status::Success, group_id)?;
                Ok(CommandResult::Payload {
                    command_id: CommandId::new(0x03),
                    len,
                })
            }
            // StoreScene → StoreSceneResponse (0x04)
            0x04 => {
                let (group_id, scene_id) =
                    parse_group_and_scene(payload).ok_or(ZclError::InsufficientBytes)?;
                let status = self.upsert(group_id, scene_id, 0, &[], &[]);
                if status == Status::Success {
                    self.current_scene = scene_id;
                    self.current_group = group_id;
                    self.scene_valid = true;
                }
                let len = write_status_group_scene(buf, status, group_id, scene_id)?;
                Ok(CommandResult::Payload {
                    command_id: CommandId::new(0x04),
                    len,
                })
            }
            // RecallScene → DefaultResponse(Success) (no specific response command)
            0x05 => {
                let (group_id, scene_id) =
                    parse_group_and_scene(payload).ok_or(ZclError::InsufficientBytes)?;
                if self.find_index(group_id, scene_id).is_some() {
                    self.current_scene = scene_id;
                    self.current_group = group_id;
                    self.scene_valid = true;
                    self.last_recalled = Some((group_id, scene_id));
                    Ok(CommandResult::DefaultResponse(Status::Success))
                } else {
                    Ok(CommandResult::DefaultResponse(Status::NotFound))
                }
            }
            // GetSceneMembership → GetSceneMembershipResponse (0x06)
            0x06 => {
                let group_id = payload
                    .get(..2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .ok_or(ZclError::InsufficientBytes)?;
                let capacity = self.capacity_remaining();
                // Collect matching scene IDs
                let mut count: u8 = 0;
                // status(1) + capacity(1) + group_id(2) + count(1) + scene_ids
                if buf.len() < 5 {
                    return Err(ZclError::BufferTooSmall);
                }
                for scene in &self.scenes {
                    if scene.group_id == group_id {
                        let off = 5 + count as usize;
                        if off >= buf.len() {
                            return Err(ZclError::BufferTooSmall);
                        }
                        buf[off] = scene.scene_id;
                        count += 1;
                    }
                }
                buf[0] = Status::Success as u8;
                buf[1] = capacity;
                let gb = group_id.to_le_bytes();
                buf[2] = gb[0];
                buf[3] = gb[1];
                buf[4] = count;
                let len = 5 + count as usize;
                Ok(CommandResult::Payload {
                    command_id: CommandId::new(0x06),
                    len,
                })
            }
            _ => Ok(CommandResult::DefaultResponse(Status::UnsupCommand)),
        }
    }

    fn attribute_list() -> &'static [AttrInfo] {
        attr_list![
            (0x0000, Uint8, READ),
            (0x0001, Uint8, READ),
            (0x0002, Uint16, READ),
            (0x0003, Boolean, READ),
            (0x0004, Bitmap8, READ),
            (0xFFFD, Uint16, READ),
        ]
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

    type Server = ScenesServer<4>;

    fn add_scene(server: &mut Server, group_id: u16, scene_id: u8, tt: u16, name: &[u8]) {
        let mut buf = [0u8; 32];
        let gb = group_id.to_le_bytes();
        let tb = tt.to_le_bytes();
        let mut payload = [0u8; 32];
        payload[0] = gb[0];
        payload[1] = gb[1];
        payload[2] = scene_id;
        payload[3] = tb[0];
        payload[4] = tb[1];
        payload[5] = u8::try_from(name.len()).unwrap_or(u8::MAX);
        payload[6..6 + name.len()].copy_from_slice(name);
        server
            .handle_command(
                CommandId::new(0x00),
                &payload[..6 + name.len()],
                unicast(),
                &mut buf,
            )
            .unwrap();
    }

    fn add_scene_with_extension(
        server: &mut Server,
        group_id: u16,
        scene_id: u8,
        tt: u16,
        name: &[u8],
        extension_bytes: &[u8],
    ) {
        let mut buf = [0u8; 32];
        let gb = group_id.to_le_bytes();
        let tb = tt.to_le_bytes();
        let mut payload = [0u8; 64];
        payload[0] = gb[0];
        payload[1] = gb[1];
        payload[2] = scene_id;
        payload[3] = tb[0];
        payload[4] = tb[1];
        payload[5] = u8::try_from(name.len()).unwrap_or(u8::MAX);
        payload[6..6 + name.len()].copy_from_slice(name);
        let extension_start = 6 + name.len();
        payload[extension_start..extension_start + extension_bytes.len()]
            .copy_from_slice(extension_bytes);
        server
            .handle_command(
                CommandId::new(0x00),
                &payload[..extension_start + extension_bytes.len()],
                unicast(),
                &mut buf,
            )
            .unwrap();
    }

    // ---- attribute tests ----

    #[test]
    fn scene_count_reads_as_uint8() {
        let server = Server::default();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint8);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn scene_valid_reads_as_boolean() {
        let server = Server::default();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0x0003), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Boolean);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x00); // false
    }

    #[test]
    fn all_mandatory_attributes_readable() {
        let server = Server::default();
        for attr in [0x0000u16, 0x0001, 0x0002, 0x0003, 0x0004, 0xFFFD] {
            let mut buf = [0u8; 4];
            assert!(
                server
                    .read_attribute(AttributeId::new(attr), &mut buf)
                    .is_ok(),
                "attr 0x{attr:04X} not readable"
            );
        }
    }

    #[test]
    fn write_attribute_returns_read_only() {
        let mut server = Server::default();
        for attr in [0x0000u16, 0x0001, 0x0002, 0x0003, 0x0004, 0xFFFD] {
            assert_eq!(
                server.write_attribute(AttributeId::new(attr), TypeId::Uint8, &[0x00]),
                Err(AttrError::ReadOnly)
            );
        }
    }

    #[test]
    fn attribute_list_has_cluster_revision_entry() {
        assert_eq!(Server::attribute_list().len(), 6);
        assert_eq!(Server::attribute_list()[5].id, AttributeId::new(0xFFFD));
    }

    #[test]
    fn cluster_revision_reads_as_uint16_one() {
        let server = Server::default();
        let mut buf = [0u8; 4];
        let (tid, n) = server
            .read_attribute(AttributeId::new(0xFFFD), &mut buf)
            .unwrap();
        assert_eq!(tid, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 1);
    }

    // ---- AddScene (0x00) ----

    #[test]
    fn add_scene_success() {
        let mut server = Server::default();
        let mut buf = [0u8; 16];
        // group=0x0001, scene=0x01, tt=10, name="Foo"
        let payload: &[u8] = &[0x01, 0x00, 0x01, 0x0A, 0x00, 0x03, b'F', b'o', b'o'];
        let result = server
            .handle_command(CommandId::new(0x00), payload, unicast(), &mut buf)
            .unwrap();
        assert!(
            matches!(result, CommandResult::Payload { command_id, len: 4 } if command_id == CommandId::new(0x00))
        );
        assert_eq!(buf[0], Status::Success as u8);
        assert_eq!(u16::from_le_bytes([buf[1], buf[2]]), 0x0001);
        assert_eq!(buf[3], 0x01);
        assert_eq!(server.scene_count(), 1);
    }

    #[test]
    fn add_scene_updates_existing_entry() {
        let mut server = Server::default();
        add_scene(&mut server, 0x0001, 0x01, 5, b"Old");
        add_scene(&mut server, 0x0001, 0x01, 10, b"New");
        assert_eq!(server.scene_count(), 1); // no duplicate
        assert_eq!(server.scenes()[0].transition_time, 10);
    }

    #[test]
    fn add_scene_table_full_returns_insufficient_space() {
        let mut server = Server::default();
        for i in 0u8..4 {
            add_scene(&mut server, 0x0001, i, 0, b"");
        }
        let mut buf = [0u8; 16];
        let payload: &[u8] = &[0x01, 0x00, 0x04, 0x00, 0x00, 0x00];
        let result = server
            .handle_command(CommandId::new(0x00), payload, unicast(), &mut buf)
            .unwrap();
        assert_eq!(buf[0], Status::InsufficientSpace as u8);
        assert!(matches!(result, CommandResult::Payload { .. }));
    }

    #[test]
    fn add_scene_rejects_names_longer_than_sixteen_bytes() {
        let mut server = Server::default();
        let mut buf = [0u8; 16];
        let name = *b"0123456789abcdefg";
        let mut payload = [0u8; 32];
        payload[0] = 0x01;
        payload[2] = 0x02;
        payload[5] = u8::try_from(name.len()).unwrap_or(u8::MAX);
        payload[6..6 + name.len()].copy_from_slice(&name);
        let result = server
            .handle_command(
                CommandId::new(0x00),
                &payload[..6 + name.len()],
                unicast(),
                &mut buf,
            )
            .unwrap();
        assert!(
            matches!(result, CommandResult::Payload { command_id, len: 4 } if command_id == CommandId::new(0x00))
        );
        assert_eq!(buf[0], Status::InvalidField as u8);
        assert_eq!(server.scene_count(), 0);
    }

    // ---- ViewScene (0x01) ----

    #[test]
    fn view_scene_found_returns_entry() {
        let mut server = Server::default();
        add_scene(&mut server, 0x0002, 0x03, 15, b"Day");
        let mut buf = [0u8; 32];
        let payload: &[u8] = &[0x02, 0x00, 0x03];
        let result = server
            .handle_command(CommandId::new(0x01), payload, unicast(), &mut buf)
            .unwrap();
        assert!(
            matches!(result, CommandResult::Payload { command_id, len: 10 } if command_id == CommandId::new(0x01))
        );
        assert_eq!(buf[0], Status::Success as u8);
        assert_eq!(buf[3], 0x03); // scene_id
        assert_eq!(u16::from_le_bytes([buf[4], buf[5]]), 15); // transition_time
        assert_eq!(buf[6], 3); // name_len
        assert_eq!(&buf[7..10], b"Day");
        assert_eq!(server.scenes()[0].extension_bytes(), b"");
    }

    #[test]
    fn add_and_view_scene_round_trips_extension_field_sets() {
        let mut server = Server::default();
        let extension_bytes = [0x06, 0x00, 0x03, 0x00, 0x00, 0x10, 0x01];
        add_scene_with_extension(&mut server, 0x0002, 0x04, 15, b"Day", &extension_bytes);

        assert_eq!(server.scenes()[0].extension_bytes(), &extension_bytes);

        let mut buf = [0u8; 32];
        let result = server
            .handle_command(
                CommandId::new(0x01),
                &[0x02, 0x00, 0x04],
                unicast(),
                &mut buf,
            )
            .unwrap();
        assert!(
            matches!(result, CommandResult::Payload { command_id, len: 17 } if command_id == CommandId::new(0x01))
        );
        assert_eq!(&buf[7..10], b"Day");
        assert_eq!(&buf[10..17], &extension_bytes);
    }

    #[test]
    fn view_scene_not_found() {
        let mut server = Server::default();
        let mut buf = [0u8; 16];
        let result = server
            .handle_command(
                CommandId::new(0x01),
                &[0x01, 0x00, 0x99],
                unicast(),
                &mut buf,
            )
            .unwrap();
        assert!(
            matches!(result, CommandResult::Payload { command_id, len: 7 } if command_id == CommandId::new(0x01))
        );
        assert_eq!(buf[0], Status::NotFound as u8);
    }

    // ---- RemoveScene (0x02) ----

    #[test]
    fn remove_scene_found() {
        let mut server = Server::default();
        add_scene(&mut server, 0x0001, 0x01, 0, b"");
        let mut buf = [0u8; 8];
        let result = server
            .handle_command(
                CommandId::new(0x02),
                &[0x01, 0x00, 0x01],
                unicast(),
                &mut buf,
            )
            .unwrap();
        assert!(
            matches!(result, CommandResult::Payload { command_id, len: 4 } if command_id == CommandId::new(0x02))
        );
        assert_eq!(buf[0], Status::Success as u8);
        assert_eq!(server.scene_count(), 0);
    }

    #[test]
    fn remove_scene_not_found() {
        let mut server = Server::default();
        let mut buf = [0u8; 8];
        let result = server
            .handle_command(
                CommandId::new(0x02),
                &[0x01, 0x00, 0x42],
                unicast(),
                &mut buf,
            )
            .unwrap();
        assert_eq!(buf[0], Status::NotFound as u8);
        assert!(matches!(result, CommandResult::Payload { .. }));
    }

    #[test]
    fn remove_current_scene_invalidates_scene_valid() {
        let mut server = Server::default();
        add_scene(&mut server, 0x0001, 0x01, 0, b"");
        // recall it to set current
        server
            .handle_command(
                CommandId::new(0x05),
                &[0x01, 0x00, 0x01],
                unicast(),
                &mut [0u8; 8],
            )
            .unwrap();
        assert!(server.scene_valid);
        server
            .handle_command(
                CommandId::new(0x02),
                &[0x01, 0x00, 0x01],
                unicast(),
                &mut [0u8; 8],
            )
            .unwrap();
        assert!(!server.scene_valid);
    }

    // ---- RemoveAllScenes (0x03) ----

    #[test]
    fn remove_all_scenes_for_group() {
        let mut server = Server::default();
        add_scene(&mut server, 0x0001, 0x01, 0, b"");
        add_scene(&mut server, 0x0001, 0x02, 0, b"");
        add_scene(&mut server, 0x0002, 0x01, 0, b""); // different group
        let mut buf = [0u8; 8];
        let result = server
            .handle_command(CommandId::new(0x03), &[0x01, 0x00], unicast(), &mut buf)
            .unwrap();
        assert!(
            matches!(result, CommandResult::Payload { command_id, len: 3 } if command_id == CommandId::new(0x03))
        );
        assert_eq!(buf[0], Status::Success as u8);
        // group 0x0001 scenes removed; group 0x0002 scene remains
        assert_eq!(server.scene_count(), 1);
    }

    // ---- StoreScene (0x04) ----

    #[test]
    fn store_scene_creates_entry_and_marks_valid() {
        let mut server = Server::default();
        let mut buf = [0u8; 8];
        let result = server
            .handle_command(
                CommandId::new(0x04),
                &[0x01, 0x00, 0x02],
                unicast(),
                &mut buf,
            )
            .unwrap();
        assert!(
            matches!(result, CommandResult::Payload { command_id, .. } if command_id == CommandId::new(0x04))
        );
        assert_eq!(buf[0], Status::Success as u8);
        assert_eq!(server.current_scene, 0x02);
        assert_eq!(server.current_group, 0x0001);
        assert!(server.scene_valid);
    }

    // ---- RecallScene (0x05) ----

    #[test]
    fn recall_scene_found_sets_current_and_marks_recalled() {
        let mut server = Server::default();
        add_scene(&mut server, 0x0003, 0x05, 10, b"Night");
        let result = server
            .handle_command(
                CommandId::new(0x05),
                &[0x03, 0x00, 0x05],
                unicast(),
                &mut [0u8; 4],
            )
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::Success)
        ));
        assert_eq!(server.current_scene, 0x05);
        assert_eq!(server.current_group, 0x0003);
        assert!(server.scene_valid);
        assert_eq!(server.last_recalled_scene(), Some((0x0003, 0x05)));
    }

    #[test]
    fn recall_scene_exposes_extension_field_sets() {
        let mut server = Server::default();
        let extension_bytes = [0x08, 0x00, 0x02, 0x00, 0x01, 0x20];
        add_scene_with_extension(&mut server, 0x0003, 0x06, 10, b"Night", &extension_bytes);

        server
            .handle_command(
                CommandId::new(0x05),
                &[0x03, 0x00, 0x06],
                unicast(),
                &mut [0u8; 4],
            )
            .unwrap();

        assert_eq!(server.last_recalled_scene(), Some((0x0003, 0x06)));
        assert_eq!(
            server
                .last_recalled_entry()
                .map(SceneEntry::extension_bytes),
            Some(&extension_bytes[..])
        );
        assert_eq!(
            server.last_recalled_extension_bytes(),
            Some(&extension_bytes[..])
        );
    }

    #[test]
    fn recall_scene_not_found_returns_not_found() {
        let mut server = Server::default();
        let result = server
            .handle_command(
                CommandId::new(0x05),
                &[0x01, 0x00, 0x99],
                unicast(),
                &mut [0u8; 4],
            )
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::NotFound)
        ));
        assert!(!server.scene_valid);
    }

    #[test]
    fn consume_recall_clears_last_recalled() {
        let mut server = Server::default();
        add_scene(&mut server, 0x0001, 0x01, 0, b"");
        server
            .handle_command(
                CommandId::new(0x05),
                &[0x01, 0x00, 0x01],
                unicast(),
                &mut [0u8; 4],
            )
            .unwrap();
        assert!(server.last_recalled_scene().is_some());
        server.consume_recall();
        assert!(server.last_recalled_scene().is_none());
    }

    // ---- GetSceneMembership (0x06) ----

    #[test]
    fn get_scene_membership_returns_scenes_for_group() {
        let mut server = Server::default();
        add_scene(&mut server, 0x0001, 0x01, 0, b"");
        add_scene(&mut server, 0x0001, 0x02, 0, b"");
        add_scene(&mut server, 0x0002, 0x01, 0, b""); // different group
        let mut buf = [0u8; 16];
        let result = server
            .handle_command(CommandId::new(0x06), &[0x01, 0x00], unicast(), &mut buf)
            .unwrap();
        assert!(
            matches!(result, CommandResult::Payload { command_id, len: 7 } if command_id == CommandId::new(0x06))
        );
        assert_eq!(buf[0], Status::Success as u8);
        assert_eq!(buf[1], 1); // capacity = 4-3=1
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), 0x0001);
        assert_eq!(buf[4], 2); // count
    }

    #[test]
    fn get_scene_membership_empty_group_returns_zero_count() {
        let mut server = Server::default();
        let mut buf = [0u8; 16];
        let result = server
            .handle_command(CommandId::new(0x06), &[0x99, 0x00], unicast(), &mut buf)
            .unwrap();
        assert!(
            matches!(result, CommandResult::Payload { command_id, len: 5 } if command_id == CommandId::new(0x06))
        );
        assert_eq!(buf[4], 0); // no scenes
    }

    // ---- dispatch integration ----

    #[test]
    fn dispatch_read_scene_count() {
        let mut server = Server::default();
        add_scene(&mut server, 0x0001, 0x01, 0, b"");
        let mut buf = [0u8; 32];
        let req: &[u8] = &[0x00, 0x01, 0x00, 0x00, 0x00];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;
        assert_eq!(n, 8);
        assert_eq!(buf[5], 0x00); // Success
        assert_eq!(buf[6], TypeId::Uint8.as_u8());
        assert_eq!(buf[7], 1);
    }

    #[test]
    fn unknown_command_returns_unsup_command() {
        let mut server = Server::default();
        let mut buf = [0u8; 8];
        let result = server
            .handle_command(CommandId::new(0xFF), &[], unicast(), &mut buf)
            .unwrap();
        assert!(matches!(
            result,
            CommandResult::DefaultResponse(Status::UnsupCommand)
        ));
    }
}
