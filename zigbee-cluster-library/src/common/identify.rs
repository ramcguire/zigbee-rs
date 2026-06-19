use crate::cluster_server::ClusterServer;
use crate::cluster_server::ClusterTick;
use crate::cluster_server::CommandResult;
use crate::cluster_server::DispatchContext;
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

/// ZCL Identify cluster (0x0003).
///
/// Time is tracked as an absolute monotonic deadline (`identify_until_ms`).
/// `cached_remaining` is updated each `ClusterServer::tick` call and read by
/// `remaining()` and `read_attribute(0x0000)`.
///
/// Two ways to start identifying:
/// - `Identify` command (0x00) — sets the deadline immediately via
///   `ctx.now_ms`.
/// - `write_attribute(0x0000)` — stores seconds; the deadline is initialized
///   lazily on the first `tick(now_ms)` call afterward.
///
/// `IdentifyQuery` (0x01) computes remaining time live from the deadline and
/// `ctx.now_ms`, so it is accurate even between tick calls.
#[derive(Default)]
pub struct IdentifyServer {
    identify_until_ms: Option<u32>,
    cached_remaining: u16,
}

impl IdentifyServer {
    pub const fn new() -> Self {
        Self {
            identify_until_ms: None,
            cached_remaining: 0,
        }
    }

    pub fn is_identifying(&self) -> bool {
        self.cached_remaining > 0
    }

    /// Cached remaining seconds. Updated by `ClusterServer::tick`.
    pub fn remaining(&self) -> u16 {
        self.cached_remaining
    }

    /// Live remaining seconds computed from the deadline and `now_ms`.
    /// Falls back to `cached_remaining` when no deadline is set (between
    /// `write_attribute` and the first `tick`).
    fn remaining_at(&self, now_ms: u32) -> u16 {
        self.identify_until_ms
            .map_or(self.cached_remaining, |deadline| {
                // now_ms.wrapping_sub(deadline) < 0x8000_0000 means now >= deadline: expired.
                if now_ms.wrapping_sub(deadline) < 0x8000_0000u32 {
                    0
                } else {
                    let remaining_ms = deadline.wrapping_sub(now_ms);
                    remaining_ms.div_ceil(1000).try_into().unwrap_or(u16::MAX)
                }
            })
    }
}

impl ClusterServer for IdentifyServer {
    const CLUSTER_ID: ClusterId = ClusterId::new(0x0003);

    fn read_attribute(
        &self,
        id: AttributeId,
        buf: &mut [u8],
    ) -> Result<(TypeId, usize), AttrError> {
        match id.0 {
            0x0000 => Ok(encode_attr::<u16>(self.cached_remaining, buf)?),
            0xFFFD => Ok(encode_attr::<u16>(2, buf)?),
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }

    fn check_write_attribute(
        &self,
        id: AttributeId,
        type_id: TypeId,
        _data: &[u8],
    ) -> Result<(), AttrError> {
        match id.0 {
            0x0000 if type_id == TypeId::Uint16 => Ok(()),
            0x0000 => Err(AttrError::InvalidDataType),
            0xFFFD => Err(AttrError::ReadOnly),
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }

    fn write_attribute(
        &mut self,
        id: AttributeId,
        _type_id: TypeId,
        data: &[u8],
    ) -> Result<(), AttrError> {
        match id.0 {
            0x0000 if data.len() >= 2 => {
                let seconds = u16::from_le_bytes([data[0], data[1]]);
                self.cached_remaining = seconds;
                // Deadline initialized lazily on the next tick() — no now_ms available here.
                self.identify_until_ms = None;
                Ok(())
            }
            0x0000 => Err(AttrError::Codec(ZclError::InsufficientBytes)),
            0xFFFD => Err(AttrError::ReadOnly),
            _ => Err(AttrError::UnsupportedAttribute),
        }
    }

    fn handle_command(
        &mut self,
        id: CommandId,
        payload: &[u8],
        ctx: DispatchContext,
        buf: &mut [u8],
    ) -> Result<CommandResult, ZclError> {
        match id.0 {
            // Identify (0x00): set deadline immediately from ctx.now_ms.
            0x00 => {
                if payload.len() < 2 {
                    return Err(ZclError::InsufficientBytes);
                }
                let seconds = u16::from_le_bytes([payload[0], payload[1]]);
                self.cached_remaining = seconds;
                self.identify_until_ms = if seconds == 0 {
                    None
                } else {
                    Some(ctx.now_ms.wrapping_add(u32::from(seconds) * 1000))
                };
                Ok(CommandResult::DefaultResponse(Status::Success))
            }
            // IdentifyQuery (0x01): return live remaining time from deadline + ctx.now_ms.
            0x01 => {
                if buf.len() < 2 {
                    return Err(ZclError::BufferTooSmall);
                }
                let timeout = self.remaining_at(ctx.now_ms);
                let [lo, hi] = timeout.to_le_bytes();
                buf[0] = lo;
                buf[1] = hi;
                Ok(CommandResult::Payload {
                    command_id: CommandId::new(0x00),
                    len: 2,
                })
            }
            _ => Ok(CommandResult::DefaultResponse(Status::UnsupCommand)),
        }
    }

    fn tick(&mut self, now_ms: u32) -> ClusterTick {
        match self.identify_until_ms {
            None if self.cached_remaining == 0 => ClusterTick::default(),

            // Lazy init: write_attribute stored seconds but no deadline yet.
            None => {
                let deadline = now_ms.wrapping_add(u32::from(self.cached_remaining) * 1000);
                self.identify_until_ms = Some(deadline);
                ClusterTick {
                    changed: false,
                    next_tick_ms: Some(now_ms.wrapping_add(1000)),
                }
            }

            Some(deadline) => {
                // now_ms.wrapping_sub(deadline) < 0x8000_0000 means now >= deadline: expired.
                if now_ms.wrapping_sub(deadline) < 0x8000_0000u32 {
                    let changed = self.cached_remaining != 0;
                    self.cached_remaining = 0;
                    self.identify_until_ms = None;
                    ClusterTick {
                        changed,
                        next_tick_ms: None,
                    }
                } else {
                    let remaining_ms = deadline.wrapping_sub(now_ms);
                    let remaining_secs = remaining_ms.div_ceil(1000).try_into().unwrap_or(u16::MAX);
                    let changed = remaining_secs != self.cached_remaining;
                    self.cached_remaining = remaining_secs;
                    ClusterTick {
                        changed,
                        next_tick_ms: Some(now_ms.wrapping_add(1000)),
                    }
                }
            }
        }
    }

    fn attribute_list() -> &'static [AttrInfo] {
        static LIST: [AttrInfo; 2] = [
            AttrInfo {
                id: AttributeId::new(0x0000),
                type_id: TypeId::Uint16,
                access: AccessFlags::READ_WRITE,
            },
            AttrInfo {
                id: AttributeId::new(0xFFFD),
                type_id: TypeId::Uint16,
                access: AccessFlags::READ,
            },
        ];
        &LIST
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_server::DispatchContext;
    use crate::cluster_server::zcl_cluster_dispatch;
    use crate::frame::IncomingZclFrame;

    fn unicast_at(now_ms: u32) -> DispatchContext {
        DispatchContext::unicast(now_ms, None)
    }

    fn unicast() -> DispatchContext {
        unicast_at(0)
    }

    // --- basics ---

    #[test]
    fn identify_time_starts_at_zero() {
        let server = IdentifyServer::new();
        assert_eq!(server.remaining(), 0);
        assert!(!server.is_identifying());
    }

    // --- tick ---

    #[test]
    fn tick_noop_when_not_identifying() {
        let mut server = IdentifyServer::new();
        let ct = server.tick(0);
        assert!(!ct.changed);
        assert_eq!(ct.next_tick_ms, None);
    }

    #[test]
    fn tick_past_deadline_returns_changed_and_no_next_tick() {
        let mut server = IdentifyServer::new();
        // Identify 5 s at t=0 → deadline = 5_000 ms.
        server
            .handle_command(CommandId::new(0x00), &[5, 0], unicast_at(0), &mut [])
            .unwrap();
        assert_eq!(server.remaining(), 5);

        // Tick at t=5_000 (exactly at deadline) → expired.
        let ct = server.tick(5_000);
        assert!(ct.changed);
        assert_eq!(ct.next_tick_ms, None);
        assert_eq!(server.remaining(), 0);
        assert!(!server.is_identifying());
    }

    #[test]
    fn tick_advances_cached_remaining() {
        let mut server = IdentifyServer::new();
        // 10 s at t=0 → deadline = 10_000 ms.
        server
            .handle_command(CommandId::new(0x00), &[10, 0], unicast_at(0), &mut [])
            .unwrap();

        let ct = server.tick(3_000); // 7 s remain (ceil((10000-3000)/1000))
        assert!(ct.changed);
        assert_eq!(server.remaining(), 7);
        assert_eq!(ct.next_tick_ms, Some(4_000));
    }

    #[test]
    fn tick_no_change_within_same_second() {
        let mut server = IdentifyServer::new();
        server
            .handle_command(CommandId::new(0x00), &[10, 0], unicast_at(0), &mut [])
            .unwrap();

        // Two ticks < 1 s apart — cached_remaining stays 10 both times.
        server.tick(500);
        let ct = server.tick(999); // ceil(9001/1000) = 10, unchanged
        assert!(!ct.changed);
    }

    #[test]
    fn write_attribute_then_tick_initializes_deadline() {
        let mut server = IdentifyServer::new();
        server
            .write_attribute(AttributeId::new(0x0000), TypeId::Uint16, &[30, 0])
            .unwrap();
        assert_eq!(server.remaining(), 30);

        // First tick at t=0 → lazy init; deadline = 30_000 ms; no change in remaining.
        let ct = server.tick(0);
        assert!(!ct.changed);
        assert_eq!(ct.next_tick_ms, Some(1_000));
        assert_eq!(server.remaining(), 30);

        // Tick at t=30_000 → expired.
        let ct = server.tick(30_000);
        assert!(ct.changed);
        assert_eq!(server.remaining(), 0);
        assert_eq!(ct.next_tick_ms, None);
    }

    // --- commands ---

    #[test]
    fn identify_command_sets_timer() {
        let req: &[u8] = &[0x01, 0x01, 0x00, 0x1e, 0x00]; // cmd=0x00, identify_time=30
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = IdentifyServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        assert_eq!(n, 5);
        assert_eq!(buf[2], 0x0b); // DefaultResponse
        assert_eq!(buf[4], Status::Success as u8);
        assert_eq!(server.remaining(), 30);
    }

    #[test]
    fn identify_command_zero_stops_identifying() {
        let mut server = IdentifyServer::new();
        server
            .handle_command(CommandId::new(0x00), &[30, 0], unicast_at(0), &mut [])
            .unwrap();
        assert!(server.is_identifying());

        server
            .handle_command(CommandId::new(0x00), &[0, 0], unicast_at(1_000), &mut [])
            .unwrap();
        assert!(!server.is_identifying());
        assert_eq!(server.remaining(), 0);
    }

    #[test]
    fn identify_query_uses_ctx_now_ms() {
        let mut server = IdentifyServer::new();
        // 30 s at t=0 → deadline = 30_000.
        server
            .handle_command(CommandId::new(0x00), &[30, 0], unicast_at(0), &mut [])
            .unwrap();

        // Query at t=10_000 without calling tick — live computation returns 20 s.
        let mut buf = [0u8; 2];
        server
            .handle_command(CommandId::new(0x01), &[], unicast_at(10_000), &mut buf)
            .unwrap();
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 20);
    }

    #[test]
    fn identify_query_returns_response_with_remaining_time() {
        // Set 0x0123 = 291 s at t=0; query at t=0 → IdentifyQueryResponse { timeout =
        // 291 }.
        let req: &[u8] = &[0x01, 0x02, 0x01]; // IdentifyQuery
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = IdentifyServer::new();
        server
            .handle_command(CommandId::new(0x00), &[0x23, 0x01], unicast_at(0), &mut [])
            .unwrap();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast_at(0), &mut buf)
            .unwrap()
            .response_len;

        assert_eq!(n, 5);
        assert_eq!(buf[0], 0x19); // cluster-specific, server→client
        assert_eq!(buf[2], 0x00); // IdentifyQueryResponse command id
        assert_eq!(u16::from_le_bytes([buf[3], buf[4]]), 0x0123);
    }

    // --- attributes ---

    #[test]
    fn read_identify_time_attribute() {
        let mut server = IdentifyServer::new();
        server
            .handle_command(CommandId::new(0x00), &[42, 0], unicast_at(0), &mut [])
            .unwrap();
        let mut buf = [0u8; 4];
        let (type_id, n) = server
            .read_attribute(AttributeId::new(0x0000), &mut buf)
            .unwrap();
        assert_eq!(type_id, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 42);
    }

    #[test]
    fn write_identify_time_attribute() {
        let mut server = IdentifyServer::new();
        server
            .write_attribute(AttributeId::new(0x0000), TypeId::Uint16, &[0x10, 0x00])
            .unwrap();
        assert_eq!(server.remaining(), 0x0010);
    }

    #[test]
    fn cluster_revision_reads_rev8_value_and_is_read_only() {
        let mut server = IdentifyServer::new();
        let mut buf = [0u8; 4];
        let (type_id, n) = server
            .read_attribute(AttributeId::new(0xFFFD), &mut buf)
            .unwrap();
        assert_eq!(type_id, TypeId::Uint16);
        assert_eq!(n, 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 2);
        assert_eq!(
            server.write_attribute(AttributeId::new(0xFFFD), TypeId::Uint16, &[2, 0]),
            Err(AttrError::ReadOnly)
        );
    }

    #[test]
    fn attribute_list_includes_cluster_revision_after_identify_time() {
        let attrs = IdentifyServer::attribute_list();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].id, AttributeId::new(0x0000));
        assert_eq!(attrs[1].id, AttributeId::new(0xFFFD));
    }
}
