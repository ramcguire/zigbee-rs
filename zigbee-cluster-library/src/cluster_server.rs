use embedded_io::ReadExactError;
use heapless::Vec;

use crate::frame::Direction;
use crate::frame::IncomingGlobalCommand;
use crate::frame::IncomingZclCommand;
use crate::frame::IncomingZclFrame;
use crate::frame::OutgoingGlobalCommand;
use crate::frame::OutgoingZclFrame;
use crate::frame::Status;
use crate::frame::ZclFrameMeta;
use crate::header::command_identifier::CommandIdentifier;
use crate::payload::WriteAttrParseErr;
use crate::payload::WriteAttributesPayload;
use crate::reporting::ReportPayloadWriter;
use crate::types::descriptors::AttrInfo;
use crate::types::descriptors::ClusterKey;
use crate::types::error::AttrError;
use crate::types::error::ZclError;
use crate::types::ids::AttributeId;
use crate::types::ids::ClusterId;
use crate::types::ids::CommandId;
use crate::types::ids::ManufacturerCode;
use crate::types::ids::TypeId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryMode {
    Unicast,
    BroadcastOrMulticast,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApsPeer {
    pub short_addr: u16,
    pub endpoint: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchContext {
    pub delivery: DeliveryMode,
    pub now_ms: u32,
    pub source: Option<ApsPeer>,
}

impl DispatchContext {
    /// Creates a unicast dispatch context.
    ///
    /// Pass `source: None` only when there is no peer to associate (e.g. a
    /// locally-generated command). Incoming `ConfigureReporting` frames
    /// handled with `source: None` will not record a report destination, so
    /// configured reports will never be delivered. Always supply the actual
    /// `ApsPeer` when handling frames received from a specific device.
    pub const fn unicast(now_ms: u32, source: Option<ApsPeer>) -> Self {
        Self {
            delivery: DeliveryMode::Unicast,
            now_ms,
            source,
        }
    }

    pub const fn broadcast(now_ms: u32) -> Self {
        Self {
            delivery: DeliveryMode::BroadcastOrMulticast,
            now_ms,
            source: None,
        }
    }

    pub const fn allows_default_response(self) -> bool {
        matches!(self.delivery, DeliveryMode::Unicast)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConfigureReportingEffect {
    pub accepted_send_records: u8,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GroupEffect {
    #[default]
    None,
    /// Group was added successfully; carries the group ID.
    Added(u16),
    /// Group was removed successfully; carries the group ID.
    Removed(u16),
    /// All groups removed (`RemoveAllGroups` command succeeded).
    AllRemoved,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DispatchEffects {
    pub configure_reporting: Option<ConfigureReportingEffect>,
    pub group: GroupEffect,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DispatchOutcome {
    pub response_len: usize,
    pub effects: DispatchEffects,
}

impl DispatchOutcome {
    pub const fn response(len: usize) -> Self {
        Self {
            response_len: len,
            effects: DispatchEffects {
                configure_reporting: None,
                group: GroupEffect::None,
            },
        }
    }
}

/// One parsed record from a `ConfigureReporting` (0x06) payload.
#[derive(Clone, Copy, Debug)]
pub struct ConfigureReportingRecord<'a> {
    /// 0 = server sends reports to client; 1 = client sets receive timeout.
    pub direction: u8,
    pub attr_id: AttributeId,
    /// Data type of the attribute. Only meaningful when `direction == 0`.
    pub attr_type: u8,
    /// Min reporting interval (seconds). Only meaningful when `direction == 0`.
    pub min_interval: u16,
    /// Max reporting interval (seconds). Only meaningful when `direction == 0`.
    pub max_interval: u16,
    /// Reportable-change value bytes. Empty for discrete types or `direction ==
    /// 1`.
    pub reportable_change: &'a [u8],
    /// Timeout period (tenths of seconds). Only meaningful when `direction ==
    /// 1`.
    pub timeout_period: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportDestination {
    Unicast(ApsPeer),
    Bound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportToken(pub u16);

impl ReportToken {
    pub const fn new(value: u16) -> Self {
        Self(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClusterReportReady {
    pub destination: ReportDestination,
    pub token: ReportToken,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportDeliveryResult {
    Sent,
    Deferred,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportReady {
    pub destination: ReportDestination,
    pub token: ReportToken,
    pub endpoint: u8,
    pub profile_id: u16,
    pub cluster: ClusterKey,
    pub len: usize,
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportingDiagnostics {
    pub coalesced_updates: u16,
    pub dropped_reports: u16,
    pub buffer_too_small: bool,
}

impl ReportingDiagnostics {
    pub const fn is_empty(self) -> bool {
        self.coalesced_updates == 0 && self.dropped_reports == 0 && !self.buffer_too_small
    }
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClusterTick {
    pub changed: bool,
    pub next_tick_ms: Option<u32>,
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceTick {
    pub changed: bool,
    pub next_tick_ms: Option<u32>,
}

#[derive(Clone, Copy)]
pub enum CommandResult {
    /// Cluster impl returns a status; dispatcher builds `DefaultResponse`.
    DefaultResponse(Status),
    /// Cluster impl wrote `len` bytes of payload into buf; dispatcher prepends
    /// ZCL header.
    Payload { command_id: CommandId, len: usize },
    /// Unconditionally suppress any response.
    Suppress,
}

pub trait ClusterServer {
    const CLUSTER_ID: ClusterId;
    const MANUFACTURER_CODE: Option<ManufacturerCode> = None;

    fn read_attribute(&self, id: AttributeId, buf: &mut [u8])
    -> Result<(TypeId, usize), AttrError>;

    /// Validate an incoming write without mutating state. Used by
    /// `WriteAttributesUndivided`.
    fn check_write_attribute(
        &self,
        id: AttributeId,
        type_id: TypeId,
        data: &[u8],
    ) -> Result<(), AttrError> {
        let _ = (type_id, data);
        // Probe with empty buffer: if the attribute exists, it's read-only by default.
        // BufferTooSmall (or any non-UnsupportedAttribute result) means the attr
        // exists.
        match self.read_attribute(id, &mut []) {
            Err(AttrError::UnsupportedAttribute) => Err(AttrError::UnsupportedAttribute),
            _ => Err(AttrError::ReadOnly),
        }
    }

    fn write_attribute(
        &mut self,
        id: AttributeId,
        type_id: TypeId,
        data: &[u8],
    ) -> Result<(), AttrError> {
        let _ = (id, type_id, data);
        Err(AttrError::UnsupportedAttribute)
    }

    fn handle_command(
        &mut self,
        id: CommandId,
        payload: &[u8],
        ctx: DispatchContext,
        buf: &mut [u8],
    ) -> Result<CommandResult, ZclError> {
        let _ = (id, payload, ctx, buf);
        Ok(CommandResult::DefaultResponse(Status::UnsupCommand))
    }

    /// Advance cluster state to `now_ms` and return the tightest deadline at
    /// which state will next change. Never return a fixed polling interval —
    /// compute the exact next-change time. Default: no-op (stateless clusters).
    fn tick(&mut self, now_ms: u32) -> ClusterTick {
        let _ = now_ms;
        ClusterTick::default()
    }

    fn report_delivery_result(
        &mut self,
        token: ReportToken,
        result: ReportDeliveryResult,
        now_ms: u32,
    ) {
        let _ = (token, result, now_ms);
    }

    fn take_reporting_diagnostics(&mut self) -> ReportingDiagnostics {
        ReportingDiagnostics::default()
    }

    /// Attribute metadata for `DiscoverAttributes` /
    /// `DiscoverAttributesExtended`. Must be sorted ascending by id.
    ///
    /// The `where Self: Sized` bound prevents calling this method through a
    /// `&dyn ClusterServer` reference. If runtime attribute discovery is
    /// needed, use a separate registry or the `DeviceServerVisitor` pattern
    /// to access the concrete type.
    fn attribute_list() -> &'static [AttrInfo]
    where
        Self: Sized,
    {
        &[]
    }

    /// Cluster-specific commands this server accepts (client-to-server).
    /// Used by `DiscoverCommandsReceived`. Must be sorted ascending by raw
    /// command id.
    ///
    /// Same `where Self: Sized` restriction as
    /// [`attribute_list`](Self::attribute_list).
    fn commands_received() -> &'static [CommandId]
    where
        Self: Sized,
    {
        &[]
    }

    /// Cluster-specific commands this server can generate (server-to-client).
    /// Used by `DiscoverCommandsGenerated`. Must be sorted ascending by raw
    /// command id.
    ///
    /// Same `where Self: Sized` restriction as
    /// [`attribute_list`](Self::attribute_list).
    fn commands_generated() -> &'static [CommandId]
    where
        Self: Sized,
    {
        &[]
    }

    /// Write one `ReadReportingConfigurationResponse` record for `attr_id` and
    /// `direction` into `buf`. Returns the number of bytes written.
    ///
    /// Default: always writes a `NOT_FOUND (0x8b)` record (4 bytes). Clusters
    /// with a `LatestReportingTable` override this via `impl_reporting!`.
    fn read_reporting_config(&self, attr_id: AttributeId, direction: u8, buf: &mut [u8]) -> usize {
        if buf.len() < 4 {
            return 0;
        }
        buf[0] = 0x8b; // NOT_FOUND
        buf[1] = direction & 0x01;
        buf[2] = (attr_id.0 & 0xff) as u8;
        buf[3] = (attr_id.0 >> 8) as u8;
        4
    }

    /// Handle one record from an incoming `ConfigureReporting` (0x06) frame.
    /// Return `Status::Success` to accept the record; any other status is
    /// returned to the requester as a per-record failure.
    /// Drain any pending `GroupEffect` produced by the last `handle_command`
    /// call. Called by `zcl_cluster_dispatch` after cluster-specific commands.
    /// Default: always `GroupEffect::None`.
    fn take_dispatch_effects(&mut self) -> DispatchEffects {
        DispatchEffects::default()
    }

    /// Serialize all mutable attribute state into `buf`.
    /// Returns number of bytes written. Default: 0 (stateless cluster).
    fn snapshot(&self, buf: &mut [u8]) -> usize {
        let _ = buf;
        0
    }

    /// Restore mutable attribute state from a snapshot produced by `snapshot`.
    /// Silently ignores malformed or truncated data. Default: no-op.
    fn restore_snapshot(&mut self, buf: &[u8]) {
        let _ = buf;
    }

    fn configure_reporting(
        &mut self,
        record: ConfigureReportingRecord<'_>,
        ctx: DispatchContext,
    ) -> Status {
        let _ = (record, ctx);
        Status::UnreportableAttribute
    }

    /// Write pending report payload bytes into `out` and return report
    /// metadata.
    ///
    /// Called by the default `Device::next_report` implementation. Return
    /// `Ok(Some(_))` when a report was written; `Ok(None)` when nothing is
    /// pending. Default: always `Ok(None)`.
    fn collect_reports(
        &mut self,
        now_ms: u32,
        out: &mut ReportPayloadWriter<'_>,
    ) -> Result<Option<ClusterReportReady>, ZclError> {
        let _ = (now_ms, out);
        Ok(None)
    }

    fn dispatch(
        &mut self,
        frame: &IncomingZclFrame<'_>,
        ctx: DispatchContext,
        buf: &mut [u8],
    ) -> Result<DispatchOutcome, ZclError>
    where
        Self: Sized,
    {
        zcl_cluster_dispatch(self, frame, ctx, buf)
    }
}

// ---------------------------------------------------------------------------
// Device trait
// ---------------------------------------------------------------------------

pub enum DispatchError {
    UnsupportedEndpoint,
    UnsupportedCluster,
    Codec(ZclError),
}

impl From<ZclError> for DispatchError {
    fn from(e: ZclError) -> Self {
        Self::Codec(e)
    }
}

/// Per-endpoint descriptor for ZDO `Active_EP_rsp` and `Simple_Desc_rsp`.
#[derive(Clone, Copy, Debug)]
pub struct EndpointDescriptor {
    pub endpoint: u8,
    pub profile_id: u16,
    pub device_id: u16,
    pub device_version: u8,
    pub input_clusters: &'static [ClusterId],
    pub output_clusters: &'static [ClusterId],
}

/// Compatibility alias — prefer `EndpointDescriptor`.
pub type SimpleDescriptor = EndpointDescriptor;

/// Identifies a cluster server registration within a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerMeta {
    pub endpoint: u8,
    pub profile_id: u16,
    pub cluster: ClusterKey,
}

/// Visitor passed to `Device::visit_servers`. Statically dispatches into each
/// concrete cluster type without allocation.
pub trait DeviceServerVisitor {
    fn visit<C: ClusterServer>(&mut self, meta: ServerMeta, server: &mut C);
}

/// Carries everything needed to dispatch one incoming ZCL frame to a cluster.
#[derive(Clone, Copy)]
pub struct ClusterRequest<'a> {
    pub endpoint: u8,
    pub cluster: ClusterKey,
    pub ctx: DispatchContext,
    pub frame: &'a IncomingZclFrame<'a>,
}

pub trait Device {
    fn endpoints(&self) -> &'static [EndpointDescriptor];

    fn active_endpoints(&self) -> &'static [EndpointDescriptor] {
        self.endpoints()
    }

    fn simple_descriptor(&self, endpoint: u8) -> Option<&'static EndpointDescriptor> {
        self.endpoints()
            .iter()
            .find(|descriptor| descriptor.endpoint == endpoint)
    }

    fn visit_servers<V: DeviceServerVisitor>(&mut self, visitor: &mut V)
    where
        Self: Sized;

    fn dispatch_cluster(
        &mut self,
        request: ClusterRequest<'_>,
        buf: &mut [u8],
    ) -> Result<DispatchOutcome, DispatchError>
    where
        Self: Sized,
    {
        dispatch_via_servers(self, request, buf)
    }

    fn next_report(&mut self, now_ms: u32, buf: &mut [u8]) -> Result<Option<ReportReady>, ZclError>
    where
        Self: Sized,
    {
        collect_next_report_via_servers(self, now_ms, buf)
    }

    fn tick(&mut self, now_ms: u32) -> DeviceTick
    where
        Self: Sized,
    {
        tick_via_servers(self, now_ms)
    }

    fn report_delivery_result(
        &mut self,
        ready: ReportReady,
        result: ReportDeliveryResult,
        now_ms: u32,
    ) where
        Self: Sized,
    {
        report_delivery_result_via_servers(self, ready, result, now_ms);
    }

    fn take_reporting_diagnostics(&mut self) -> ReportingDiagnostics
    where
        Self: Sized,
    {
        take_reporting_diagnostics_via_servers(self)
    }

    /// Serialize mutable cluster attribute state to `w`.
    ///
    /// Wire format: one framed record per server that returns `snapshot() > 0`:
    /// `[cluster_id: u16 LE][endpoint: u8][len: u16 LE][data: len bytes]`
    fn save_state<W: embedded_io::Write>(&mut self, w: &mut W) -> Result<(), W::Error>
    where
        Self: Sized,
    {
        save_state_via_servers(self, w)
    }

    /// Restore mutable cluster attribute state from a snapshot written by
    /// `save_state`. Unknown or missing records are silently skipped.
    fn restore_state<R: embedded_io::Read>(&mut self, r: &mut R) -> Result<(), R::Error>
    where
        Self: Sized,
    {
        restore_state_via_servers(self, r)
    }
}

// ---------------------------------------------------------------------------
// Device visitor helpers
// ---------------------------------------------------------------------------

struct DispatchVisitor<'req, 'buf> {
    request: ClusterRequest<'req>,
    buf: &'buf mut [u8],
    result: Option<Result<DispatchOutcome, ZclError>>,
}

impl DeviceServerVisitor for DispatchVisitor<'_, '_> {
    fn visit<C: ClusterServer>(&mut self, meta: ServerMeta, server: &mut C) {
        if self.result.is_some() {
            return;
        }
        if meta.endpoint != self.request.endpoint || meta.cluster != self.request.cluster {
            return;
        }
        self.result = Some(zcl_cluster_dispatch(
            server,
            self.request.frame,
            self.request.ctx,
            self.buf,
        ));
    }
}

pub fn dispatch_via_servers<D: Device>(
    device: &mut D,
    request: ClusterRequest<'_>,
    buf: &mut [u8],
) -> Result<DispatchOutcome, DispatchError> {
    if !device
        .endpoints()
        .iter()
        .any(|e| e.endpoint == request.endpoint)
    {
        return Err(DispatchError::UnsupportedEndpoint);
    }
    let mut visitor = DispatchVisitor {
        request,
        buf,
        result: None,
    };
    device.visit_servers(&mut visitor);
    match visitor.result {
        Some(Ok(outcome)) => Ok(outcome),
        Some(Err(e)) => Err(DispatchError::Codec(e)),
        None => Err(DispatchError::UnsupportedCluster),
    }
}

struct TickVisitor {
    now_ms: u32,
    tick: DeviceTick,
}

impl DeviceServerVisitor for TickVisitor {
    fn visit<C: ClusterServer>(&mut self, _meta: ServerMeta, server: &mut C) {
        let ct = server.tick(self.now_ms);
        self.tick.changed |= ct.changed;
        match (self.tick.next_tick_ms, ct.next_tick_ms) {
            (None, Some(d)) => self.tick.next_tick_ms = Some(d),
            (Some(existing), Some(d))
                if d.wrapping_sub(self.now_ms) < existing.wrapping_sub(self.now_ms) =>
            {
                self.tick.next_tick_ms = Some(d);
            }
            _ => {}
        }
    }
}

pub fn tick_via_servers<D: Device>(device: &mut D, now_ms: u32) -> DeviceTick {
    let mut visitor = TickVisitor {
        now_ms,
        tick: DeviceTick::default(),
    };
    device.visit_servers(&mut visitor);
    visitor.tick
}

struct CollectReportVisitor<'buf> {
    now_ms: u32,
    buf: &'buf mut [u8],
    result: Option<Result<Option<ReportReady>, ZclError>>,
    // Filled in from ServerMeta when a cluster returns Some.
    current_meta: Option<ServerMeta>,
}

impl DeviceServerVisitor for CollectReportVisitor<'_> {
    fn visit<C: ClusterServer>(&mut self, meta: ServerMeta, server: &mut C) {
        if self.result.is_some() {
            return; // already found a report
        }
        let mut writer = ReportPayloadWriter::new(self.buf);
        match server.collect_reports(self.now_ms, &mut writer) {
            Err(e) => {
                self.result = Some(Err(e));
            }
            Ok(None) => {}
            Ok(Some(cluster_ready)) => {
                let len = writer.len();
                self.result = Some(Ok(Some(ReportReady {
                    destination: cluster_ready.destination,
                    token: cluster_ready.token,
                    endpoint: meta.endpoint,
                    profile_id: meta.profile_id,
                    cluster: meta.cluster,
                    len,
                })));
                self.current_meta = Some(meta);
            }
        }
    }
}

pub fn collect_next_report_via_servers<D: Device>(
    device: &mut D,
    now_ms: u32,
    buf: &mut [u8],
) -> Result<Option<ReportReady>, ZclError> {
    let mut visitor = CollectReportVisitor {
        now_ms,
        buf,
        result: None,
        current_meta: None,
    };
    device.visit_servers(&mut visitor);
    visitor.result.unwrap_or(Ok(None))
}

struct ReportDeliveryVisitor {
    endpoint: u8,
    cluster: ClusterKey,
    token: ReportToken,
    result: ReportDeliveryResult,
    now_ms: u32,
}

impl DeviceServerVisitor for ReportDeliveryVisitor {
    fn visit<C: ClusterServer>(&mut self, meta: ServerMeta, server: &mut C) {
        if meta.endpoint == self.endpoint && meta.cluster == self.cluster {
            server.report_delivery_result(self.token, self.result, self.now_ms);
        }
    }
}

pub fn report_delivery_result_via_servers<D: Device>(
    device: &mut D,
    ready: ReportReady,
    result: ReportDeliveryResult,
    now_ms: u32,
) {
    let mut visitor = ReportDeliveryVisitor {
        endpoint: ready.endpoint,
        cluster: ready.cluster,
        token: ready.token,
        result,
        now_ms,
    };
    device.visit_servers(&mut visitor);
}

struct DiagnosticsVisitor {
    diagnostics: ReportingDiagnostics,
}

impl DeviceServerVisitor for DiagnosticsVisitor {
    fn visit<C: ClusterServer>(&mut self, _meta: ServerMeta, server: &mut C) {
        let d = server.take_reporting_diagnostics();
        self.diagnostics.coalesced_updates = self
            .diagnostics
            .coalesced_updates
            .saturating_add(d.coalesced_updates);
        self.diagnostics.dropped_reports = self
            .diagnostics
            .dropped_reports
            .saturating_add(d.dropped_reports);
        self.diagnostics.buffer_too_small |= d.buffer_too_small;
    }
}

pub fn take_reporting_diagnostics_via_servers<D: Device>(device: &mut D) -> ReportingDiagnostics {
    let mut visitor = DiagnosticsVisitor {
        diagnostics: ReportingDiagnostics::default(),
    };
    device.visit_servers(&mut visitor);
    visitor.diagnostics
}

struct SaveStateVisitor<'w, W: embedded_io::Write> {
    writer: &'w mut W,
    error: Option<W::Error>,
}

impl<W: embedded_io::Write> DeviceServerVisitor for SaveStateVisitor<'_, W> {
    fn visit<C: ClusterServer>(&mut self, meta: ServerMeta, server: &mut C) {
        if self.error.is_some() {
            return;
        }
        // 5-byte header + up to 256 bytes of snapshot data
        let mut buf = [0u8; 261];
        let data_len = server.snapshot(&mut buf[5..]);
        if data_len == 0 {
            return;
        }
        let data_len = data_len.min(buf.len() - 5);
        let cluster_id = meta.cluster.id.0;
        buf[0] = (cluster_id & 0xFF) as u8;
        buf[1] = (cluster_id >> 8) as u8;
        buf[2] = meta.endpoint;
        let len_bytes = u16::try_from(data_len).unwrap_or(0).to_le_bytes();
        buf[3] = len_bytes[0];
        buf[4] = len_bytes[1];
        if let Err(e) = self.writer.write_all(&buf[..5 + data_len]) {
            self.error = Some(e);
        }
    }
}

pub fn save_state_via_servers<D: Device, W: embedded_io::Write>(
    device: &mut D,
    w: &mut W,
) -> Result<(), W::Error> {
    let mut visitor = SaveStateVisitor {
        writer: w,
        error: None,
    };
    device.visit_servers(&mut visitor);
    visitor.error.map_or(Ok(()), Err)
}

struct RestoreStateVisitor<'a> {
    cluster_id: u16,
    endpoint: u8,
    data: &'a [u8],
}

impl DeviceServerVisitor for RestoreStateVisitor<'_> {
    fn visit<C: ClusterServer>(&mut self, meta: ServerMeta, server: &mut C) {
        if meta.cluster.id.0 == self.cluster_id && meta.endpoint == self.endpoint {
            server.restore_snapshot(self.data);
        }
    }
}

pub fn restore_state_via_servers<D: Device, R: embedded_io::Read>(
    device: &mut D,
    r: &mut R,
) -> Result<(), R::Error> {
    let mut header = [0u8; 5];
    loop {
        match r.read_exact(&mut header) {
            Ok(()) => {}
            Err(ReadExactError::UnexpectedEof) => break,
            Err(ReadExactError::Other(e)) => return Err(e),
        }
        let cluster_id = u16::from_le_bytes([header[0], header[1]]);
        let endpoint = header[2];
        let data_len = u16::from_le_bytes([header[3], header[4]]) as usize;

        let mut buf = [0u8; 256];
        if data_len > buf.len() {
            // Record too large — cannot skip without seekable reader; stop parsing.
            break;
        }
        match r.read_exact(&mut buf[..data_len]) {
            Ok(()) => {}
            Err(ReadExactError::UnexpectedEof) => break,
            Err(ReadExactError::Other(e)) => return Err(e),
        }

        let mut visitor = RestoreStateVisitor {
            cluster_id,
            endpoint,
            data: &buf[..data_len],
        };
        device.visit_servers(&mut visitor);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public helpers
// ---------------------------------------------------------------------------

/// Build a non-manufacturer-specific `DefaultResponse` frame into `buf`.
/// Returns bytes written.
pub fn build_default_response(
    request_command: CommandIdentifier,
    status: Status,
    seq: u8,
    buf: &mut [u8],
) -> Result<usize, ZclError> {
    build_default_response_with_mfr(request_command, status, seq, None, buf)
}

/// Build a `DefaultResponse` frame for `frame`, preserving
/// manufacturer-specific framing.
pub fn build_default_response_for_frame(
    frame: &IncomingZclFrame<'_>,
    status: Status,
    buf: &mut [u8],
) -> Result<usize, ZclError> {
    let Some(response) = OutgoingZclFrame::default_response(frame, status) else {
        return Ok(0);
    };
    response.encode(buf)
}

/// Build a `DefaultResponse` frame into `buf`, optionally preserving a
/// manufacturer code.
pub fn build_default_response_with_mfr(
    request_command: CommandIdentifier,
    status: Status,
    seq: u8,
    manufacturer_code: Option<ManufacturerCode>,
    buf: &mut [u8],
) -> Result<usize, ZclError> {
    let mut meta = ZclFrameMeta::new(seq, Direction::ServerToClient).disable_default_response();
    if let Some(code) = manufacturer_code {
        meta = meta.with_manufacturer_code(code);
    }
    OutgoingZclFrame::global(
        meta,
        OutgoingGlobalCommand::DefaultResponse(crate::frame::DefaultResponse {
            command_identifier: request_command.raw(),
            status,
        }),
    )
    .encode(buf)
}

/// True when ZCL rules allow sending a `DefaultResponse` for this frame +
/// context
/// + status.
pub fn should_send_default_response(
    frame: &IncomingZclFrame<'_>,
    ctx: DispatchContext,
    status: Status,
) -> bool {
    if !ctx.allows_default_response() {
        return false;
    }
    if matches!(
        frame.command(),
        IncomingZclCommand::Global(
            IncomingGlobalCommand::DefaultResponse(_)
                | IncomingGlobalCommand::WriteAttributesNoResponse(_)
        )
    ) {
        return false;
    }
    if status == Status::Success && frame.disable_default_response() {
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn response_header_len(manufacturer_code: Option<ManufacturerCode>) -> usize {
    3 + if manufacturer_code.is_some() { 2 } else { 0 }
}

fn zcl_response_header_len(frame: &IncomingZclFrame<'_>) -> usize {
    response_header_len(frame.manufacturer_code())
}

fn write_response_header_parts(
    buf: &mut [u8],
    frame: &IncomingZclFrame<'_>,
    cmd_id: u8,
    frame_control_base: u8,
) -> Result<usize, ZclError> {
    let manufacturer_code = frame.manufacturer_code();
    let mfr_bit = if manufacturer_code.is_some() {
        0x04u8
    } else {
        0x00u8
    };
    let needed = response_header_len(manufacturer_code);
    if buf.len() < needed {
        return Err(ZclError::BufferTooSmall);
    }
    let mut n = 0;
    buf[n] = frame_control_base | mfr_bit;
    n += 1;
    if let Some(mfr) = manufacturer_code {
        buf[n..n + 2].copy_from_slice(&mfr.0.to_le_bytes());
        n += 2;
    }
    buf[n] = frame.sequence_number();
    n += 1;
    buf[n] = cmd_id;
    n += 1;
    Ok(n)
}

fn write_global_response_header(
    buf: &mut [u8],
    frame: &IncomingZclFrame<'_>,
    cmd_id: u8,
) -> Result<usize, ZclError> {
    write_response_header_parts(buf, frame, cmd_id, 0x18)
}

fn write_cluster_response_header(
    buf: &mut [u8],
    frame: &IncomingZclFrame<'_>,
    cmd_id: u8,
) -> Result<usize, ZclError> {
    write_response_header_parts(buf, frame, cmd_id, 0x19)
}

fn put_byte(buf: &mut [u8], pos: usize, val: u8) -> Result<usize, ZclError> {
    *buf.get_mut(pos).ok_or(ZclError::BufferTooSmall)? = val;
    Ok(pos + 1)
}

fn put_u16_le(buf: &mut [u8], pos: usize, val: u16) -> Result<usize, ZclError> {
    buf.get_mut(pos..pos + 2)
        .ok_or(ZclError::BufferTooSmall)?
        .copy_from_slice(&val.to_le_bytes());
    Ok(pos + 2)
}

fn dispatch_write_attributes_no_response<CS: ClusterServer>(
    server: &mut CS,
    payload: &WriteAttributesPayload,
) -> usize {
    for record in payload.records().flatten() {
        let _ = server.write_attribute(record.attr_id, record.type_id, record.value);
    }
    0 // no response, not even DefaultResponse (ZCL §2.5.7)
}

pub fn zcl_cluster_dispatch<CS: ClusterServer>(
    server: &mut CS,
    frame: &IncomingZclFrame<'_>,
    ctx: DispatchContext,
    buf: &mut [u8],
) -> Result<DispatchOutcome, ZclError> {
    let n = match frame.command() {
        IncomingZclCommand::Global(IncomingGlobalCommand::ReadAttributes(attrs)) => {
            let hdr_len = write_global_response_header(buf, frame, 0x01)?;
            let mut pos = hdr_len;
            for record in attrs {
                let attr_id = AttributeId::new(record.attribute_id);
                pos = put_u16_le(buf, pos, record.attribute_id)?;
                // Reserve pos for status and pos+1 for type_id; pass [pos+2..] to
                // read_attribute.
                let value_buf = buf.get_mut(pos + 2..).ok_or(ZclError::BufferTooSmall)?;
                match server.read_attribute(attr_id, value_buf) {
                    Ok((type_id, n)) => {
                        buf[pos] = 0x00; // Success
                        buf[pos + 1] = type_id.as_u8();
                        pos += 2 + n;
                    }
                    Err(e) => match e.to_status() {
                        Some(status) => {
                            pos = put_byte(buf, pos, status as u8)?;
                        }
                        None => return Err(e.into()),
                    },
                }
            }
            Ok(pos)
        }

        IncomingZclCommand::Global(IncomingGlobalCommand::DefaultResponse(_)) => {
            Ok(0) // ZCL §2.5.12: never respond to an incoming DefaultResponse
        }

        IncomingZclCommand::Global(IncomingGlobalCommand::WriteAttributes(payload)) => {
            dispatch_write_attributes(server, payload, frame, ctx, buf)
        }

        IncomingZclCommand::Global(IncomingGlobalCommand::WriteAttributesUndivided(payload)) => {
            dispatch_write_attributes_undivided(server, payload, frame, buf)
        }

        IncomingZclCommand::Global(IncomingGlobalCommand::WriteAttributesNoResponse(payload)) => {
            Ok(dispatch_write_attributes_no_response(server, payload))
        }

        IncomingZclCommand::Global(IncomingGlobalCommand::DiscoverAttributes {
            start_attr,
            max_count,
        }) => dispatch_discover_attributes::<CS>(start_attr.0, *max_count, frame, buf),

        IncomingZclCommand::Global(IncomingGlobalCommand::DiscoverCommandsReceived {
            start_cmd,
            max_count,
        }) => dispatch_discover_commands(
            0x12,
            *start_cmd,
            *max_count,
            CS::commands_received(),
            frame,
            buf,
        ),

        IncomingZclCommand::Global(IncomingGlobalCommand::DiscoverCommandsGenerated {
            start_cmd,
            max_count,
        }) => dispatch_discover_commands(
            0x14,
            *start_cmd,
            *max_count,
            CS::commands_generated(),
            frame,
            buf,
        ),

        IncomingZclCommand::Global(IncomingGlobalCommand::DiscoverAttributesExtended {
            start_attr,
            max_count,
        }) => dispatch_discover_attributes_extended::<CS>(start_attr.0, *max_count, frame, buf),

        IncomingZclCommand::ClusterSpecific { command_id, data } => {
            if frame.direction() == Direction::ServerToClient {
                // direction=1 means server-to-client: a server ignores these
                return Ok(DispatchOutcome::response(0));
            }
            let hdr_len = zcl_response_header_len(frame);
            if buf.len() < hdr_len {
                return Err(ZclError::BufferTooSmall);
            }
            let result = server.handle_command(*command_id, data, ctx, &mut buf[hdr_len..])?;
            let effects = server.take_dispatch_effects();
            let response_len = finalize_command_response(result, frame, ctx, hdr_len, buf)?;
            return Ok(DispatchOutcome {
                response_len,
                effects,
            });
        }

        IncomingZclCommand::Global(IncomingGlobalCommand::KnownUnhandled {
            command_id: CommandIdentifier::ConfigureReporting,
            data,
        }) => return dispatch_configure_reporting(server, frame, ctx, data, buf),

        IncomingZclCommand::Global(IncomingGlobalCommand::KnownUnhandled {
            command_id: CommandIdentifier::ReadReportingConfiguration,
            data,
        }) => return dispatch_read_reporting_config(server, frame, data, buf),

        IncomingZclCommand::Global(IncomingGlobalCommand::KnownUnhandled {
            command_id: CommandIdentifier::ConfigureReportingResponse,
            ..
        }) => Ok(0), // ZCL §2.4.8: never respond to ConfigureReportingResponse

        IncomingZclCommand::Global(
            IncomingGlobalCommand::KnownUnhandled { .. } | IncomingGlobalCommand::Unknown { .. },
        ) => dispatch_unknown_global(frame, ctx, buf),
    };
    n.map(DispatchOutcome::response)
}

// ---------------------------------------------------------------------------
// Sub-dispatchers
// ---------------------------------------------------------------------------

fn dispatch_write_attributes<CS: ClusterServer>(
    server: &mut CS,
    payload: &WriteAttributesPayload<'_>,
    frame: &IncomingZclFrame<'_>,
    ctx: DispatchContext,
    buf: &mut [u8],
) -> Result<usize, ZclError> {
    let hdr_len = write_global_response_header(buf, frame, 0x04)?;
    let mut pos = hdr_len;

    for record_result in payload.records() {
        match record_result {
            Err(WriteAttrParseErr { attr_id: Some(id) }) => {
                // Unknown type_id: emit per-record INVALID_DATA_TYPE and stop —
                // stream position is irrecoverable after a length-unknown type.
                pos = put_byte(buf, pos, Status::InvalidDataType as u8)?;
                pos = put_u16_le(buf, pos, id.0)?;
                break;
            }
            Err(WriteAttrParseErr { attr_id: None }) => {
                return Err(ZclError::InsufficientBytes);
            }
            Ok(record) => {
                match server.write_attribute(record.attr_id, record.type_id, record.value) {
                    Ok(()) => {}
                    Err(e) => match e.to_status() {
                        Some(status) => {
                            pos = put_byte(buf, pos, status as u8)?;
                            pos = put_u16_le(buf, pos, record.attr_id.0)?;
                        }
                        None => return Err(e.into()),
                    },
                }
            }
        }
    }

    // pos == hdr_len means all records succeeded → single success (no attr_id)
    if pos == hdr_len {
        pos = put_byte(buf, pos, 0x00)?;
    }

    let _ = ctx; // WriteAttributesResponse never triggers an additional DefaultResponse
    Ok(pos)
}

fn dispatch_write_attributes_undivided<CS: ClusterServer>(
    server: &mut CS,
    payload: &WriteAttributesPayload<'_>,
    frame: &IncomingZclFrame<'_>,
    buf: &mut [u8],
) -> Result<usize, ZclError> {
    let hdr_len = write_global_response_header(buf, frame, 0x04)?;

    // First pass: check all records without mutating state.
    let mut failures: Vec<(u16, u8), 16> = Vec::new(); // (attr_id, status_byte)
    for record_result in payload.records() {
        match record_result {
            Err(WriteAttrParseErr { attr_id: Some(id) }) => {
                failures
                    .push((id.0, Status::InvalidDataType as u8))
                    .map_err(|_| ZclError::BufferTooSmall)?;
                break; // stream position irrecoverable; failures non-empty → second pass skipped
            }
            Err(WriteAttrParseErr { attr_id: None }) => {
                return Err(ZclError::InsufficientBytes);
            }
            Ok(record) => {
                if let Err(e) =
                    server.check_write_attribute(record.attr_id, record.type_id, record.value)
                {
                    match e.to_status() {
                        Some(status) => {
                            failures
                                .push((record.attr_id.0, status as u8))
                                .map_err(|_| ZclError::BufferTooSmall)?;
                        }
                        None => return Err(e.into()),
                    }
                }
            }
        }
    }

    if !failures.is_empty() {
        // One or more checks failed: write nothing, return failure records.
        let mut pos = hdr_len;
        for (attr_id, status_byte) in &failures {
            pos = put_byte(buf, pos, *status_byte)?;
            pos = put_u16_le(buf, pos, *attr_id)?;
        }
        return Ok(pos);
    }

    // Second pass: all checks passed → commit all writes.
    // Parse errors cannot occur here: the first pass would have populated
    // `failures` and returned before reaching this point.
    for record_result in payload.records() {
        let record = record_result.map_err(|_| ZclError::InsufficientBytes)?;
        // Errors here are unexpected (we just validated), but propagate Codec failures.
        if let Err(AttrError::Codec(ze)) =
            server.write_attribute(record.attr_id, record.type_id, record.value)
        {
            return Err(ze);
        }
    }

    let pos = put_byte(buf, hdr_len, 0x00)?; // single success record
    Ok(pos)
}

fn dispatch_discover_attributes<CS: ClusterServer>(
    start_attr: u16,
    max_count: u8,
    frame: &IncomingZclFrame<'_>,
    buf: &mut [u8],
) -> Result<usize, ZclError> {
    let list = CS::attribute_list();
    let start_idx = list.partition_point(|a| a.id.0 < start_attr);
    let remaining = &list[start_idx..];
    let count = remaining.len().min(usize::from(max_count));
    // discovery_complete = 1 when all remaining attributes fit within max_count
    let discovery_complete = u8::from(count >= remaining.len());

    let hdr_len = write_global_response_header(buf, frame, 0x0d)?;
    let mut pos = hdr_len;
    pos = put_byte(buf, pos, discovery_complete)?;
    for attr in &remaining[..count] {
        pos = put_u16_le(buf, pos, attr.id.0)?;
        pos = put_byte(buf, pos, attr.type_id.as_u8())?;
    }
    Ok(pos)
}

/// Shared handler for `DiscoverCommandsReceived` (response 0x12) and
/// `DiscoverCommandsGenerated` (response 0x14).
fn dispatch_discover_commands(
    response_cmd_id: u8,
    start_cmd: u8,
    max_count: u8,
    commands: &'static [CommandId],
    frame: &IncomingZclFrame<'_>,
    buf: &mut [u8],
) -> Result<usize, ZclError> {
    let start_idx = commands.partition_point(|c| c.0 < start_cmd);
    let remaining = &commands[start_idx..];
    let count = remaining.len().min(usize::from(max_count));
    let discovery_complete = u8::from(count >= remaining.len());

    let hdr_len = write_global_response_header(buf, frame, response_cmd_id)?;
    let mut pos = hdr_len;
    pos = put_byte(buf, pos, discovery_complete)?;
    for cmd in &remaining[..count] {
        pos = put_byte(buf, pos, cmd.0)?;
    }
    Ok(pos)
}

fn dispatch_discover_attributes_extended<CS: ClusterServer>(
    start_attr: u16,
    max_count: u8,
    frame: &IncomingZclFrame<'_>,
    buf: &mut [u8],
) -> Result<usize, ZclError> {
    let list = CS::attribute_list();
    let start_idx = list.partition_point(|a| a.id.0 < start_attr);
    let remaining = &list[start_idx..];
    let count = remaining.len().min(usize::from(max_count));
    let discovery_complete = u8::from(count >= remaining.len());

    let hdr_len = write_global_response_header(buf, frame, 0x16)?;
    let mut pos = hdr_len;
    pos = put_byte(buf, pos, discovery_complete)?;
    for attr in &remaining[..count] {
        pos = put_u16_le(buf, pos, attr.id.0)?;
        pos = put_byte(buf, pos, attr.type_id.as_u8())?;
        pos = put_byte(buf, pos, attr.access.as_u8())?;
    }
    Ok(pos)
}

/// Returns the byte-size of the `reportable_change` field for analog types,
/// or `None` for discrete types (which have no such field).
fn type_size_for_reporting(type_id: u8) -> Option<usize> {
    match type_id {
        0x20..=0x27 => Some((type_id - 0x20) as usize + 1), // uint8..uint64
        0x28..=0x2f => Some((type_id - 0x28) as usize + 1), // int8..int64
        0x38 => Some(2),                                    // semi-precision float
        0x39 => Some(4),                                    // single-precision float
        0x3a => Some(8),                                    // double-precision float
        _ => None,
    }
}

/// Dispatch a `ConfigureReporting` (0x06) frame to the cluster server.
///
/// Calls `server.configure_reporting()` for each record. Builds a
/// `ConfigureReportingResponse` (0x07): a single success byte when all
/// records pass, or per-record failure tuples otherwise (ZCL §2.4.7).
/// Broadcast/multicast → `Ok(DispatchOutcome::response(0))`.
/// Parse all `ConfigureReporting` records from `data` into `out`.
///
/// Returns `Err(ZclError::InsufficientBytes)` on the first truncated record
/// so the caller can reject the entire frame before mutating any state.
fn parse_configure_reporting_records<'a>(
    data: &'a [u8],
    out: &mut Vec<ConfigureReportingRecord<'a>, 16>,
) -> Result<(), ZclError> {
    let mut p = 0usize;
    while p < data.len() {
        if p + 3 > data.len() {
            return Err(ZclError::InsufficientBytes);
        }
        let direction = data[p] & 0x01;
        let attr_id = u16::from_le_bytes([data[p + 1], data[p + 2]]);
        p += 3;

        let record = if direction == 0 {
            if p + 5 > data.len() {
                return Err(ZclError::InsufficientBytes);
            }
            let attr_type = data[p];
            let min_interval = u16::from_le_bytes([data[p + 1], data[p + 2]]);
            let max_interval = u16::from_le_bytes([data[p + 3], data[p + 4]]);
            p += 5;
            let change_size = type_size_for_reporting(attr_type).unwrap_or(0);
            if p + change_size > data.len() {
                return Err(ZclError::InsufficientBytes);
            }
            let reportable_change = &data[p..p + change_size];
            p += change_size;
            ConfigureReportingRecord {
                direction: 0,
                attr_id: AttributeId::new(attr_id),
                attr_type,
                min_interval,
                max_interval,
                reportable_change,
                timeout_period: 0,
            }
        } else {
            if p + 2 > data.len() {
                return Err(ZclError::InsufficientBytes);
            }
            let timeout_period = u16::from_le_bytes([data[p], data[p + 1]]);
            p += 2;
            ConfigureReportingRecord {
                direction: 1,
                attr_id: AttributeId::new(attr_id),
                attr_type: 0,
                min_interval: 0,
                max_interval: 0,
                reportable_change: &[],
                timeout_period,
            }
        };

        out.push(record).map_err(|_| ZclError::BufferTooSmall)?;
    }
    Ok(())
}

fn dispatch_configure_reporting<CS: ClusterServer>(
    server: &mut CS,
    frame: &IncomingZclFrame<'_>,
    ctx: DispatchContext,
    data: &[u8],
    buf: &mut [u8],
) -> Result<DispatchOutcome, ZclError> {
    if !ctx.allows_default_response() {
        return Ok(DispatchOutcome::response(0));
    }

    // Validate the entire payload before mutating any state.
    let mut records: Vec<ConfigureReportingRecord<'_>, 16> = Vec::new();
    parse_configure_reporting_records(data, &mut records)?;

    let hdr_len = write_global_response_header(buf, frame, 0x07)?;
    let mut pos = hdr_len;
    let mut accepted_send: u8 = 0;
    let mut failures: Vec<(u8, u16, u8), 16> = Vec::new(); // (direction, attr_id, status_byte)

    for record in &records {
        let direction = record.direction;
        let attr_id = record.attr_id.0;
        let status = server.configure_reporting(*record, ctx);
        if status == Status::Success {
            if direction == 0 {
                accepted_send = accepted_send.saturating_add(1);
            }
        } else {
            // Ignore overflow: extra failures beyond 16 are silently dropped.
            let _ = failures.push((direction, attr_id, status as u8));
        }
    }

    if failures.is_empty() {
        // All records accepted (or payload was empty) → single success byte.
        pos = put_byte(buf, pos, 0x00)?;
    } else {
        for (dir, aid, status_byte) in &failures {
            pos = put_byte(buf, pos, *status_byte)?;
            pos = put_byte(buf, pos, *dir)?;
            pos = put_u16_le(buf, pos, *aid)?;
        }
    }

    Ok(DispatchOutcome {
        response_len: pos,
        effects: DispatchEffects {
            configure_reporting: Some(ConfigureReportingEffect {
                accepted_send_records: accepted_send,
            }),
            group: GroupEffect::None,
        },
    })
}

/// Dispatch `ReadReportingConfiguration` (0x08) →
/// `ReadReportingConfigurationResponse` (0x09).
///
/// Request payload: repeated `[direction(1), attr_id(2)]` records.
/// Response: one record per request, each written by
/// `ClusterServer::read_reporting_config`. Empty request returns an empty
/// response body (just the header).
fn dispatch_read_reporting_config<CS: ClusterServer>(
    server: &CS,
    frame: &IncomingZclFrame<'_>,
    data: &[u8],
    buf: &mut [u8],
) -> Result<DispatchOutcome, ZclError> {
    let hdr_len = write_global_response_header(buf, frame, 0x09)?;
    let mut pos = hdr_len;
    let mut offset = 0;
    while offset + 3 <= data.len() {
        let direction = data[offset];
        let attr_id = AttributeId::new(u16::from_le_bytes([data[offset + 1], data[offset + 2]]));
        offset += 3;
        let n = server.read_reporting_config(attr_id, direction, &mut buf[pos..]);
        pos += n;
    }
    Ok(DispatchOutcome {
        response_len: pos,
        effects: DispatchEffects::default(),
    })
}

fn dispatch_unknown_global(
    frame: &IncomingZclFrame<'_>,
    ctx: DispatchContext,
    buf: &mut [u8],
) -> Result<usize, ZclError> {
    if should_send_default_response(frame, ctx, Status::UnsupGeneralCommand) {
        build_default_response_for_frame(frame, Status::UnsupGeneralCommand, buf)
    } else {
        Ok(0)
    }
}

fn finalize_command_response(
    result: CommandResult,
    frame: &IncomingZclFrame<'_>,
    ctx: DispatchContext,
    hdr_len: usize,
    buf: &mut [u8],
) -> Result<usize, ZclError> {
    match result {
        CommandResult::Suppress => Ok(0),
        CommandResult::Payload { command_id, len } => {
            // Payload is already in buf[hdr_len..hdr_len+len]. Write header into
            // buf[..hdr_len].
            if len > buf.len().saturating_sub(hdr_len) {
                return Err(ZclError::BufferTooSmall);
            }
            write_cluster_response_header(&mut buf[..hdr_len], frame, command_id.0)?;
            Ok(hdr_len + len)
        }
        CommandResult::DefaultResponse(status) => {
            if should_send_default_response(frame, ctx, status) {
                build_default_response_for_frame(frame, status, buf)
            } else {
                Ok(0)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use super::*;
    use crate::attribute_store::AttrDescriptor;
    use crate::attribute_store::SplitAttributeStore;
    use crate::attribute_store::StorageKind;
    use crate::frame::IncomingZclFrame;
    use crate::types::descriptors::AccessFlags;

    static TEST_ATTRS: &[AttrDescriptor] = &[
        AttrDescriptor {
            attr: AttributeId::new(0x0000),
            access: AccessFlags::READ,
            type_id: TypeId::Uint8,
            storage: StorageKind::ConstScalar(42),
        },
        AttrDescriptor {
            attr: AttributeId::new(0x0001),
            access: AccessFlags::READ_WRITE,
            type_id: TypeId::Uint16,
            storage: StorageKind::MutableScalar { index: 0 },
        },
        AttrDescriptor {
            attr: AttributeId::new(0x0002),
            access: AccessFlags::READ,
            type_id: TypeId::CharacterString,
            storage: StorageKind::StaticString(crate::attribute_store::StaticStringValue::Text(
                "hello",
            )),
        },
    ];

    const _: () = assert!(
        crate::attribute_store::is_sorted(TEST_ATTRS),
        "TEST_ATTRS must be sorted"
    );
    const _: () = assert!(
        crate::attribute_store::has_no_duplicate_keys(TEST_ATTRS),
        "TEST_ATTRS must have unique keys"
    );

    use core::cell::Cell;

    struct TestServer {
        store: SplitAttributeStore<1>,
    }

    impl TestServer {
        fn new() -> Self {
            Self {
                store: SplitAttributeStore::new(TEST_ATTRS, [Cell::new(0u64)]),
            }
        }
    }

    impl ClusterServer for TestServer {
        const CLUSTER_ID: ClusterId = ClusterId::new(0xABCD);

        fn read_attribute(
            &self,
            id: AttributeId,
            buf: &mut [u8],
        ) -> Result<(TypeId, usize), AttrError> {
            self.store.read_into(id, buf)
        }

        fn check_write_attribute(
            &self,
            id: AttributeId,
            type_id: TypeId,
            data: &[u8],
        ) -> Result<(), AttrError> {
            self.store.check_write_from(id, type_id, data)
        }

        fn write_attribute(
            &mut self,
            id: AttributeId,
            type_id: TypeId,
            data: &[u8],
        ) -> Result<(), AttrError> {
            self.store.write_from(id, type_id, data)
        }

        fn attribute_list() -> &'static [AttrInfo] {
            static LIST: [AttrInfo; 3] = [
                AttrInfo {
                    id: AttributeId::new(0x0000),
                    type_id: TypeId::Uint8,
                    access: AccessFlags::READ,
                },
                AttrInfo {
                    id: AttributeId::new(0x0001),
                    type_id: TypeId::Uint16,
                    access: AccessFlags::READ_WRITE,
                },
                AttrInfo {
                    id: AttributeId::new(0x0002),
                    type_id: TypeId::CharacterString,
                    access: AccessFlags::READ,
                },
            ];
            &LIST
        }
    }

    struct PayloadServer;

    impl ClusterServer for PayloadServer {
        const CLUSTER_ID: ClusterId = ClusterId::new(0xBEEF);

        fn read_attribute(
            &self,
            _id: AttributeId,
            _buf: &mut [u8],
        ) -> Result<(TypeId, usize), AttrError> {
            Err(AttrError::UnsupportedAttribute)
        }

        fn check_write_attribute(
            &self,
            _id: AttributeId,
            _type_id: TypeId,
            _data: &[u8],
        ) -> Result<(), AttrError> {
            Err(AttrError::UnsupportedAttribute)
        }

        fn write_attribute(
            &mut self,
            _id: AttributeId,
            _type_id: TypeId,
            _data: &[u8],
        ) -> Result<(), AttrError> {
            Err(AttrError::UnsupportedAttribute)
        }

        fn handle_command(
            &mut self,
            id: CommandId,
            _payload: &[u8],
            _ctx: DispatchContext,
            buf: &mut [u8],
        ) -> Result<CommandResult, ZclError> {
            if id == CommandId::new(0x40) {
                if buf.len() < 2 {
                    return Err(ZclError::BufferTooSmall);
                }
                buf[0] = 0xAA;
                buf[1] = 0xBB;
                Ok(CommandResult::Payload {
                    command_id: CommandId::new(0x41),
                    len: 2,
                })
            } else {
                Ok(CommandResult::DefaultResponse(Status::UnsupCommand))
            }
        }
    }

    fn unicast() -> DispatchContext {
        DispatchContext::unicast(0, None)
    }

    fn broadcast() -> DispatchContext {
        DispatchContext::broadcast(0)
    }

    // -------------------------------------------------------------------
    // ReadAttributes
    // -------------------------------------------------------------------

    #[test]
    fn read_attributes_success_encodes_value() {
        // ReadAttributes for attr 0x0000 (Uint8 = 42)
        let req: &[u8] = &[
            0x00, // frame control: global, client→server
            0x01, // seq
            0x00, // ReadAttributes
            0x00, 0x00, // attr 0x0000
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TestServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // Response: ZCL header(3) + attr_id(2) + status(1) + type_id(1) + value(1) = 8
        assert_eq!(n, 8);
        assert_eq!(buf[0], 0x18); // frame control
        assert_eq!(buf[1], 0x01); // seq echoed
        assert_eq!(buf[2], 0x01); // ReadAttributesResponse
        assert_eq!(buf[3..5], [0x00, 0x00]); // attr_id LE
        assert_eq!(buf[5], 0x00); // Success
        assert_eq!(buf[6], TypeId::Uint8.as_u8());
        assert_eq!(buf[7], 42); // value
    }

    #[test]
    fn read_attributes_unknown_attr_returns_per_record_status() {
        let req: &[u8] = &[
            0x00, 0x02, 0x00, 0xFF, 0xFF, // unknown attr
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TestServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + attr_id(2) + status(1) = 6
        assert_eq!(n, 6);
        assert_eq!(buf[3..5], [0xFF, 0xFF]);
        assert_eq!(buf[5], Status::UnsupportedAttribute as u8);
    }

    // -------------------------------------------------------------------
    // WriteAttributes
    // -------------------------------------------------------------------

    #[test]
    fn write_attributes_success_returns_single_success_record() {
        // Write attr 0x0001 (Uint16, writable) = 0x1234
        let req: &[u8] = &[
            0x00, 0x03, 0x02, // header: global, seq=3, WriteAttributes
            0x01, 0x00, // attr_id
            0x21, // Uint16
            0x34, 0x12, // 0x1234 LE
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TestServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + success(1) = 4
        assert_eq!(n, 4);
        assert_eq!(buf[2], 0x04); // WriteAttributesResponse
        assert_eq!(buf[3], 0x00); // Success, no attr_id
    }

    #[test]
    fn write_attributes_readonly_returns_failure_record() {
        // Write attr 0x0000 (read-only)
        let req: &[u8] = &[
            0x00, 0x04, 0x02, 0x00, 0x00, // attr_id 0x0000
            0x20, // Uint8
            0x05,
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TestServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + status(1) + attr_id(2) = 6
        assert_eq!(n, 6);
        assert_eq!(buf[3], Status::ReadOnly as u8);
        assert_eq!(buf[4..6], [0x00, 0x00]);
    }

    #[test]
    fn write_attributes_unknown_type_id_returns_invalid_data_type_record() {
        // attr_id = 0x0001, type_id = 0xFF (Unknown) — value length is unknowable
        let req: &[u8] = &[
            0x00, 0x10, 0x02, // WriteAttributes
            0x01, 0x00, // attr_id
            0xFF, // Unknown type_id — no value bytes follow
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TestServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + status(1) + attr_id(2) = 6
        assert_eq!(n, 6);
        assert_eq!(buf[2], 0x04); // WriteAttributesResponse
        assert_eq!(buf[3], Status::InvalidDataType as u8);
        assert_eq!(buf[4..6], [0x01, 0x00]); // attr_id LE
    }

    #[test]
    fn write_attributes_no_response_returns_ok_zero() {
        let req: &[u8] = &[
            0x00, 0x05, 0x05, // WriteAttributesNoResponse
            0x00, 0x00, // read-only attr
            0x20, 0x01,
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TestServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;
        assert_eq!(n, 0);
    }

    // -------------------------------------------------------------------
    // WriteAttributesUndivided
    // -------------------------------------------------------------------

    #[test]
    fn write_attributes_undivided_all_pass_writes_all() {
        // Two records: attr 0x0001 (writable) twice — both should succeed
        let req: &[u8] = &[
            0x00, 0x06, 0x03, // WriteAttributesUndivided
            0x01, 0x00, 0x21, 0x01, 0x00, // attr 0x0001 = 1
            0x01, 0x00, 0x21, 0x02, 0x00, // attr 0x0001 = 2 (second write wins)
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TestServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        assert_eq!(n, 4); // header(3) + success(1)
        assert_eq!(buf[3], 0x00);
    }

    #[test]
    fn write_attributes_undivided_any_fail_writes_none() {
        // Record 1: writable attr. Record 2: read-only attr.
        // Both must fail → value unchanged after dispatch.
        let req: &[u8] = &[
            0x00, 0x07, 0x03, 0x01, 0x00, 0x21, 0x99, 0x00, // writable
            0x00, 0x00, 0x20, 0x01, // read-only attr 0x0000
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TestServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // Should contain only the failure record for attr 0x0000
        assert!(n > 4);
        let found_readonly = buf[3..n].chunks(3).any(|chunk| {
            chunk.len() == 3
                && chunk[0] == Status::ReadOnly as u8
                && u16::from_le_bytes([chunk[1], chunk[2]]) == 0x0000
        });
        assert!(
            found_readonly,
            "expected ReadOnly failure record for attr 0x0000"
        );

        // Confirm the writable attr was NOT written (value unchanged = 0)
        let mut rbuf = [0u8; 4];
        server
            .store
            .read_into(AttributeId::new(0x0001), &mut rbuf)
            .unwrap();
        assert_eq!(u16::from_le_bytes([rbuf[0], rbuf[1]]), 0u16);
    }

    // -------------------------------------------------------------------
    // DefaultResponse (incoming)
    // -------------------------------------------------------------------

    #[test]
    fn incoming_default_response_returns_ok_zero() {
        let req: &[u8] = &[
            0x18, // server→client, disable DR
            0x08, 0x0b, // DefaultResponse command
            0x00, // responding to ReadAttributes
            0x00, // Success
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TestServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;
        assert_eq!(n, 0);
    }

    #[test]
    fn discover_attributes_all_fit_returns_complete() {
        let req: &[u8] = &[
            0x00, 0x09, 0x0c, // DiscoverAttributes
            0x00, 0x00, // start_attr = 0x0000
            0xFF, // max_count = 255
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 64];
        let mut server = TestServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + discovery_complete(1) + 3 records × 3 bytes = 13
        assert_eq!(n, 13);
        assert_eq!(buf[2], 0x0d); // DiscoverAttributesResponse
        assert_eq!(buf[3], 0x01); // discovery_complete = true
        // First record: attr 0x0000, Uint8
        assert_eq!(buf[4..6], [0x00, 0x00]);
        assert_eq!(buf[6], TypeId::Uint8.as_u8());
    }

    #[test]
    fn discover_attributes_truncated_returns_incomplete() {
        let req: &[u8] = &[
            0x00, 0x0a, 0x0c, 0x00, 0x00, // start_attr = 0x0000
            0x01, // max_count = 1
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TestServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        assert_eq!(buf[3], 0x00); // discovery_complete = false (more exist)
        // Only 1 record: attr 0x0000, Uint8
        let _ = n;
    }

    // -------------------------------------------------------------------
    // ClusterSpecific direction bit
    // -------------------------------------------------------------------

    #[test]
    fn cluster_specific_server_to_client_returns_ok_zero() {
        // direction bit = 1 (server→client): server ignores it
        let req: &[u8] = &[
            0x09, // cluster-specific | direction=server-to-client
            0x0b, 0x00, // command 0x00
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TestServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;
        assert_eq!(n, 0);
    }

    #[test]
    fn cluster_specific_payload_response_uses_cluster_specific_header() {
        let req: &[u8] = &[
            0x01, // cluster-specific | client→server
            0x22, 0x40,
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = PayloadServer;
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        assert_eq!(n, 5);
        assert_eq!(buf[0], 0x19);
        assert_eq!(buf[1], 0x22);
        assert_eq!(buf[2], 0x41);
        assert_eq!(&buf[3..5], &[0xAA, 0xBB]);
    }

    // -------------------------------------------------------------------
    // Default Response suppression rules
    // -------------------------------------------------------------------

    #[test]
    fn configure_reporting_broadcast_returns_ok_zero() {
        // ConfigureReporting broadcast → no response
        let req: &[u8] = &[0x00, 0x0c, 0x06];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TestServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, broadcast(), &mut buf)
            .unwrap()
            .response_len;
        assert_eq!(n, 0);
    }

    #[test]
    fn configure_reporting_empty_unicast_returns_success() {
        // ConfigureReporting with no records → ConfigureReportingResponse(Success)
        let req: &[u8] = &[0x00, 0x0d, 0x06];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TestServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;
        assert_eq!(n, 4);
        assert_eq!(buf[2], 0x07); // ConfigureReportingResponse
        assert_eq!(buf[3], 0x00); // Success
    }

    #[test]
    fn configure_reporting_manufacturer_specific_preserves_manufacturer_code() {
        let req: &[u8] = &[
            0x04, // global | manufacturer-specific | client→server
            0x34, 0x12, // manufacturer code
            0x55, // sequence
            0x06, // ConfigureReporting (no records)
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TestServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        assert_eq!(n, 6);
        assert_eq!(buf[0], 0x1c);
        assert_eq!(&buf[1..3], &[0x34, 0x12]);
        assert_eq!(buf[3], 0x55);
        assert_eq!(buf[4], 0x07); // ConfigureReportingResponse
        assert_eq!(buf[5], 0x00); // Success
    }

    #[test]
    fn configure_reporting_with_records_returns_unreportable() {
        // ConfigureReporting: direction=0, attr_id=0x0001, type=Uint16(0x21),
        // min=0x0000, max=0x003C, reportable_change=0x0001
        let req: &[u8] = &[
            0x00, 0x10, 0x06, // global, seq=0x10, ConfigureReporting
            0x00, // direction=0 (server sends to client)
            0x01, 0x00, // attr_id=0x0001
            0x21, // type=Uint16
            0x00, 0x00, // min_interval=0
            0x3C, 0x00, // max_interval=60
            0x01, 0x00, // reportable_change=1
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TestServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + status(1) + direction(1) + attr_id(2) = 7
        assert_eq!(n, 7);
        assert_eq!(buf[2], 0x07); // ConfigureReportingResponse
        assert_eq!(buf[3], Status::UnreportableAttribute as u8);
        assert_eq!(buf[4], 0x00); // direction
        assert_eq!(&buf[5..7], &[0x01, 0x00]); // attr_id LE
    }

    #[test]
    fn read_reporting_configuration_unconfigured_attr_returns_not_found() {
        // ReadReportingConfiguration: direction=0, attr_id=0x0000
        let req: &[u8] = &[
            0x00, 0x20, 0x08, // global, seq=0x20, ReadReportingConfiguration
            0x00, 0x00, 0x00, // direction=0, attr_id=0x0000
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TestServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;
        // header(3) + status(1) + direction(1) + attr_id(2) = 7
        assert_eq!(n, 7);
        assert_eq!(buf[2], 0x09); // ReadReportingConfigurationResponse
        assert_eq!(buf[3], 0x8b); // NOT_FOUND
        assert_eq!(buf[4], 0x00); // direction
        assert_eq!(&buf[5..7], &[0x00, 0x00]); // attr_id LE
    }

    #[test]
    fn read_reporting_configuration_empty_request_returns_header_only() {
        let req: &[u8] = &[0x00, 0x21, 0x08]; // no records
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TestServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;
        assert_eq!(n, 3); // just the header
        assert_eq!(buf[2], 0x09);
    }

    #[test]
    fn read_reporting_configuration_multiple_attrs_each_get_not_found() {
        let req: &[u8] = &[
            0x00, 0x22, 0x08, 0x00, 0x00, 0x00, // attr 0x0000
            0x00, 0x01, 0x00, // attr 0x0001
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TestServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;
        // header(3) + 2×record(4) = 11
        assert_eq!(n, 11);
        assert_eq!(buf[2], 0x09);
        assert_eq!(buf[3], 0x8b); // record 1 NOT_FOUND
        assert_eq!(&buf[4..6], &[0x00, 0x00, 0x00][..2]); // direction+attr_id_lo
        assert_eq!(buf[7], 0x8b); // record 2 NOT_FOUND
    }

    #[test]
    fn sequence_number_is_echoed_in_response() {
        let req: &[u8] = &[
            0x00, 0xAB, 0x00, // seq = 0xAB, ReadAttributes
            0x00, 0x00,
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TestServer::new();
        let _ = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;
        assert_eq!(buf[1], 0xAB);
    }

    // -------------------------------------------------------------------
    // build_default_response / should_send_default_response
    // -------------------------------------------------------------------

    #[test]
    fn build_default_response_writes_correct_bytes() {
        use crate::header::command_identifier::CommandIdentifier;
        let mut buf = [0u8; 8];
        let n = build_default_response(
            CommandIdentifier::ReadAttributes,
            Status::UnsupportedAttribute,
            0x42,
            &mut buf,
        )
        .unwrap();
        assert_eq!(n, 5);
        assert_eq!(buf[0], 0x18);
        assert_eq!(buf[1], 0x42);
        assert_eq!(buf[2], 0x0b);
        assert_eq!(buf[3], 0x00); // ReadAttributes raw
        assert_eq!(buf[4], Status::UnsupportedAttribute as u8);
    }

    #[test]
    fn build_default_response_for_frame_preserves_manufacturer_code() {
        let req: &[u8] = &[
            0x04, // global | manufacturer-specific | client→server
            0x78, 0x56, // manufacturer code
            0x42, 0x00,
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 8];
        let n =
            build_default_response_for_frame(&frame, Status::UnsupportedCluster, &mut buf).unwrap();

        assert_eq!(n, 7);
        assert_eq!(buf[0], 0x1c);
        assert_eq!(&buf[1..3], &[0x78, 0x56]);
        assert_eq!(buf[3], 0x42);
        assert_eq!(buf[4], 0x0b);
        assert_eq!(buf[5], 0x00);
        assert_eq!(buf[6], Status::UnsupportedCluster as u8);
    }
    #[test]
    fn should_send_default_response_suppressed_on_broadcast() {
        let req: &[u8] = &[0x00, 0x01, 0x06];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        assert!(!should_send_default_response(
            &frame,
            broadcast(),
            Status::UnsupCommand
        ));
    }

    #[test]
    fn should_send_default_response_suppressed_for_success_with_disable_bit() {
        // frame_control 0x10 = disable-default-response bit set
        let req: &[u8] = &[0x10, 0x01, 0x06];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        assert!(!should_send_default_response(
            &frame,
            unicast(),
            Status::Success
        ));
    }

    #[test]
    fn should_send_default_response_error_ignores_disable_bit() {
        let req: &[u8] = &[0x10, 0x01, 0x06];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        assert!(should_send_default_response(
            &frame,
            unicast(),
            Status::UnsupCommand
        ));
    }

    #[test]
    fn should_send_default_response_suppressed_for_incoming_default_response() {
        let req: &[u8] = &[
            0x18, // global | server→client | disable default response
            0x01, 0x0b, 0x00, 0x00,
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        assert!(!should_send_default_response(
            &frame,
            unicast(),
            Status::UnsupportedCluster
        ));
    }

    #[test]
    fn should_send_default_response_suppressed_for_write_no_response() {
        let req: &[u8] = &[0x00, 0x01, 0x05, 0x00, 0x00, 0x20, 0x01];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        assert!(!should_send_default_response(
            &frame,
            unicast(),
            Status::UnsupportedCluster
        ));
    }

    // -------------------------------------------------------------------
    // DiscoverCommandsReceived / DiscoverCommandsGenerated
    // -------------------------------------------------------------------

    struct CommandServer;

    impl ClusterServer for CommandServer {
        const CLUSTER_ID: ClusterId = ClusterId::new(0xCAFE);

        fn read_attribute(
            &self,
            _id: AttributeId,
            _buf: &mut [u8],
        ) -> Result<(TypeId, usize), AttrError> {
            Err(AttrError::UnsupportedAttribute)
        }

        fn commands_received() -> &'static [CommandId] {
            static CMDS: [CommandId; 3] = [
                CommandId::new(0x00),
                CommandId::new(0x01),
                CommandId::new(0x02),
            ];
            &CMDS
        }

        fn commands_generated() -> &'static [CommandId] {
            static CMDS: [CommandId; 1] = [CommandId::new(0x00)];
            &CMDS
        }
    }

    #[test]
    fn discover_commands_received_empty_cluster_returns_complete() {
        // TestServer has no commands_received (default empty)
        let req: &[u8] = &[
            0x00, 0x20, 0x11, // DiscoverCommandsReceived
            0x00, // start_cmd = 0
            0xFF, // max_count = 255
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TestServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + discovery_complete(1) = 4, no command records
        assert_eq!(n, 4);
        assert_eq!(buf[2], 0x12); // DiscoverCommandsReceivedResponse
        assert_eq!(buf[3], 0x01); // discovery_complete = true
    }

    #[test]
    fn discover_commands_received_all_fit_returns_complete() {
        let req: &[u8] = &[
            0x00, 0x21, 0x11, // DiscoverCommandsReceived
            0x00, // start_cmd = 0
            0xFF, // max_count = 255
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = CommandServer;
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + discovery_complete(1) + 3 command records × 1 byte = 7
        assert_eq!(n, 7);
        assert_eq!(buf[2], 0x12); // DiscoverCommandsReceivedResponse
        assert_eq!(buf[3], 0x01); // discovery_complete = true
        assert_eq!(buf[4], 0x00); // cmd 0x00
        assert_eq!(buf[5], 0x01); // cmd 0x01
        assert_eq!(buf[6], 0x02); // cmd 0x02
    }

    #[test]
    fn discover_commands_received_truncated_returns_incomplete() {
        let req: &[u8] = &[
            0x00, 0x22, 0x11, // DiscoverCommandsReceived
            0x00, // start_cmd = 0
            0x02, // max_count = 2
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = CommandServer;
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + discovery_complete(1) + 2 records = 6
        assert_eq!(n, 6);
        assert_eq!(buf[3], 0x00); // discovery_complete = false
        assert_eq!(buf[4], 0x00); // cmd 0x00
        assert_eq!(buf[5], 0x01); // cmd 0x01
    }

    #[test]
    fn discover_commands_received_start_offset_skips_earlier_commands() {
        let req: &[u8] = &[
            0x00, 0x23, 0x11, // DiscoverCommandsReceived
            0x01, // start_cmd = 1 (skip 0x00)
            0xFF,
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = CommandServer;
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + complete(1) + 2 records (0x01, 0x02) = 6
        assert_eq!(n, 6);
        assert_eq!(buf[3], 0x01); // complete
        assert_eq!(buf[4], 0x01);
        assert_eq!(buf[5], 0x02);
    }

    #[test]
    fn discover_commands_generated_returns_correct_response_id() {
        let req: &[u8] = &[
            0x00, 0x24, 0x13, // DiscoverCommandsGenerated
            0x00, 0xFF,
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = CommandServer;
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + complete(1) + 1 record = 5
        assert_eq!(n, 5);
        assert_eq!(buf[2], 0x14); // DiscoverCommandsGeneratedResponse
        assert_eq!(buf[3], 0x01); // complete
        assert_eq!(buf[4], 0x00); // cmd 0x00
    }

    // -------------------------------------------------------------------
    // DiscoverAttributesExtended
    // -------------------------------------------------------------------

    #[test]
    fn discover_attributes_extended_all_fit_returns_complete_with_access() {
        let req: &[u8] = &[
            0x00, 0x30, 0x15, // DiscoverAttributesExtended
            0x00, 0x00, // start_attr = 0x0000
            0xFF, // max_count = 255
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 64];
        let mut server = TestServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + discovery_complete(1) + 3 records × 4 bytes = 16
        assert_eq!(n, 16);
        assert_eq!(buf[2], 0x16); // DiscoverAttributesExtendedResponse
        assert_eq!(buf[3], 0x01); // discovery_complete = true

        // First record: attr 0x0000, Uint8, READ (0x01)
        assert_eq!(buf[4..6], [0x00, 0x00]);
        assert_eq!(buf[6], TypeId::Uint8.as_u8());
        assert_eq!(buf[7], AccessFlags::READ.as_u8());

        // Second record: attr 0x0001, Uint16, READ_WRITE (0x03)
        assert_eq!(buf[8..10], [0x01, 0x00]);
        assert_eq!(buf[10], TypeId::Uint16.as_u8());
        assert_eq!(buf[11], AccessFlags::READ_WRITE.as_u8());
    }

    #[test]
    fn discover_attributes_extended_truncated_returns_incomplete() {
        let req: &[u8] = &[
            0x00, 0x31, 0x15, 0x00, 0x00, // start_attr = 0x0000
            0x01, // max_count = 1
        ];
        let (frame, _) = IncomingZclFrame::decode(req).unwrap();
        let mut buf = [0u8; 32];
        let mut server = TestServer::new();
        let n = zcl_cluster_dispatch(&mut server, &frame, unicast(), &mut buf)
            .unwrap()
            .response_len;

        // header(3) + complete(1) + 1 record × 4 bytes = 8
        assert_eq!(n, 8);
        assert_eq!(buf[3], 0x00); // discovery_complete = false
    }
}
