use heapless::Vec;

use crate::cluster_server::ClusterServer;
use crate::cluster_server::ConfigureReportingRecord;
use crate::cluster_server::DispatchContext;
use crate::cluster_server::ReportDeliveryResult;
use crate::cluster_server::ReportDestination;
use crate::cluster_server::ReportToken;
use crate::cluster_server::ReportingDiagnostics;
use crate::frame::Status;
use crate::types::descriptors::AttrInfo;
use crate::types::error::AttrError;
use crate::types::error::ZclError;
use crate::types::ids::AttributeId;
use crate::types::ids::TypeId;

/// Incrementally assembles a `ReportAttributes` (0x0a) payload.
///
/// Both write methods are position-atomic: an `Err` result leaves `len()`
/// unchanged and no partial record is visible in the output buffer.
pub struct ReportPayloadWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> ReportPayloadWriter<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn len(&self) -> usize {
        self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }

    /// Write a pre-encoded attribute record: `attr_id (u16 LE) + type_id (u8) +
    /// encoded_value`.
    pub fn write_encoded(
        &mut self,
        attr_id: AttributeId,
        type_id: TypeId,
        encoded_value: &[u8],
    ) -> Result<(), ZclError> {
        let needed = 2 + 1 + encoded_value.len();
        let end = self.pos + needed;
        let slot = self
            .buf
            .get_mut(self.pos..end)
            .ok_or(ZclError::BufferTooSmall)?;
        slot[0..2].copy_from_slice(&attr_id.0.to_le_bytes());
        slot[2] = type_id.as_u8();
        slot[3..].copy_from_slice(encoded_value);
        self.pos = end;
        Ok(())
    }

    /// Read `attr_id` from `cluster` and write the encoded record into the
    /// buffer.
    pub fn write_from_cluster<C: ClusterServer>(
        &mut self,
        cluster: &C,
        attr_id: AttributeId,
    ) -> Result<(), ZclError> {
        let start = self.pos;
        // Reserve 3 bytes for attr_id (2) + type_id (1); value goes after.
        let header_end = start + 3;
        if self.buf.len() < header_end {
            return Err(ZclError::BufferTooSmall);
        }
        let value_buf = self
            .buf
            .get_mut(header_end..)
            .ok_or(ZclError::BufferTooSmall)?;
        let (type_id, value_len) =
            cluster
                .read_attribute(attr_id, value_buf)
                .map_err(|e| match e {
                    AttrError::Codec(ze) => ze,
                    _ => ZclError::InvalidValue,
                })?;
        let end = header_end + value_len;
        // Check nothing ran past buf — read_attribute already wrote into value_buf
        // safely.
        if end > self.buf.len() {
            return Err(ZclError::BufferTooSmall);
        }
        self.buf[start..start + 2].copy_from_slice(&attr_id.0.to_le_bytes());
        self.buf[start + 2] = type_id.as_u8();
        self.pos = end;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LatestUpdate {
    Unchanged,
    Pending,
    Coalesced,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportDue {
    Change,
    MaxInterval,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportCandidate {
    pub attr_id: AttributeId,
    pub type_id: TypeId,
    pub destination: ReportDestination,
    pub token: ReportToken,
    pub due: ReportDue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportSkip {
    BelowThreshold,
    BufferTooSmall,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportRetention {
    Latest,
    Queue,
    MustDeliver,
}

/// Per-subscription state.
#[derive(Clone, Copy, Debug)]
pub struct ReportingEntry<const VALUE_BYTES: usize> {
    pub attr_id: AttributeId,
    pub type_id: TypeId,
    pub min_interval: u16,
    pub max_interval: u16,
    /// Absolute monotonic ms of the last successfully delivered report.
    /// `None` = never reported.
    pub last_reported_ms: Option<u32>,
    pub destination: ReportDestination,
    pub token: ReportToken,
    /// True when application state changed and a report is pending
    /// transmission.
    pending: bool,
    /// Reportable-change threshold (≤`VALUE_BYTES` bytes, type-encoded LE).
    /// Zero length = any-change threshold (Boolean / default).
    reportable_change: [u8; VALUE_BYTES],
    reportable_change_len: u8,
    /// Last successfully reported encoded value (≤`VALUE_BYTES` bytes).
    /// Zero length = never reported.
    last_encoded: [u8; VALUE_BYTES],
    last_encoded_len: u8,
    /// Encoded value written into the most recent in-flight report.
    /// Committed to `last_encoded` only after `ReportDeliveryResult::Sent`.
    pending_encoded: [u8; VALUE_BYTES],
    pending_encoded_len: u8,
}

/// `Latest`-retention reporting state for at most `N` attributes.
///
/// `VALUE_BYTES` controls how many bytes are stored per-entry for threshold
/// tracking (`last_encoded`, `pending_encoded`, `reportable_change`). Must
/// match the `max_encoded_bytes` argument passed to `impl_reporting!`. Typical
/// values: `u8` attrs → 1, `u16`/`i16` → 2, `u32`/`i32` → 4, `u64`/`i64` → 8.
///
/// Each new entry receives a unique token from a monotonically incrementing
/// counter, so tokens remain valid even after earlier entries are removed.
pub struct LatestReportingTable<const N: usize, const VALUE_BYTES: usize = 4> {
    entries: Vec<ReportingEntry<VALUE_BYTES>, N>,
    diagnostics: ReportingDiagnostics,
    next_token: u16,
}

pub type ReportingTable<const N: usize, const VALUE_BYTES: usize = 4> =
    LatestReportingTable<N, VALUE_BYTES>;

impl<const N: usize, const VALUE_BYTES: usize> LatestReportingTable<N, VALUE_BYTES> {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            diagnostics: ReportingDiagnostics {
                coalesced_updates: 0,
                dropped_reports: 0,
                buffer_too_small: false,
            },
            next_token: 0,
        }
    }

    /// Configure reporting for one attribute.
    ///
    /// Validates against `attrs` and updates or inserts an entry.
    /// Edge behavior:
    /// - `direction == 1` (receive) → `UnreportableAttribute`
    /// - attribute not in `attrs` or not reportable → `UnreportableAttribute`
    /// - type mismatch → `InvalidDataType`
    /// - `ctx.source.is_none()` (broadcast/non-unicast) → `Failure`
    /// - `max_interval == 0xffff` → disable/remove and return `Success`
    /// - table capacity exhausted → `InsufficientSpace`
    pub fn configure(
        &mut self,
        record: ConfigureReportingRecord<'_>,
        ctx: DispatchContext,
        attrs: &[AttrInfo],
    ) -> Status {
        // Receive-direction: not supported.
        if record.direction != 0 {
            return Status::UnreportableAttribute;
        }

        let type_id = TypeId::from_u8(record.attr_type);
        let attr_id = record.attr_id;

        // Validate attribute exists and is reportable.
        let Some(attr_info) = attrs.iter().find(|a| a.id == attr_id) else {
            return Status::UnreportableAttribute;
        };
        if !attr_info.access.is_reportable() {
            return Status::UnreportableAttribute;
        }
        if attr_info.type_id != type_id {
            return Status::InvalidDataType;
        }

        // max_interval == 0xFFFF → disable.
        if record.max_interval == 0xFFFF {
            self.entries.retain(|e| e.attr_id != attr_id);
            return Status::Success;
        }

        // Unicast source required.
        let Some(source) = ctx.source else {
            return Status::Failure;
        };
        let destination = ReportDestination::Unicast(source);

        // Store reportable_change bytes (up to VALUE_BYTES).
        let rc_len =
            u8::try_from(record.reportable_change.len().min(VALUE_BYTES)).unwrap_or(u8::MAX);
        let mut rc_bytes = [0u8; VALUE_BYTES];
        rc_bytes[..rc_len as usize].copy_from_slice(&record.reportable_change[..rc_len as usize]);

        // Upsert: update existing entry or push a new one.
        if let Some(entry) = self.entries.iter_mut().find(|e| e.attr_id == attr_id) {
            entry.type_id = type_id;
            entry.min_interval = record.min_interval;
            entry.max_interval = record.max_interval;
            entry.destination = destination;
            entry.reportable_change = rc_bytes;
            entry.reportable_change_len = rc_len;
            // Token and last_encoded preserved so threshold comparison stays
            // valid.
        } else {
            let token = ReportToken::new(self.next_token);
            self.next_token = self.next_token.wrapping_add(1);
            let entry = ReportingEntry {
                attr_id,
                type_id,
                min_interval: record.min_interval,
                max_interval: record.max_interval,
                // Age starts from subscription time so min_interval is honoured
                // from when reporting was configured, not from the epoch.
                last_reported_ms: Some(ctx.now_ms),
                destination,
                token,
                pending: false,
                reportable_change: rc_bytes,
                reportable_change_len: rc_len,
                last_encoded: [0u8; VALUE_BYTES],
                last_encoded_len: 0,
                pending_encoded: [0u8; VALUE_BYTES],
                pending_encoded_len: 0,
            };
            if self.entries.push(entry).is_err() {
                return Status::InsufficientSpace;
            }
        }

        Status::Success
    }

    /// Configure bound reporting for one attribute.
    ///
    /// Like `configure`, but stores `ReportDestination::Bound` instead of a
    /// unicast peer. Use this when the device should report via the APS
    /// binding table (e.g., application-initiated or coordinator-managed
    /// bindings).
    pub fn configure_bound(
        &mut self,
        attr_id: AttributeId,
        type_id: TypeId,
        min_interval: u16,
        max_interval: u16,
        now_ms: u32,
        attrs: &[AttrInfo],
    ) -> Status {
        let Some(attr_info) = attrs.iter().find(|a| a.id == attr_id) else {
            return Status::UnreportableAttribute;
        };
        if !attr_info.access.is_reportable() {
            return Status::UnreportableAttribute;
        }
        if attr_info.type_id != type_id {
            return Status::InvalidDataType;
        }

        if max_interval == 0xFFFF {
            self.entries.retain(|e| e.attr_id != attr_id);
            return Status::Success;
        }

        if let Some(entry) = self.entries.iter_mut().find(|e| e.attr_id == attr_id) {
            entry.type_id = type_id;
            entry.min_interval = min_interval;
            entry.max_interval = max_interval;
            entry.destination = ReportDestination::Bound;
        } else {
            let token = ReportToken::new(self.next_token);
            self.next_token = self.next_token.wrapping_add(1);
            let entry = ReportingEntry {
                attr_id,
                type_id,
                min_interval,
                max_interval,
                last_reported_ms: Some(now_ms),
                destination: ReportDestination::Bound,
                token,
                pending: false,
                reportable_change: [0u8; VALUE_BYTES],
                reportable_change_len: 0,
                last_encoded: [0u8; VALUE_BYTES],
                last_encoded_len: 0,
                pending_encoded: [0u8; VALUE_BYTES],
                pending_encoded_len: 0,
            };
            if self.entries.push(entry).is_err() {
                return Status::InsufficientSpace;
            }
        }

        Status::Success
    }

    /// Mark an attribute as having a new value. Returns `Pending` on first
    /// update, `Coalesced` when a pending update is replaced, `Unchanged`
    /// when no entry exists.
    pub fn note_value_update(&mut self, attr_id: AttributeId) -> LatestUpdate {
        match self.entries.iter_mut().find(|e| e.attr_id == attr_id) {
            None => LatestUpdate::Unchanged,
            Some(entry) if entry.pending => {
                self.diagnostics.coalesced_updates =
                    self.diagnostics.coalesced_updates.saturating_add(1);
                LatestUpdate::Coalesced
            }
            Some(entry) => {
                entry.pending = true;
                LatestUpdate::Pending
            }
        }
    }

    /// Return the first report candidate that is due, or `None`.
    ///
    /// Returns a *copy* so the caller may borrow `self` again (e.g., to call
    /// `skip` or read attribute state) without holding a reference into
    /// `entries`.
    pub fn next_due(&self, now_ms: u32) -> Option<ReportCandidate> {
        for entry in &self.entries {
            let age = entry
                .last_reported_ms
                .map_or(u32::MAX, |t| now_ms.wrapping_sub(t));

            let min_elapsed = age >= u32::from(entry.min_interval) * 1000;

            // Change-driven: pending and min_interval elapsed.
            if entry.pending && min_elapsed {
                return Some(ReportCandidate {
                    attr_id: entry.attr_id,
                    type_id: entry.type_id,
                    destination: entry.destination,
                    token: entry.token,
                    due: ReportDue::Change,
                });
            }

            // Max-interval-driven: max_interval != 0 (0 = change-only) and expired.
            if entry.max_interval != 0 {
                let max_elapsed = age >= u32::from(entry.max_interval) * 1000;
                if max_elapsed {
                    return Some(ReportCandidate {
                        attr_id: entry.attr_id,
                        type_id: entry.type_id,
                        destination: entry.destination,
                        token: entry.token,
                        due: ReportDue::MaxInterval,
                    });
                }
            }
        }
        None
    }

    /// Skip a pending report.
    ///
    /// `BelowThreshold`: clear `pending` without changing `last_reported_ms`.
    /// `BufferTooSmall`: leave `pending`; set `buffer_too_small` diagnostic.
    pub fn skip(&mut self, token: ReportToken, reason: ReportSkip) {
        match reason {
            ReportSkip::BelowThreshold => {
                if let Some(entry) = self.entry_by_token_mut(token) {
                    entry.pending = false;
                }
            }
            ReportSkip::BufferTooSmall => {
                self.diagnostics.buffer_too_small = true;
                // pending left as-is
            }
        }
    }

    /// Finalize a report attempt.
    ///
    /// `Sent`: commit `last_reported_ms`, clear `pending`.
    /// `Deferred`: leave `pending`; no diagnostic increment.
    /// `Failed`: clear `pending`; increment `dropped_reports`.
    pub fn complete(&mut self, token: ReportToken, result: ReportDeliveryResult, now_ms: u32) {
        let Some(entry) = self.entry_by_token_mut(token) else {
            return;
        };
        match result {
            ReportDeliveryResult::Sent => {
                entry.last_reported_ms = Some(now_ms);
                if entry.pending_encoded_len != 0 {
                    let n = usize::from(entry.pending_encoded_len);
                    entry.last_encoded[..n].copy_from_slice(&entry.pending_encoded[..n]);
                    entry.last_encoded_len = entry.pending_encoded_len;
                    entry.pending_encoded_len = 0;
                }
                entry.pending = false;
            }
            ReportDeliveryResult::Deferred => {
                // Keep pending; caller will retry.
            }
            ReportDeliveryResult::Failed => {
                entry.pending_encoded_len = 0;
                entry.pending = false;
                self.diagnostics.dropped_reports =
                    self.diagnostics.dropped_reports.saturating_add(1);
            }
        }
    }

    /// Drain accumulated diagnostics.
    pub fn take_diagnostics(&mut self) -> ReportingDiagnostics {
        core::mem::take(&mut self.diagnostics)
    }

    /// Write one `ReadReportingConfigurationResponse` record for `attr_id` into
    /// `buf` and return the number of bytes written.
    ///
    /// Direction must be 0 (server generates reports); direction=1 returns
    /// `NOT_FOUND` because this device does not receive remote attribute
    /// reports.
    ///
    /// Response record layout (ZCL §2.4.10.1):
    /// - `status` (1) + `direction` (1) + `attr_id` (2)
    /// - if `status == 0x00`: `data_type` (1) + `min_interval` (2) +
    ///   `max_interval` (2)
    ///   + `reportable_change` (0 or `reportable_change_len` bytes for analog
    ///     attrs)
    ///
    /// Returns 0 if `buf` is too small to hold the record.
    pub fn write_read_response_record(
        &self,
        attr_id: AttributeId,
        direction: u8,
        buf: &mut [u8],
    ) -> usize {
        if direction != 0 {
            if buf.len() < 4 {
                return 0;
            }
            buf[0] = 0x8b; // NOT_FOUND
            buf[1] = direction;
            buf[2] = (attr_id.0 & 0xff) as u8;
            buf[3] = (attr_id.0 >> 8) as u8;
            return 4;
        }
        match self.entries.iter().find(|e| e.attr_id == attr_id) {
            None => {
                if buf.len() < 4 {
                    return 0;
                }
                buf[0] = 0x8b; // NOT_FOUND
                buf[1] = 0x00;
                buf[2] = (attr_id.0 & 0xff) as u8;
                buf[3] = (attr_id.0 >> 8) as u8;
                4
            }
            Some(entry) => {
                let rc_len = entry.reportable_change_len as usize;
                let needed = 9 + rc_len;
                if buf.len() < needed {
                    return 0;
                }
                buf[0] = 0x00; // SUCCESS
                buf[1] = 0x00; // direction
                buf[2] = (attr_id.0 & 0xff) as u8;
                buf[3] = (attr_id.0 >> 8) as u8;
                buf[4] = entry.type_id.as_u8();
                buf[5] = (entry.min_interval & 0xff) as u8;
                buf[6] = (entry.min_interval >> 8) as u8;
                buf[7] = (entry.max_interval & 0xff) as u8;
                buf[8] = (entry.max_interval >> 8) as u8;
                buf[9..9 + rc_len].copy_from_slice(&entry.reportable_change[..rc_len]);
                9 + rc_len
            }
        }
    }

    /// Returns `true` when the change-driven report for `token` should be
    /// suppressed.
    ///
    /// Suppression rules:
    /// - Never suppress when this is the first report (no last-encoded value
    ///   yet).
    /// - No threshold configured → suppress if encoded bytes are identical.
    /// - Threshold configured → suppress if |current − last| < threshold.
    /// - For `MaxInterval`-driven reports, call `skip` only for `Change`-driven
    ///   ones; callers should not call this for `ReportDue::MaxInterval`
    ///   candidates.
    pub fn is_below_threshold(&self, token: ReportToken, type_id: TypeId, current: &[u8]) -> bool {
        let Some(entry) = self.entries.iter().find(|e| e.token == token) else {
            return false;
        };
        if entry.last_encoded_len == 0 {
            return false; // Never reported → always send.
        }
        let last = &entry.last_encoded[..entry.last_encoded_len as usize];
        if last.len() != current.len() {
            return false;
        }
        let threshold = &entry.reportable_change[..entry.reportable_change_len as usize];
        if threshold.is_empty() {
            return current == last;
        }
        numeric_below_threshold(type_id, current, last, threshold)
    }

    /// Stage the encoded value written into the current in-flight report.
    ///
    /// The staged value is committed to `last_encoded` only when `complete`
    /// receives `ReportDeliveryResult::Sent`. Deferred or failed sends must
    /// not affect threshold comparisons for the next retry.
    pub fn record_value(&mut self, token: ReportToken, encoded: &[u8]) {
        let Some(entry) = self.entry_by_token_mut(token) else {
            return;
        };
        let n = encoded.len().min(VALUE_BYTES);
        entry.pending_encoded[..n].copy_from_slice(&encoded[..n]);
        entry.pending_encoded_len = u8::try_from(n).unwrap_or(0);
    }

    fn entry_by_token_mut(
        &mut self,
        token: ReportToken,
    ) -> Option<&mut ReportingEntry<VALUE_BYTES>> {
        self.entries.iter_mut().find(|e| e.token == token)
    }
}

fn numeric_below_threshold(type_id: TypeId, current: &[u8], last: &[u8], threshold: &[u8]) -> bool {
    match type_id {
        TypeId::Int8 => {
            if current.is_empty() || last.is_empty() || threshold.is_empty() {
                return false;
            }
            let c = i8::from_ne_bytes([current[0]]);
            let l = i8::from_ne_bytes([last[0]]);
            let t = i8::from_ne_bytes([threshold[0]]);
            c.saturating_sub(l).abs() < t
        }
        TypeId::Int16 => {
            if current.len() < 2 || last.len() < 2 || threshold.len() < 2 {
                return false;
            }
            let c = i16::from_le_bytes([current[0], current[1]]);
            let l = i16::from_le_bytes([last[0], last[1]]);
            let t = i16::from_le_bytes([threshold[0], threshold[1]]);
            // Null sentinel i16::MIN — treat as "always changed".
            if c == i16::MIN || l == i16::MIN {
                return false;
            }
            c.saturating_sub(l).abs() < t
        }
        TypeId::Uint8 => {
            if current.is_empty() || last.is_empty() || threshold.is_empty() {
                return false;
            }
            current[0].abs_diff(last[0]) < threshold[0]
        }
        TypeId::Uint16 => {
            if current.len() < 2 || last.len() < 2 || threshold.len() < 2 {
                return false;
            }
            let c = u16::from_le_bytes([current[0], current[1]]);
            let l = u16::from_le_bytes([last[0], last[1]]);
            let t = u16::from_le_bytes([threshold[0], threshold[1]]);
            // Null sentinel 0xFFFF — treat as "always changed".
            if c == 0xFFFF || l == 0xFFFF {
                return false;
            }
            c.abs_diff(l) < t
        }
        // Boolean and other types: byte equality.
        _ => current == last,
    }
}

impl<const N: usize, const VALUE_BYTES: usize> Default for LatestReportingTable<N, VALUE_BYTES> {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for read/write access to non-volatile storage of a reporting table.
///
/// Implementors wrap any NVM backend (flash pages, EEPROM, embedded-storage
/// `NorFlash`, etc.). `load` must fill the buffer with the bytes previously
/// written by `save`, returning the number of bytes loaded. On first boot
/// (uninitialized storage) implementations should return `Ok(0)`.
#[allow(clippy::result_unit_err)]
pub trait ReportingStore {
    /// Load persisted bytes into `buf`. Returns the number of bytes loaded.
    fn load(&self, buf: &mut [u8]) -> Result<usize, ()>;
    /// Persist `buf` to non-volatile storage. The entire slice is considered
    /// one atomic record — partial writes are never visible after a reload.
    fn save(&mut self, buf: &[u8]) -> Result<(), ()>;
}

/// Wire format per entry (11 bytes):
///   `attr_id`(2) + `type_id`(1) + `min`(2) + `max`(2) + `dst_type`(1) +
/// `dst_short`(2) + `dst_ep`(1)
const ENTRY_BYTES: usize = 11;
const MAGIC: [u8; 2] = [0xA5, 0x5A];

impl<const N: usize, const VALUE_BYTES: usize> LatestReportingTable<N, VALUE_BYTES> {
    /// Persist the current subscriptions to `store`.
    ///
    /// Wire format: `[0xA5, 0x5A, count, …entries…]`
    /// Each entry is 11 bytes; total is `3 + count * 11`.
    #[allow(clippy::result_unit_err)]
    pub fn persist<S: ReportingStore>(&self, store: &mut S, buf: &mut [u8]) -> Result<(), ()> {
        let count = self.entries.len();
        let needed = 3 + count * ENTRY_BYTES;
        if buf.len() < needed {
            return Err(());
        }
        buf[0] = MAGIC[0];
        buf[1] = MAGIC[1];
        buf[2] = u8::try_from(count).unwrap_or(u8::MAX);
        let mut off = 3;
        for entry in &self.entries {
            let id = entry.attr_id.0;
            buf[off] = (id & 0xFF) as u8;
            buf[off + 1] = (id >> 8) as u8;
            buf[off + 2] = entry.type_id.as_u8();
            buf[off + 3] = (entry.min_interval & 0xFF) as u8;
            buf[off + 4] = (entry.min_interval >> 8) as u8;
            buf[off + 5] = (entry.max_interval & 0xFF) as u8;
            buf[off + 6] = (entry.max_interval >> 8) as u8;
            match entry.destination {
                ReportDestination::Unicast(peer) => {
                    buf[off + 7] = 0x00;
                    buf[off + 8] = (peer.short_addr & 0xFF) as u8;
                    buf[off + 9] = (peer.short_addr >> 8) as u8;
                    buf[off + 10] = peer.endpoint;
                }
                ReportDestination::Bound => {
                    buf[off + 7] = 0x01;
                    buf[off + 8] = 0;
                    buf[off + 9] = 0;
                    buf[off + 10] = 0;
                }
            }
            off += ENTRY_BYTES;
        }
        store.save(&buf[..needed])
    }

    /// Restore subscriptions from `store`.
    ///
    /// On first boot (uninitialized storage) `load` returns `Ok(0)` and this
    /// is a no-op. Entries that do not match `attrs` are silently skipped.
    /// `now_ms` is used as the initial `last_reported_ms` so reports wait a
    /// full `min_interval` before firing after restore.
    #[allow(clippy::result_unit_err)]
    pub fn restore<S: ReportingStore>(
        &mut self,
        store: &S,
        buf: &mut [u8],
        now_ms: u32,
        attrs: &[AttrInfo],
    ) -> Result<(), ()> {
        let n = store.load(buf)?;
        if n == 0 {
            return Ok(());
        }
        if n < 3 || buf[0] != MAGIC[0] || buf[1] != MAGIC[1] {
            return Err(());
        }
        let count = buf[2] as usize;
        if n < 3 + count * ENTRY_BYTES {
            return Err(());
        }
        self.entries.clear();
        self.next_token = 0;
        let mut off = 3;
        for i in 0..count {
            let attr_id = AttributeId::new(u16::from_le_bytes([buf[off], buf[off + 1]]));
            let type_id = TypeId::from_u8(buf[off + 2]);
            let min_interval = u16::from_le_bytes([buf[off + 3], buf[off + 4]]);
            let max_interval = u16::from_le_bytes([buf[off + 5], buf[off + 6]]);
            let dst_type = buf[off + 7];
            let dst_short = u16::from_le_bytes([buf[off + 8], buf[off + 9]]);
            let dst_ep = buf[off + 10];
            off += ENTRY_BYTES;

            // Skip entries whose attribute is no longer reportable.
            let valid = attrs
                .iter()
                .any(|a| a.id == attr_id && a.access.is_reportable() && a.type_id == type_id);
            if !valid {
                continue;
            }

            let destination = if dst_type == 0x01 {
                ReportDestination::Bound
            } else {
                ReportDestination::Unicast(crate::cluster_server::ApsPeer {
                    short_addr: dst_short,
                    endpoint: dst_ep,
                })
            };

            let token = ReportToken::new(u16::try_from(i).unwrap_or(u16::MAX));
            let entry = ReportingEntry {
                attr_id,
                type_id,
                min_interval,
                max_interval,
                last_reported_ms: Some(now_ms),
                destination,
                token,
                pending: false,
                reportable_change: [0u8; VALUE_BYTES],
                reportable_change_len: 0,
                last_encoded: [0u8; VALUE_BYTES],
                last_encoded_len: 0,
                pending_encoded: [0u8; VALUE_BYTES],
                pending_encoded_len: 0,
            };
            // Ignore full-table error on restore (best-effort).
            let _ = self.entries.push(entry);
        }
        // Ensure next_token is past all restored tokens so new entries won't collide.
        self.next_token = u16::try_from(count).unwrap_or(u16::MAX);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_server::ApsPeer;
    use crate::cluster_server::ClusterServer;
    use crate::cluster_server::DeliveryMode;
    use crate::cluster_server::DispatchContext;
    use crate::types::descriptors::AccessFlags;
    use crate::types::descriptors::AttrInfo;
    use crate::types::ids::ClusterId;

    static ATTRS: &[AttrInfo] = &[
        AttrInfo {
            id: AttributeId::new(0x0000),
            type_id: TypeId::Int16,
            access: AccessFlags::READ.union(AccessFlags::REPORTABLE),
        },
        AttrInfo {
            id: AttributeId::new(0x0001),
            type_id: TypeId::Uint8,
            access: AccessFlags::READ,
        },
    ];

    fn unicast_ctx() -> DispatchContext {
        DispatchContext {
            delivery: DeliveryMode::Unicast,
            now_ms: 0,
            source: Some(ApsPeer {
                short_addr: 0x1234,
                endpoint: 1,
            }),
        }
    }

    fn broadcast_ctx() -> DispatchContext {
        DispatchContext {
            delivery: DeliveryMode::BroadcastOrMulticast,
            now_ms: 0,
            source: None,
        }
    }

    fn send_record(
        attr_id: u16,
        attr_type: u8,
        min: u16,
        max: u16,
    ) -> ConfigureReportingRecord<'static> {
        ConfigureReportingRecord {
            direction: 0,
            attr_id: AttributeId::new(attr_id),
            attr_type,
            min_interval: min,
            max_interval: max,
            reportable_change: &[],
            timeout_period: 0,
        }
    }

    // --- configure ---

    #[test]
    fn configure_receive_direction_returns_unreportable() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        let record = ConfigureReportingRecord {
            direction: 1,
            attr_id: AttributeId::new(0x0000),
            attr_type: TypeId::Int16.as_u8(),
            min_interval: 0,
            max_interval: 60,
            reportable_change: &[],
            timeout_period: 30,
        };
        assert_eq!(
            table.configure(record, unicast_ctx(), ATTRS),
            Status::UnreportableAttribute
        );
    }

    #[test]
    fn configure_unknown_attr_returns_unreportable() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        let record = send_record(0xFFFF, TypeId::Int16.as_u8(), 0, 60);
        assert_eq!(
            table.configure(record, unicast_ctx(), ATTRS),
            Status::UnreportableAttribute
        );
    }

    #[test]
    fn configure_non_reportable_attr_returns_unreportable() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        // attr 0x0001 has READ but not REPORTABLE
        let record = send_record(0x0001, TypeId::Uint8.as_u8(), 0, 60);
        assert_eq!(
            table.configure(record, unicast_ctx(), ATTRS),
            Status::UnreportableAttribute
        );
    }

    #[test]
    fn configure_type_mismatch_returns_invalid_data_type() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        // attr 0x0000 is Int16 but we say Uint8
        let record = send_record(0x0000, TypeId::Uint8.as_u8(), 0, 60);
        assert_eq!(
            table.configure(record, unicast_ctx(), ATTRS),
            Status::InvalidDataType
        );
    }

    #[test]
    fn configure_broadcast_source_returns_failure() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 0, 60);
        assert_eq!(
            table.configure(record, broadcast_ctx(), ATTRS),
            Status::Failure
        );
    }

    #[test]
    fn configure_max_interval_0xffff_disables() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        // First, add an entry.
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 0, 60);
        assert_eq!(
            table.configure(record, unicast_ctx(), ATTRS),
            Status::Success
        );
        // Then disable it.
        let disable = send_record(0x0000, TypeId::Int16.as_u8(), 0, 0xFFFF);
        assert_eq!(
            table.configure(disable, unicast_ctx(), ATTRS),
            Status::Success
        );
        // Table should be empty.
        assert_eq!(table.next_due(0), None);
    }

    #[test]
    fn configure_success_inserts_entry() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 1, 60);
        assert_eq!(
            table.configure(record, unicast_ctx(), ATTRS),
            Status::Success
        );
    }

    #[test]
    fn configure_full_table_returns_insufficient_space() {
        // Two reportable attrs so we can fill then overflow a capacity-1 table.
        static ATTRS2: &[AttrInfo] = &[
            AttrInfo {
                id: AttributeId::new(0x0000),
                type_id: TypeId::Int16,
                access: AccessFlags::READ.union(AccessFlags::REPORTABLE),
            },
            AttrInfo {
                id: AttributeId::new(0x0001),
                type_id: TypeId::Uint8,
                access: AccessFlags::READ.union(AccessFlags::REPORTABLE),
            },
        ];
        let mut table: LatestReportingTable<1> = LatestReportingTable::new();
        let r1 = send_record(0x0000, TypeId::Int16.as_u8(), 0, 60);
        assert_eq!(table.configure(r1, unicast_ctx(), ATTRS2), Status::Success);
        let r2 = send_record(0x0001, TypeId::Uint8.as_u8(), 0, 60);
        assert_eq!(
            table.configure(r2, unicast_ctx(), ATTRS2),
            Status::InsufficientSpace
        );
    }

    // --- note_value_update ---

    #[test]
    fn note_value_update_returns_unchanged_when_no_entry() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        assert_eq!(
            table.note_value_update(AttributeId::new(0x0000)),
            LatestUpdate::Unchanged
        );
    }

    #[test]
    fn note_value_update_returns_pending_on_first_update() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 0, 60);
        table.configure(record, unicast_ctx(), ATTRS);

        assert_eq!(
            table.note_value_update(AttributeId::new(0x0000)),
            LatestUpdate::Pending
        );
    }

    #[test]
    fn note_value_update_returns_coalesced_when_already_pending() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 0, 60);
        table.configure(record, unicast_ctx(), ATTRS);
        table.note_value_update(AttributeId::new(0x0000));
        // Second update before report → coalesced.
        assert_eq!(
            table.note_value_update(AttributeId::new(0x0000)),
            LatestUpdate::Coalesced
        );
        assert_eq!(table.take_diagnostics().coalesced_updates, 1);
    }

    // --- next_due ---

    #[test]
    fn next_due_change_fires_after_min_interval() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        // min_interval = 10 s
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 10, 60);
        table.configure(record, unicast_ctx(), ATTRS);
        table.note_value_update(AttributeId::new(0x0000));

        // At 9 s (before min_interval) → not yet due.
        assert_eq!(table.next_due(9_000), None);
        // At 10 s → due.
        let cand = table.next_due(10_000).expect("should be due");
        assert_eq!(cand.attr_id, AttributeId::new(0x0000));
        assert_eq!(cand.due, ReportDue::Change);
    }

    #[test]
    fn next_due_max_interval_fires_when_expired() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        // min_interval = 0, max_interval = 30 s; no pending update.
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 0, 30);
        table.configure(record, unicast_ctx(), ATTRS);

        // No pending, but max_interval has passed.
        let cand = table.next_due(30_001).expect("max interval expired");
        assert_eq!(cand.due, ReportDue::MaxInterval);
    }

    #[test]
    fn next_due_none_when_min_interval_not_elapsed() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 30, 300);
        table.configure(record, unicast_ctx(), ATTRS);
        table.note_value_update(AttributeId::new(0x0000));
        assert_eq!(table.next_due(0), None);
    }

    // --- skip ---

    #[test]
    fn skip_below_threshold_clears_pending() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 0, 60);
        table.configure(record, unicast_ctx(), ATTRS);
        table.note_value_update(AttributeId::new(0x0000));

        let cand = table.next_due(0).expect("pending at t=0 with min=0");
        table.skip(cand.token, ReportSkip::BelowThreshold);

        // No longer due.
        assert_eq!(table.next_due(0), None);
    }

    #[test]
    fn skip_buffer_too_small_leaves_pending_and_sets_diagnostic() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 0, 60);
        table.configure(record, unicast_ctx(), ATTRS);
        table.note_value_update(AttributeId::new(0x0000));

        let cand = table.next_due(0).expect("pending");
        table.skip(cand.token, ReportSkip::BufferTooSmall);

        // Still pending.
        assert!(table.next_due(0).is_some());
        assert!(table.take_diagnostics().buffer_too_small);
    }

    // --- complete ---

    #[test]
    fn complete_sent_commits_last_reported_ms_and_clears_pending() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 0, 60);
        table.configure(record, unicast_ctx(), ATTRS);
        table.note_value_update(AttributeId::new(0x0000));

        let cand = table.next_due(1_000).expect("pending");
        table.complete(cand.token, ReportDeliveryResult::Sent, 1_000);

        // No longer due immediately after.
        assert_eq!(table.next_due(1_000), None);
    }

    #[test]
    fn complete_failed_clears_pending_and_increments_dropped() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 0, 60);
        table.configure(record, unicast_ctx(), ATTRS);
        table.note_value_update(AttributeId::new(0x0000));

        let cand = table.next_due(0).expect("pending");
        table.complete(cand.token, ReportDeliveryResult::Failed, 0);

        assert_eq!(table.take_diagnostics().dropped_reports, 1);
        assert_eq!(table.next_due(0), None);
    }

    #[test]
    fn complete_deferred_leaves_pending() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 0, 60);
        table.configure(record, unicast_ctx(), ATTRS);
        table.note_value_update(AttributeId::new(0x0000));

        let cand = table.next_due(0).expect("pending");
        table.complete(cand.token, ReportDeliveryResult::Deferred, 0);

        // Still pending.
        assert!(table.next_due(0).is_some());
    }

    // --- ReportPayloadWriter ---

    struct MockCluster;

    impl ClusterServer for MockCluster {
        const CLUSTER_ID: ClusterId = ClusterId::new(0xFFFF);

        fn read_attribute(
            &self,
            id: AttributeId,
            buf: &mut [u8],
        ) -> Result<(TypeId, usize), AttrError> {
            match id.0 {
                0x0000 => {
                    if buf.len() < 2 {
                        return Err(AttrError::Codec(ZclError::BufferTooSmall));
                    }
                    buf[0] = 0x2A; // low byte of 0x082A = 2090 (20.90°C in 0.01°C units)
                    buf[1] = 0x08;
                    Ok((TypeId::Int16, 2))
                }
                _ => Err(AttrError::UnsupportedAttribute),
            }
        }
    }

    #[test]
    fn write_encoded_appends_record() {
        let mut buf = [0u8; 16];
        let mut writer = ReportPayloadWriter::new(&mut buf);
        writer
            .write_encoded(AttributeId::new(0x0000), TypeId::Int16, &[0x2A, 0x08])
            .unwrap();
        assert_eq!(writer.len(), 5); // 2 (attr_id) + 1 (type) + 2 (value)
        assert_eq!(&buf[..5], &[0x00, 0x00, TypeId::Int16.as_u8(), 0x2A, 0x08]);
    }

    #[test]
    fn write_encoded_atomic_on_overflow() {
        let mut buf = [0u8; 3]; // too small for a full record
        let mut writer = ReportPayloadWriter::new(&mut buf);
        let err = writer.write_encoded(AttributeId::new(0x0000), TypeId::Int16, &[0x2A, 0x08]);
        assert!(err.is_err());
        assert_eq!(writer.len(), 0); // position unchanged
    }

    #[test]
    fn write_from_cluster_appends_record() {
        let mut buf = [0u8; 16];
        let cluster = MockCluster;
        let mut writer = ReportPayloadWriter::new(&mut buf);
        writer
            .write_from_cluster(&cluster, AttributeId::new(0x0000))
            .unwrap();
        assert_eq!(writer.len(), 5);
        assert_eq!(&buf[..5], &[0x00, 0x00, TypeId::Int16.as_u8(), 0x2A, 0x08]);
    }

    #[test]
    fn write_from_cluster_atomic_on_small_buf() {
        let mut buf = [0u8; 2]; // too small for header + value
        let cluster = MockCluster;
        let mut writer = ReportPayloadWriter::new(&mut buf);
        let err = writer.write_from_cluster(&cluster, AttributeId::new(0x0000));
        assert!(err.is_err());
        assert_eq!(writer.len(), 0);
    }

    #[test]
    fn multiple_writes_accumulate() {
        let mut buf = [0u8; 32];
        let cluster = MockCluster;
        let mut writer = ReportPayloadWriter::new(&mut buf);
        writer
            .write_from_cluster(&cluster, AttributeId::new(0x0000))
            .unwrap();
        writer
            .write_encoded(AttributeId::new(0x0001), TypeId::Uint8, &[0x42])
            .unwrap();
        // 5 + 4 = 9 bytes
        assert_eq!(writer.len(), 9);
    }

    // --- persist / restore ---

    struct MemStore {
        data: [u8; 64],
        len: usize,
    }

    impl MemStore {
        fn new() -> Self {
            Self {
                data: [0; 64],
                len: 0,
            }
        }
    }

    impl ReportingStore for MemStore {
        fn load(&self, buf: &mut [u8]) -> Result<usize, ()> {
            let n = self.len.min(buf.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            Ok(n)
        }
        fn save(&mut self, data: &[u8]) -> Result<(), ()> {
            if data.len() > self.data.len() {
                return Err(());
            }
            self.data[..data.len()].copy_from_slice(data);
            self.len = data.len();
            Ok(())
        }
    }

    impl MemStore {
        fn uninitialized() -> Self {
            Self {
                data: [0xFF; 64],
                len: 0,
            }
        }
    }

    #[test]
    fn persist_and_restore_unicast_entry() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 10, 60);
        table.configure(record, unicast_ctx(), ATTRS);

        let mut store = MemStore::new();
        let mut buf = [0u8; 64];
        table.persist(&mut store, &mut buf).unwrap();

        let mut table2: LatestReportingTable<4> = LatestReportingTable::new();
        let mut buf2 = [0u8; 64];
        table2.restore(&store, &mut buf2, 0, ATTRS).unwrap();

        // Entry survives round-trip.
        table2.note_value_update(AttributeId::new(0x0000));
        let cand = table2.next_due(10_000).expect("restored entry should fire");
        assert_eq!(cand.attr_id, AttributeId::new(0x0000));
        match cand.destination {
            ReportDestination::Unicast(peer) => {
                assert_eq!(peer.short_addr, 0x1234);
                assert_eq!(peer.endpoint, 1);
            }
            ReportDestination::Bound => panic!("expected Unicast"),
        }
    }

    #[test]
    fn persist_and_restore_bound_entry() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        table.configure_bound(AttributeId::new(0x0000), TypeId::Int16, 0, 60, 0, ATTRS);

        let mut store = MemStore::new();
        let mut buf = [0u8; 64];
        table.persist(&mut store, &mut buf).unwrap();

        let mut table2: LatestReportingTable<4> = LatestReportingTable::new();
        let mut buf2 = [0u8; 64];
        table2.restore(&store, &mut buf2, 0, ATTRS).unwrap();

        table2.note_value_update(AttributeId::new(0x0000));
        let cand = table2.next_due(0).expect("restored bound entry");
        assert_eq!(cand.destination, ReportDestination::Bound);
    }

    #[test]
    fn restore_uninitialized_store_is_noop() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        let store = MemStore::uninitialized();
        let mut buf = [0u8; 64];
        // load() returns Ok(0) → no-op
        table.restore(&store, &mut buf, 0, ATTRS).unwrap();
        assert_eq!(table.next_due(u32::MAX), None);
    }

    #[test]
    fn restore_skips_stale_non_reportable_attr() {
        // Persist a unicast entry for attr 0x0001 (not reportable in ATTRS).
        // Simulate by directly writing the raw bytes.
        let mut store = MemStore::new();
        // magic + count=1 + entry for attr 0x0001 (READ-only in ATTRS)
        store.data[0] = 0xA5;
        store.data[1] = 0x5A;
        store.data[2] = 1; // one entry
        let attr: u16 = 0x0001;
        store.data[3] = (attr & 0xFF) as u8;
        store.data[4] = (attr >> 8) as u8;
        store.data[5] = TypeId::Uint8.as_u8();
        store.data[6] = 0; // min low
        store.data[7] = 0; // min high
        store.data[8] = 60; // max low
        store.data[9] = 0; // max high
        store.data[10] = 0; // Unicast
        store.data[11] = 0x34; // short addr lo
        store.data[12] = 0x12; // short addr hi
        store.data[13] = 1; // endpoint
        store.len = 14;

        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        let mut buf = [0u8; 64];
        table.restore(&store, &mut buf, 0, ATTRS).unwrap();
        // Non-reportable attr → skipped.
        assert_eq!(table.next_due(u32::MAX), None);
    }

    #[test]
    fn restore_min_interval_honoured_after_restore() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 30, 300);
        table.configure(record, unicast_ctx(), ATTRS);

        let mut store = MemStore::new();
        let mut buf = [0u8; 64];
        table.persist(&mut store, &mut buf).unwrap();

        // Restore at t=5_000. min_interval=30s → not due until t=35_000.
        let mut table2: LatestReportingTable<4> = LatestReportingTable::new();
        let mut buf2 = [0u8; 64];
        table2.restore(&store, &mut buf2, 5_000, ATTRS).unwrap();
        table2.note_value_update(AttributeId::new(0x0000));

        assert_eq!(table2.next_due(5_000), None);
        assert!(table2.next_due(35_000).is_some());
    }

    // --- reportable-change threshold ---

    #[test]
    fn collect_reports_suppressed_when_value_unchanged() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 0, 60);
        table.configure(record, unicast_ctx(), ATTRS);
        table.note_value_update(AttributeId::new(0x0000));

        // Simulate collect_reports: read value, check threshold, record.
        let cand = table.next_due(0).expect("pending");
        let value = &[0x10u8, 0x00]; // some value
        assert!(!table.is_below_threshold(cand.token, TypeId::Int16, value)); // first report → not suppressed
        table.record_value(cand.token, value);
        table.complete(cand.token, ReportDeliveryResult::Sent, 1_000);

        // Same value reported again.
        table.note_value_update(AttributeId::new(0x0000));
        let cand2 = table.next_due(1_000).expect("pending again");
        // Same encoded bytes → suppressed.
        assert!(table.is_below_threshold(cand2.token, TypeId::Int16, value));
    }

    #[test]
    fn deferred_report_does_not_commit_threshold_baseline() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 0, 60);
        table.configure(record, unicast_ctx(), ATTRS);
        table.note_value_update(AttributeId::new(0x0000));

        let cand = table.next_due(0).expect("pending");
        let value = &[0x10u8, 0x00];
        table.record_value(cand.token, value);
        table.complete(cand.token, ReportDeliveryResult::Deferred, 1_000);

        let retry = table.next_due(1_000).expect("still pending after deferral");
        assert!(!table.is_below_threshold(retry.token, TypeId::Int16, value));
    }

    #[test]
    fn collect_reports_not_suppressed_when_value_changes() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 0, 60);
        table.configure(record, unicast_ctx(), ATTRS);
        table.note_value_update(AttributeId::new(0x0000));

        let cand = table.next_due(0).expect("pending");
        let value_a = &[0x10u8, 0x00];
        table.record_value(cand.token, value_a);
        table.complete(cand.token, ReportDeliveryResult::Sent, 1_000);

        table.note_value_update(AttributeId::new(0x0000));
        let cand2 = table.next_due(1_000).expect("pending");
        let value_b = &[0x20u8, 0x00]; // different value
        assert!(!table.is_below_threshold(cand2.token, TypeId::Int16, value_b));
    }

    #[test]
    fn int16_threshold_suppresses_small_delta() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        // threshold = 50 (0x32, 0x00 in LE)
        let record = ConfigureReportingRecord {
            direction: 0,
            attr_id: AttributeId::new(0x0000),
            attr_type: TypeId::Int16.as_u8(),
            min_interval: 0,
            max_interval: 60,
            reportable_change: &[0x32, 0x00],
            timeout_period: 0,
        };
        table.configure(record, unicast_ctx(), ATTRS);
        table.note_value_update(AttributeId::new(0x0000));

        let cand = table.next_due(0).expect("pending");
        let base = &[0xE8u8, 0x03]; // 1000 in LE
        table.record_value(cand.token, base);
        table.complete(cand.token, ReportDeliveryResult::Sent, 1_000);

        table.note_value_update(AttributeId::new(0x0000));
        let cand2 = table.next_due(1_000).expect("pending");

        // Delta = 30, threshold = 50 → suppressed.
        let close = &[0x0Eu8, 0x04]; // 1000 + 30 = 1030 in LE
        assert!(table.is_below_threshold(cand2.token, TypeId::Int16, close));

        // Delta = 60, threshold = 50 → not suppressed.
        let far = &[0x26u8, 0x04]; // 1000 + 60 = 1060 in LE: [0x44, 0x04]
        assert!(!table.is_below_threshold(cand2.token, TypeId::Int16, far));
    }

    #[test]
    fn max_interval_report_not_suppressed_by_threshold() {
        // max_interval reports always fire regardless of threshold — callers
        // are responsible for not calling is_below_threshold for MaxInterval.
        // This test verifies next_due returns MaxInterval when elapsed.
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        let record = send_record(0x0000, TypeId::Int16.as_u8(), 0, 30);
        table.configure(record, unicast_ctx(), ATTRS);

        // Record a value (no change pending).
        let token = table.next_due(30_001).expect("max interval").token;
        let value = &[0x10u8, 0x00];
        table.record_value(token, value);
        table.complete(token, ReportDeliveryResult::Sent, 30_001);

        // Max interval expires again; same value but it's a MaxInterval report.
        let cand = table.next_due(60_002).expect("max interval second fire");
        assert_eq!(cand.due, ReportDue::MaxInterval);
    }

    // --- token stability after removal ---

    #[test]
    fn token_remains_valid_after_earlier_entry_removed() {
        static ATTRS2: &[AttrInfo] = &[
            AttrInfo {
                id: AttributeId::new(0x0000),
                type_id: TypeId::Int16,
                access: AccessFlags::READ.union(AccessFlags::REPORTABLE),
            },
            AttrInfo {
                id: AttributeId::new(0x0001),
                type_id: TypeId::Int16,
                access: AccessFlags::READ.union(AccessFlags::REPORTABLE),
            },
        ];
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();

        // Add two entries.
        let r0 = send_record(0x0000, TypeId::Int16.as_u8(), 0, 60);
        table.configure(r0, unicast_ctx(), ATTRS2);
        let r1 = send_record(0x0001, TypeId::Int16.as_u8(), 0, 60);
        table.configure(r1, unicast_ctx(), ATTRS2);

        // Trigger update on attr 0x0001, collect its token before removal.
        table.note_value_update(AttributeId::new(0x0001));
        let cand = table.next_due(0).expect("attr 0x0001 pending");
        let token_1 = cand.token;
        assert_eq!(cand.attr_id, AttributeId::new(0x0001));

        // Remove attr 0x0000 — shifts attr 0x0001 to index 0 internally.
        let disable = send_record(0x0000, TypeId::Int16.as_u8(), 0, 0xFFFF);
        table.configure(disable, unicast_ctx(), ATTRS2);

        // Token for attr 0x0001 must still resolve correctly.
        table.complete(token_1, ReportDeliveryResult::Sent, 1_000);
        assert_eq!(table.next_due(1_000), None);
    }

    // --- configure_bound ---

    #[test]
    fn configure_bound_unknown_attr_returns_unreportable() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        assert_eq!(
            table.configure_bound(AttributeId::new(0xFFFF), TypeId::Int16, 0, 60, 0, ATTRS),
            Status::UnreportableAttribute
        );
    }

    #[test]
    fn configure_bound_non_reportable_attr_returns_unreportable() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        // attr 0x0001 is READ-only, not REPORTABLE
        assert_eq!(
            table.configure_bound(AttributeId::new(0x0001), TypeId::Uint8, 0, 60, 0, ATTRS),
            Status::UnreportableAttribute
        );
    }

    #[test]
    fn configure_bound_type_mismatch_returns_invalid_data_type() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        assert_eq!(
            table.configure_bound(AttributeId::new(0x0000), TypeId::Uint8, 0, 60, 0, ATTRS),
            Status::InvalidDataType
        );
    }

    #[test]
    fn configure_bound_max_0xffff_removes_entry() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        table.configure_bound(AttributeId::new(0x0000), TypeId::Int16, 0, 60, 0, ATTRS);
        table.configure_bound(AttributeId::new(0x0000), TypeId::Int16, 0, 0xFFFF, 0, ATTRS);
        assert_eq!(table.next_due(u32::MAX), None);
    }

    #[test]
    fn configure_bound_stores_bound_destination() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        assert_eq!(
            table.configure_bound(AttributeId::new(0x0000), TypeId::Int16, 0, 60, 0, ATTRS),
            Status::Success
        );
        table.note_value_update(AttributeId::new(0x0000));
        let cand = table.next_due(0).expect("pending");
        assert_eq!(cand.destination, ReportDestination::Bound);
    }

    #[test]
    fn configure_bound_due_after_min_interval() {
        let mut table: LatestReportingTable<4> = LatestReportingTable::new();
        table.configure_bound(AttributeId::new(0x0000), TypeId::Int16, 10, 60, 0, ATTRS);
        table.note_value_update(AttributeId::new(0x0000));

        assert_eq!(table.next_due(9_000), None);
        let cand = table.next_due(10_000);
        assert!(cand.is_some());
        assert_eq!(cand.unwrap().destination, ReportDestination::Bound);
    }
}
