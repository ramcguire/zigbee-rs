//! Integration tests for `#[derive(ZigbeeDevice)]`.
//!
//! Verifies that the macro generates correct `Device::endpoints()` and
//! `Device::visit_servers()` implementations equivalent to the manual impl.
#![allow(dead_code)]

use zigbee_cluster_library::ZigbeeDevice;
use zigbee_cluster_library::cluster_server::ClusterServer;
use zigbee_cluster_library::cluster_server::Device;
use zigbee_cluster_library::cluster_server::DeviceServerVisitor;
use zigbee_cluster_library::cluster_server::DispatchContext;
use zigbee_cluster_library::cluster_server::ServerMeta;
use zigbee_cluster_library::common::BasicConfig;
use zigbee_cluster_library::common::BasicServer;
use zigbee_cluster_library::common::IdentifyServer;
use zigbee_cluster_library::measurement::temperature::TemperatureMeasurementServer;

// ── Derived device ───────────────────────────────────────────────────────────

#[derive(ZigbeeDevice)]
pub struct SensorDevice {
    #[zcl(endpoint = 1, profile = 0x0104, device = 0x0302, version = 0)]
    #[zcl(server)]
    pub basic: BasicServer,

    #[zcl(endpoint = 1)]
    #[zcl(server)]
    pub identify: IdentifyServer,

    #[zcl(endpoint = 1)]
    #[zcl(server)]
    pub temperature: TemperatureMeasurementServer,
}

impl SensorDevice {
    fn new() -> Self {
        Self {
            basic: BasicServer::new(BasicConfig::new(3, "Acme", "Sensor-1", 0x03, true)),
            identify: IdentifyServer::new(),
            temperature: TemperatureMeasurementServer::new(),
        }
    }
}

struct ManualSensorDevice {
    basic: BasicServer,
    identify: IdentifyServer,
    temperature: TemperatureMeasurementServer,
}

static MANUAL_SENSOR_INPUT_CLUSTERS: [zigbee_cluster_library::types::ids::ClusterId; 3] = [
    BasicServer::CLUSTER_ID,
    IdentifyServer::CLUSTER_ID,
    TemperatureMeasurementServer::CLUSTER_ID,
];

static MANUAL_SENSOR_ENDPOINTS: [zigbee_cluster_library::cluster_server::EndpointDescriptor; 1] =
    [zigbee_cluster_library::cluster_server::EndpointDescriptor {
        endpoint: 1,
        profile_id: 0x0104,
        device_id: 0x0302,
        device_version: 0,
        input_clusters: &MANUAL_SENSOR_INPUT_CLUSTERS,
        output_clusters: &[],
    }];

impl ManualSensorDevice {
    fn new() -> Self {
        Self {
            basic: BasicServer::new(BasicConfig::new(3, "Acme", "Sensor-1", 0x03, true)),
            identify: IdentifyServer::new(),
            temperature: TemperatureMeasurementServer::new(),
        }
    }
}

impl Device for ManualSensorDevice {
    fn endpoints(&self) -> &'static [zigbee_cluster_library::cluster_server::EndpointDescriptor] {
        &MANUAL_SENSOR_ENDPOINTS
    }

    fn visit_servers<V: DeviceServerVisitor>(&mut self, visitor: &mut V) {
        visitor.visit(
            ServerMeta {
                endpoint: 1,
                profile_id: 0x0104,
                cluster: zigbee_cluster_library::types::descriptors::ClusterKey::new(
                    BasicServer::CLUSTER_ID,
                    None,
                ),
            },
            &mut self.basic,
        );
        visitor.visit(
            ServerMeta {
                endpoint: 1,
                profile_id: 0x0104,
                cluster: zigbee_cluster_library::types::descriptors::ClusterKey::new(
                    IdentifyServer::CLUSTER_ID,
                    None,
                ),
            },
            &mut self.identify,
        );
        visitor.visit(
            ServerMeta {
                endpoint: 1,
                profile_id: 0x0104,
                cluster: zigbee_cluster_library::types::descriptors::ClusterKey::new(
                    TemperatureMeasurementServer::CLUSTER_ID,
                    None,
                ),
            },
            &mut self.temperature,
        );
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn endpoints_returns_single_endpoint_with_correct_metadata() {
    let device = SensorDevice::new();
    let eps = device.endpoints();

    assert_eq!(eps.len(), 1, "expected exactly one endpoint");
    let ep = &eps[0];
    assert_eq!(ep.endpoint, 1);
    assert_eq!(ep.profile_id, 0x0104);
    assert_eq!(ep.device_id, 0x0302);
    assert_eq!(ep.device_version, 0);
}

#[test]
fn endpoint_input_clusters_contains_all_three_server_cluster_ids() {
    let device = SensorDevice::new();
    let ep = &device.endpoints()[0];
    let ids = ep.input_clusters;

    assert_eq!(ids.len(), 3);
    assert!(
        ids.contains(&BasicServer::CLUSTER_ID),
        "missing Basic cluster 0x0000"
    );
    assert!(
        ids.contains(&IdentifyServer::CLUSTER_ID),
        "missing Identify cluster 0x0003"
    );
    assert!(
        ids.contains(&TemperatureMeasurementServer::CLUSTER_ID),
        "missing Temperature Measurement cluster 0x0402"
    );
}

#[test]
fn endpoint_output_clusters_is_empty() {
    let device = SensorDevice::new();
    let ep = &device.endpoints()[0];
    assert_eq!(ep.output_clusters.len(), 0);
}

#[test]
fn simple_descriptor_lookup_matches_endpoint_1() {
    let device = SensorDevice::new();
    let desc = device.simple_descriptor(1);
    assert!(desc.is_some());
    assert_eq!(desc.unwrap().endpoint, 1);
}

#[test]
fn simple_descriptor_unknown_endpoint_returns_none() {
    let device = SensorDevice::new();
    assert!(device.simple_descriptor(2).is_none());
    assert!(device.simple_descriptor(0).is_none());
}

#[test]
fn visit_servers_reaches_all_three_clusters_in_source_order() {
    struct CountVisitor {
        visited: Vec<u16>,
    }
    impl DeviceServerVisitor for CountVisitor {
        fn visit<C: ClusterServer>(&mut self, _meta: ServerMeta, _server: &mut C) {
            self.visited.push(C::CLUSTER_ID.0);
        }
    }

    let mut device = SensorDevice::new();
    let mut v = CountVisitor {
        visited: Vec::new(),
    };
    device.visit_servers(&mut v);

    assert_eq!(v.visited.len(), 3);
    // Source order: basic → identify → temperature
    assert_eq!(v.visited[0], BasicServer::CLUSTER_ID.0);
    assert_eq!(v.visited[1], IdentifyServer::CLUSTER_ID.0);
    assert_eq!(v.visited[2], TemperatureMeasurementServer::CLUSTER_ID.0);
}

#[test]
fn derived_device_matches_manual_descriptor_and_route_projection() {
    fn routes<D: Device>(device: &mut D) -> Vec<(u8, u16, u16, Option<u16>)> {
        struct Routes {
            out: Vec<(u8, u16, u16, Option<u16>)>,
        }
        impl DeviceServerVisitor for Routes {
            fn visit<C: ClusterServer>(&mut self, meta: ServerMeta, _server: &mut C) {
                self.out.push((
                    meta.endpoint,
                    meta.profile_id,
                    meta.cluster.id.0,
                    meta.cluster.manufacturer.map(|code| code.0),
                ));
            }
        }

        let mut visitor = Routes { out: Vec::new() };
        device.visit_servers(&mut visitor);
        visitor.out
    }

    let mut derived = SensorDevice::new();
    let mut manual = ManualSensorDevice::new();

    assert_eq!(derived.endpoints().len(), manual.endpoints().len());
    for (derived_ep, manual_ep) in derived.endpoints().iter().zip(manual.endpoints()) {
        assert_eq!(derived_ep.endpoint, manual_ep.endpoint);
        assert_eq!(derived_ep.profile_id, manual_ep.profile_id);
        assert_eq!(derived_ep.device_id, manual_ep.device_id);
        assert_eq!(derived_ep.device_version, manual_ep.device_version);
        assert_eq!(derived_ep.input_clusters, manual_ep.input_clusters);
        assert_eq!(derived_ep.output_clusters, manual_ep.output_clusters);
    }

    assert_eq!(routes(&mut derived), routes(&mut manual));
}

#[test]
fn tick_reaches_identify_server() {
    let mut device = SensorDevice::new();
    // Tick should not panic; identify is inactive so changed = false.
    let tick = device.tick(0);
    assert!(!tick.changed);
    assert!(tick.next_tick_ms.is_none());
}

// ── Client cluster advertisement ─────────────────────────────────────────────

#[derive(ZigbeeDevice)]
pub struct BridgeDevice {
    #[zcl(endpoint = 2, profile = 0x0104, device = 0x0051, version = 0)]
    #[zcl(server)]
    #[zcl(client_cluster = 0x0019)] // OTA Upgrade cluster advertised as output
    pub basic: BasicServer,
}

impl BridgeDevice {
    fn new() -> Self {
        Self {
            basic: BasicServer::new(BasicConfig::new(3, "Acme", "Bridge-1", 0x01, true)),
        }
    }
}

#[test]
fn client_cluster_appears_in_output_list() {
    let device = BridgeDevice::new();
    let ep = &device.endpoints()[0];
    assert_eq!(ep.endpoint, 2);
    assert_eq!(ep.input_clusters.len(), 1);
    assert_eq!(ep.output_clusters.len(), 1);
    assert_eq!(ep.output_clusters[0].0, 0x0019);
}

// ── Default server route ─────────────────────────────────────────────────────

#[derive(ZigbeeDevice)]
pub struct DefaultServerDevice {
    #[zcl(endpoint = 4, profile = 0x0104, device = 0x0302, version = 0)]
    pub basic: BasicServer,
}

impl DefaultServerDevice {
    fn new() -> Self {
        Self {
            basic: BasicServer::new(BasicConfig::new(3, "Acme", "Default-Server", 0x01, true)),
        }
    }
}

#[test]
fn endpoint_attribute_defaults_to_server_route() {
    let mut device = DefaultServerDevice::new();
    let ep = &device.endpoints()[0];

    assert_eq!(ep.endpoint, 4);
    assert_eq!(ep.input_clusters, &[BasicServer::CLUSTER_ID]);

    struct CountVisitor(usize);
    impl DeviceServerVisitor for CountVisitor {
        fn visit<C: ClusterServer>(&mut self, _meta: ServerMeta, _server: &mut C) {
            self.0 += 1;
        }
    }

    let mut visitor = CountVisitor(0);
    device.visit_servers(&mut visitor);
    assert_eq!(visitor.0, 1);
}

// ── Manufacturer-specific cluster ────────────────────────────────────────────

pub struct VendorCluster;

impl ClusterServer for VendorCluster {
    const CLUSTER_ID: zigbee_cluster_library::types::ids::ClusterId =
        zigbee_cluster_library::types::ids::ClusterId::new(0xfc00);
    const MANUFACTURER_CODE: Option<zigbee_cluster_library::types::ids::ManufacturerCode> = Some(
        zigbee_cluster_library::types::ids::ManufacturerCode::new(0x1234),
    );

    fn read_attribute(
        &self,
        _id: zigbee_cluster_library::types::ids::AttributeId,
        _buf: &mut [u8],
    ) -> Result<
        (zigbee_cluster_library::types::ids::TypeId, usize),
        zigbee_cluster_library::types::error::AttrError,
    > {
        Err(zigbee_cluster_library::types::error::AttrError::UnsupportedAttribute)
    }
}

#[derive(ZigbeeDevice)]
pub struct VendorDevice {
    #[zcl(endpoint = 1, profile = 0x0104, device = 0xffff, version = 0)]
    #[zcl(server)]
    pub vendor: VendorCluster,
}

impl VendorDevice {
    fn new() -> Self {
        Self {
            vendor: VendorCluster,
        }
    }
}

#[test]
fn manufacturer_specific_cluster_appears_in_input_list() {
    let device = VendorDevice::new();
    let ep = &device.endpoints()[0];
    assert_eq!(ep.input_clusters.len(), 1);
    assert_eq!(ep.input_clusters[0].0, 0xfc00);
}

#[test]
fn manufacturer_specific_dispatch_routes_correctly() {
    use zigbee_cluster_library::cluster_server::ClusterRequest;
    use zigbee_cluster_library::cluster_server::DispatchError;
    use zigbee_cluster_library::frame::IncomingZclFrame;
    use zigbee_cluster_library::types::descriptors::ClusterKey;
    use zigbee_cluster_library::types::ids::ManufacturerCode;

    let mut device = VendorDevice::new();

    // Simulate a ReadAttributes frame (global, empty attr list,
    // manufacturer-specific header)
    let frame_bytes: &[u8] = &[
        0x04, // global | manufacturer-specific | client→server
        0x34, 0x12, // manufacturer code 0x1234 LE
        0x01, // sequence
        0x00, /* ReadAttributes command
               * no attribute ids → empty response */
    ];
    let (frame, _) = IncomingZclFrame::decode(frame_bytes).unwrap();

    let request = ClusterRequest {
        endpoint: 1,
        cluster: ClusterKey::new(
            VendorCluster::CLUSTER_ID,
            Some(ManufacturerCode::new(0x1234)),
        ),
        ctx: DispatchContext::unicast(0, None),
        frame: &frame,
    };

    let mut buf = [0u8; 64];
    let result = device.dispatch_cluster(request, &mut buf);
    assert!(
        result.is_ok(),
        "dispatch to manufacturer-specific cluster failed"
    );

    // Dispatch to standard key (no manufacturer) should return UnsupportedCluster
    let std_request = ClusterRequest {
        endpoint: 1,
        cluster: ClusterKey::new(VendorCluster::CLUSTER_ID, None),
        ctx: DispatchContext::unicast(0, None),
        frame: &frame,
    };
    let result2 = device.dispatch_cluster(std_request, &mut buf);
    assert!(
        matches!(result2, Err(DispatchError::UnsupportedCluster)),
        "expected UnsupportedCluster for standard key on manufacturer-specific cluster"
    );
}

pub struct StandardFc00Cluster;

impl ClusterServer for StandardFc00Cluster {
    const CLUSTER_ID: zigbee_cluster_library::types::ids::ClusterId =
        zigbee_cluster_library::types::ids::ClusterId::new(0xfc00);

    fn read_attribute(
        &self,
        _id: zigbee_cluster_library::types::ids::AttributeId,
        _buf: &mut [u8],
    ) -> Result<
        (zigbee_cluster_library::types::ids::TypeId, usize),
        zigbee_cluster_library::types::error::AttrError,
    > {
        Err(zigbee_cluster_library::types::error::AttrError::UnsupportedAttribute)
    }
}

#[derive(ZigbeeDevice)]
pub struct SharedAdvertisedClusterIdDevice {
    #[zcl(endpoint = 5, profile = 0x0104, device = 0xffff, version = 0)]
    pub standard: StandardFc00Cluster,

    #[zcl(endpoint = 5)]
    pub vendor: VendorCluster,
}

#[test]
fn same_numeric_cluster_id_is_advertised_once_but_routes_by_manufacturer() {
    let mut device = SharedAdvertisedClusterIdDevice {
        standard: StandardFc00Cluster,
        vendor: VendorCluster,
    };

    let ep = &device.endpoints()[0];
    assert_eq!(ep.endpoint, 5);
    assert_eq!(ep.input_clusters.len(), 1);
    assert_eq!(ep.input_clusters[0].0, 0xfc00);

    struct RouteVisitor {
        routes: Vec<(u8, u16, Option<u16>)>,
    }
    impl DeviceServerVisitor for RouteVisitor {
        fn visit<C: ClusterServer>(&mut self, meta: ServerMeta, _server: &mut C) {
            self.routes.push((
                meta.endpoint,
                meta.cluster.id.0,
                meta.cluster.manufacturer.map(|code| code.0),
            ));
        }
    }

    let mut visitor = RouteVisitor { routes: Vec::new() };
    device.visit_servers(&mut visitor);

    assert_eq!(
        visitor.routes,
        vec![(5, 0xfc00, None), (5, 0xfc00, Some(0x1234))]
    );
}

// ── Report priority through generated visit_servers ──────────────────────────

struct ReportClusterA {
    pending: bool,
}

struct ReportClusterB {
    pending: bool,
}

impl ClusterServer for ReportClusterA {
    const CLUSTER_ID: zigbee_cluster_library::types::ids::ClusterId =
        zigbee_cluster_library::types::ids::ClusterId::new(0xfc10);

    fn read_attribute(
        &self,
        _id: zigbee_cluster_library::types::ids::AttributeId,
        _buf: &mut [u8],
    ) -> Result<
        (zigbee_cluster_library::types::ids::TypeId, usize),
        zigbee_cluster_library::types::error::AttrError,
    > {
        Err(zigbee_cluster_library::types::error::AttrError::UnsupportedAttribute)
    }

    fn collect_reports(
        &mut self,
        _now_ms: u32,
        out: &mut zigbee_cluster_library::reporting::ReportPayloadWriter<'_>,
    ) -> Result<
        Option<zigbee_cluster_library::cluster_server::ClusterReportReady>,
        zigbee_cluster_library::types::error::ZclError,
    > {
        if !self.pending {
            return Ok(None);
        }
        out.write_encoded(
            zigbee_cluster_library::types::ids::AttributeId::new(1),
            zigbee_cluster_library::types::ids::TypeId::Uint8,
            &[0xa1],
        )?;
        Ok(Some(
            zigbee_cluster_library::cluster_server::ClusterReportReady {
                destination: zigbee_cluster_library::cluster_server::ReportDestination::Bound,
                token: zigbee_cluster_library::cluster_server::ReportToken::new(0xa),
            },
        ))
    }
}

impl ClusterServer for ReportClusterB {
    const CLUSTER_ID: zigbee_cluster_library::types::ids::ClusterId =
        zigbee_cluster_library::types::ids::ClusterId::new(0xfc11);

    fn read_attribute(
        &self,
        _id: zigbee_cluster_library::types::ids::AttributeId,
        _buf: &mut [u8],
    ) -> Result<
        (zigbee_cluster_library::types::ids::TypeId, usize),
        zigbee_cluster_library::types::error::AttrError,
    > {
        Err(zigbee_cluster_library::types::error::AttrError::UnsupportedAttribute)
    }

    fn collect_reports(
        &mut self,
        _now_ms: u32,
        out: &mut zigbee_cluster_library::reporting::ReportPayloadWriter<'_>,
    ) -> Result<
        Option<zigbee_cluster_library::cluster_server::ClusterReportReady>,
        zigbee_cluster_library::types::error::ZclError,
    > {
        if !self.pending {
            return Ok(None);
        }
        out.write_encoded(
            zigbee_cluster_library::types::ids::AttributeId::new(2),
            zigbee_cluster_library::types::ids::TypeId::Uint8,
            &[0xb1],
        )?;
        Ok(Some(
            zigbee_cluster_library::cluster_server::ClusterReportReady {
                destination: zigbee_cluster_library::cluster_server::ReportDestination::Bound,
                token: zigbee_cluster_library::cluster_server::ReportToken::new(0xb),
            },
        ))
    }
}

#[derive(ZigbeeDevice)]
struct ReportPriorityDevice {
    #[zcl(endpoint = 6, profile = 0x0104, device = 0xffff, version = 0)]
    first: ReportClusterA,

    #[zcl(endpoint = 6)]
    second: ReportClusterB,
}

#[test]
fn next_report_uses_source_order_priority_from_derived_visit_servers() {
    let mut device = ReportPriorityDevice {
        first: ReportClusterA { pending: true },
        second: ReportClusterB { pending: true },
    };
    let mut buf = [0u8; 16];

    let ready = device.next_report(100, &mut buf).unwrap().unwrap();

    assert_eq!(ready.endpoint, 6);
    assert_eq!(ready.profile_id, 0x0104);
    assert_eq!(ready.cluster.id.0, 0xfc10);
    assert_eq!(
        ready.token,
        zigbee_cluster_library::cluster_server::ReportToken::new(0xa)
    );
    assert_eq!(ready.len, 4);
    assert_eq!(buf[..ready.len], [1, 0, 0x20, 0xa1]);
}

// ── Multi-endpoint device ────────────────────────────────────────────────────

#[derive(ZigbeeDevice)]
pub struct TwoEndpointDevice {
    // ep 1 declared first; ep 3 declared second — tests that endpoints() sorts ascending
    #[zcl(endpoint = 1, profile = 0x0104, device = 0x0302, version = 1)]
    #[zcl(server)]
    pub basic: BasicServer,

    #[zcl(endpoint = 3, profile = 0x0104, device = 0x0302, version = 0)]
    #[zcl(server)]
    pub temperature: TemperatureMeasurementServer,
}

impl TwoEndpointDevice {
    fn new() -> Self {
        Self {
            basic: BasicServer::new(BasicConfig::new(3, "Acme", "GW", 0x01, true)),
            temperature: TemperatureMeasurementServer::new(),
        }
    }
}

#[test]
fn two_endpoint_device_endpoints_sorted_ascending() {
    let device = TwoEndpointDevice::new();
    let eps = device.endpoints();

    assert_eq!(eps.len(), 2);
    assert_eq!(eps[0].endpoint, 1);
    assert_eq!(eps[0].device_version, 1);
    assert_eq!(eps[1].endpoint, 3);
    assert_eq!(eps[1].device_version, 0);
}

#[test]
fn two_endpoint_device_simple_descriptor_per_endpoint() {
    let device = TwoEndpointDevice::new();
    assert!(device.simple_descriptor(1).is_some());
    assert!(device.simple_descriptor(3).is_some());
    assert!(device.simple_descriptor(2).is_none());
}

#[test]
fn two_endpoint_device_input_clusters_segregated() {
    let device = TwoEndpointDevice::new();
    let ep1 = device.simple_descriptor(1).unwrap();
    let ep3 = device.simple_descriptor(3).unwrap();

    assert!(ep1.input_clusters.contains(&BasicServer::CLUSTER_ID));
    assert!(
        !ep1.input_clusters
            .contains(&TemperatureMeasurementServer::CLUSTER_ID)
    );

    assert!(
        ep3.input_clusters
            .contains(&TemperatureMeasurementServer::CLUSTER_ID)
    );
    assert!(!ep3.input_clusters.contains(&BasicServer::CLUSTER_ID));
}

#[test]
fn two_endpoint_device_visit_servers_field_order() {
    struct EpTracker {
        endpoints_visited: Vec<u8>,
    }
    impl DeviceServerVisitor for EpTracker {
        fn visit<C: ClusterServer>(&mut self, meta: ServerMeta, _server: &mut C) {
            self.endpoints_visited.push(meta.endpoint);
        }
    }

    let mut device = TwoEndpointDevice::new();
    let mut v = EpTracker {
        endpoints_visited: Vec::new(),
    };
    device.visit_servers(&mut v);

    // Source field order: basic (ep 1) then temperature (ep 3)
    assert_eq!(v.endpoints_visited, vec![1, 3]);
}

#[test]
fn two_endpoint_device_dispatch_routes_to_correct_endpoint() {
    use zigbee_cluster_library::cluster_server::ClusterRequest;
    use zigbee_cluster_library::cluster_server::DispatchError;
    use zigbee_cluster_library::frame::IncomingZclFrame;
    use zigbee_cluster_library::types::descriptors::ClusterKey;

    let mut device = TwoEndpointDevice::new();
    // ReadAttributes with no attr ids — always a valid, harmless request
    let frame_bytes: &[u8] = &[0x00, 0x01, 0x00];
    let (frame, _) = IncomingZclFrame::decode(frame_bytes).unwrap();
    let mut buf = [0u8; 64];

    // Basic cluster is on ep 1 — should succeed
    let ok = device.dispatch_cluster(
        ClusterRequest {
            endpoint: 1,
            cluster: ClusterKey::new(BasicServer::CLUSTER_ID, None),
            ctx: DispatchContext::unicast(0, None),
            frame: &frame,
        },
        &mut buf,
    );
    assert!(ok.is_ok(), "dispatch to ep1/Basic failed");

    // Basic cluster on ep 3 does not exist — UnsupportedCluster
    let err = device.dispatch_cluster(
        ClusterRequest {
            endpoint: 3,
            cluster: ClusterKey::new(BasicServer::CLUSTER_ID, None),
            ctx: DispatchContext::unicast(0, None),
            frame: &frame,
        },
        &mut buf,
    );
    assert!(
        matches!(err, Err(DispatchError::UnsupportedCluster)),
        "expected UnsupportedCluster for Basic on ep3"
    );

    // Unknown endpoint — UnsupportedEndpoint
    let err2 = device.dispatch_cluster(
        ClusterRequest {
            endpoint: 2,
            cluster: ClusterKey::new(BasicServer::CLUSTER_ID, None),
            ctx: DispatchContext::unicast(0, None),
            frame: &frame,
        },
        &mut buf,
    );
    assert!(
        matches!(err2, Err(DispatchError::UnsupportedEndpoint)),
        "expected UnsupportedEndpoint for ep2"
    );
}

// ── Empty device (no zcl fields) ─────────────────────────────────────────────

#[derive(ZigbeeDevice)]
pub struct EmptyDevice {}

#[test]
fn empty_device_has_no_endpoints() {
    let device = EmptyDevice {};
    assert_eq!(device.endpoints().len(), 0);
    assert!(device.simple_descriptor(1).is_none());
}

#[test]
fn empty_device_visit_servers_is_noop() {
    struct CountVisitor(usize);
    impl DeviceServerVisitor for CountVisitor {
        fn visit<C: ClusterServer>(&mut self, _meta: ServerMeta, _server: &mut C) {
            self.0 += 1;
        }
    }

    let mut device = EmptyDevice {};
    let mut v = CountVisitor(0);
    device.visit_servers(&mut v);
    assert_eq!(v.0, 0);
}
