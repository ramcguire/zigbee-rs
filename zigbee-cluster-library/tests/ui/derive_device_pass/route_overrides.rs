use zigbee_cluster_library::cluster_server::{ClusterServer, Device, DeviceServerVisitor, ServerMeta};
use zigbee_cluster_library::types::error::AttrError;
use zigbee_cluster_library::types::ids::{AttributeId, ClusterId, ManufacturerCode, TypeId};
use zigbee_cluster_library::ZigbeeDevice;

struct ClusterA;
struct ClusterB;

impl ClusterServer for ClusterA {
    const CLUSTER_ID: ClusterId = ClusterId::new(0x0001);

    fn read_attribute(&self, _id: AttributeId, _buf: &mut [u8]) -> Result<(TypeId, usize), AttrError> {
        Err(AttrError::UnsupportedAttribute)
    }
}

impl ClusterServer for ClusterB {
    const CLUSTER_ID: ClusterId = ClusterId::new(0x0002);
    const MANUFACTURER_CODE: Option<ManufacturerCode> = Some(ManufacturerCode::new(0x1111));

    fn read_attribute(&self, _id: AttributeId, _buf: &mut [u8]) -> Result<(TypeId, usize), AttrError> {
        Err(AttrError::UnsupportedAttribute)
    }
}

#[derive(ZigbeeDevice)]
struct DeviceWithOverrides {
    #[zcl(endpoint = 1, profile = 0x0104, device = 0x0302, cluster = 0xfc00, manufacturer = 0x1234)]
    a: ClusterA,

    #[zcl(endpoint = 1, cluster = 0xfc00, manufacturer = 0x5678)]
    b: ClusterB,
}

fn main() {
    let mut device = DeviceWithOverrides { a: ClusterA, b: ClusterB };
    assert_eq!(device.endpoints()[0].input_clusters.len(), 1);
    assert_eq!(device.endpoints()[0].input_clusters[0].0, 0xfc00);

    struct Routes(Vec<(u16, Option<u16>)>);
    impl DeviceServerVisitor for Routes {
        fn visit<C: ClusterServer>(&mut self, meta: ServerMeta, _server: &mut C) {
            self.0.push((meta.cluster.id.0, meta.cluster.manufacturer.map(|code| code.0)));
        }
    }

    let mut routes = Routes(Vec::new());
    device.visit_servers(&mut routes);
    assert_eq!(routes.0, vec![(0xfc00, Some(0x1234)), (0xfc00, Some(0x5678))]);
}
