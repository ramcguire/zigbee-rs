use zigbee_cluster_library::cluster_server::ClusterServer;
use zigbee_cluster_library::types::error::AttrError;
use zigbee_cluster_library::types::ids::{AttributeId, ClusterId, TypeId};
use zigbee_cluster_library::ZigbeeDevice;

struct A;
struct B;

impl ClusterServer for A {
    const CLUSTER_ID: ClusterId = ClusterId::new(0x0001);

    fn read_attribute(&self, _id: AttributeId, _buf: &mut [u8]) -> Result<(TypeId, usize), AttrError> {
        Err(AttrError::UnsupportedAttribute)
    }
}

impl ClusterServer for B {
    const CLUSTER_ID: ClusterId = ClusterId::new(0x0002);

    fn read_attribute(&self, _id: AttributeId, _buf: &mut [u8]) -> Result<(TypeId, usize), AttrError> {
        Err(AttrError::UnsupportedAttribute)
    }
}

#[derive(ZigbeeDevice)]
struct Device {
    #[zcl(endpoint = 1, profile = 0x0104, device = 0x0302, cluster = 0xfc00, manufacturer = 0x1234)]
    a: A,

    #[zcl(endpoint = 1, cluster = 0xfc00, manufacturer = 0x1234)]
    b: B,
}

fn main() {}
