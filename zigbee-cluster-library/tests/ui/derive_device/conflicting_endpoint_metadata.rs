use zigbee_cluster_library::common::{BasicServer, IdentifyServer};
use zigbee_cluster_library::ZigbeeDevice;

#[derive(ZigbeeDevice)]
struct Device {
    #[zcl(endpoint = 1, profile = 0x0104, device = 0x0302, version = 0)]
    basic: BasicServer,

    #[zcl(endpoint = 1, profile = 0x0105, device = 0x0302, version = 0)]
    identify: IdentifyServer,
}

fn main() {}
