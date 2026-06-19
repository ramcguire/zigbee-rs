use zigbee_cluster_library::common::BasicServer;
use zigbee_cluster_library::ZigbeeDevice;

#[derive(ZigbeeDevice)]
struct Device {
    #[zcl(endpoint = 1)]
    basic: BasicServer,
}

fn main() {}
