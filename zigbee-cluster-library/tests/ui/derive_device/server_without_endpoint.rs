use zigbee_cluster_library::common::BasicServer;
use zigbee_cluster_library::ZigbeeDevice;

#[derive(ZigbeeDevice)]
struct Device {
    #[zcl(server)]
    basic: BasicServer,
}

fn main() {}
