use zigbee_cluster_library::common::BasicServer;
use zigbee_cluster_library::ZigbeeDevice;

#[derive(ZigbeeDevice)]
struct Device {
    #[zcl(endpoint = 0, profile = 0x0104, device = 0x0302)]
    basic: BasicServer,
}

fn main() {}
