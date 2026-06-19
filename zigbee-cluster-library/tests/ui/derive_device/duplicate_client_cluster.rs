use zigbee_cluster_library::common::BasicServer;
use zigbee_cluster_library::ZigbeeDevice;

#[derive(ZigbeeDevice)]
struct Device {
    #[zcl(endpoint = 1, profile = 0x0104, device = 0x0302)]
    #[zcl(client_cluster = 0x0019)]
    #[zcl(client_cluster = 0x0019)]
    basic: BasicServer,
}

fn main() {}
