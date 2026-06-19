extern crate zigbee_cluster_library as zcl;

use zcl::cluster_server::Device;
use zcl::common::BasicServer;
use zcl::ZigbeeDevice;

#[derive(ZigbeeDevice)]
#[zigbee_device(crate = zcl)]
struct DeviceWithOverride {
    #[zcl(endpoint = 1, profile = 0x0104, device = 0x0302)]
    basic: BasicServer,
}

fn main() {
    let _ = DeviceWithOverride::endpoints;
}
