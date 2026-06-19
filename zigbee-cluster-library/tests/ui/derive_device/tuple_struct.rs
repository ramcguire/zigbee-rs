use zigbee_cluster_library::common::BasicServer;
use zigbee_cluster_library::ZigbeeDevice;

#[derive(ZigbeeDevice)]
struct Device(BasicServer);

fn main() {}
