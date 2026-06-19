use zcl::ZigbeeDevice;
use zcl::cluster_server::{ClusterServer, Device};
use zcl::common::{BasicConfig, BasicServer};

#[derive(ZigbeeDevice)]
struct RenamedDependencyDevice {
    #[zcl(endpoint = 1, profile = 0x0104, device = 0x0302)]
    basic: BasicServer,
}

fn main() {
    let device = RenamedDependencyDevice {
        basic: BasicServer::new(BasicConfig::new(3, "Acme", "Renamed", 0x01, true)),
    };
    assert_eq!(device.endpoints()[0].input_clusters, &[BasicServer::CLUSTER_ID]);
}
