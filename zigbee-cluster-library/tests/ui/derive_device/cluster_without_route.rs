use zigbee_cluster_library::ZigbeeDevice;

#[derive(ZigbeeDevice)]
struct Device {
    #[zcl(cluster = 0xfc00)]
    marker: u8,
}

fn main() {}
