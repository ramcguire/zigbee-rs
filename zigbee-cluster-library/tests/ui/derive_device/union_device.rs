use zigbee_cluster_library::ZigbeeDevice;

#[derive(ZigbeeDevice)]
union Device {
    value: u8,
}

fn main() {}
