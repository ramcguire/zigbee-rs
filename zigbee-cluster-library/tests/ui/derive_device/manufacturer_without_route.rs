use zigbee_cluster_library::ZigbeeDevice;

#[derive(ZigbeeDevice)]
struct Device {
    #[zcl(manufacturer = 0x1234)]
    marker: u8,
}

fn main() {}
