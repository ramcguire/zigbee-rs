mod helpers;
mod vectors {
    include!("../vectors/clusters/occupancy.rs");
}

use helpers::assert_response;
use helpers::dispatch_bytes;
use zigbee_cluster_library::measurement::occupancy::OccupancySensingServer;
use zigbee_cluster_library::types::enums::OccupancySensorType;

// READ_CASES[0]: occupancy=false
// READ_CASES[1]: occupancy=true
const READ_OCCUPIED: &[bool] = &[false, true];

#[test]
fn read_attributes_matches_zigpy() {
    let mut buf = [0u8; 64];
    for (i, (req, expected)) in vectors::READ_CASES.iter().enumerate() {
        let mut server = OccupancySensingServer::new(OccupancySensorType::Pir, 0x01);
        server.set_occupied(READ_OCCUPIED[i]);
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(
            &outcome,
            &buf,
            expected,
            &format!("READ_CASES[{i}] occupied={}", READ_OCCUPIED[i]),
        );
    }
}

#[test]
fn write_attributes_matches_zigpy() {
    let mut buf = [0u8; 64];
    for (i, (req, expected)) in vectors::WRITE_CASES.iter().enumerate() {
        let mut server = OccupancySensingServer::new(OccupancySensorType::Pir, 0x01);
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(&outcome, &buf, expected, &format!("WRITE_CASES[{i}]"));
    }
}

#[test]
fn discover_attributes_exhaustive() {
    let mut buf = [0u8; 128];
    for (i, (req, expected)) in vectors::DISCOVER_CASES.iter().enumerate() {
        let mut server = OccupancySensingServer::new(OccupancySensorType::Pir, 0x01);
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(&outcome, &buf, expected, &format!("DISCOVER_CASES[{i}]"));
    }
}
