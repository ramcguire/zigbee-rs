mod helpers;
mod vectors {
    include!("../vectors/clusters/illuminance.rs");
}

use helpers::assert_response;
use helpers::dispatch_bytes;
use zigbee_cluster_library::measurement::illuminance::IlluminanceMeasurementServer;

// READ_CASES[0..=2]: measured_value=[0, 1000, 65533]
// READ_CASES[3]: min_measured_value=10
// READ_CASES[4]: max_measured_value=60000
// READ_CASES[5]: tolerance=100
fn make_read_server(i: usize) -> IlluminanceMeasurementServer {
    let mut s = IlluminanceMeasurementServer::new();
    match i {
        0 => s.set_measured_value(Some(0)),
        1 => s.set_measured_value(Some(1000)),
        2 => s.set_measured_value(Some(65533)),
        3 => s.set_min_measured_value(Some(10)),
        4 => s.set_max_measured_value(Some(60000)),
        5 => s.set_tolerance(100),
        _ => {}
    }
    s
}

#[test]
fn read_attributes_matches_zigpy() {
    let mut buf = [0u8; 64];
    for (i, (req, expected)) in vectors::READ_CASES.iter().enumerate() {
        let mut server = make_read_server(i);
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(&outcome, &buf, expected, &format!("READ_CASES[{i}]"));
    }
}

#[test]
fn write_attributes_matches_zigpy() {
    let mut buf = [0u8; 64];
    for (i, (req, expected)) in vectors::WRITE_CASES.iter().enumerate() {
        let mut server = IlluminanceMeasurementServer::new();
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(&outcome, &buf, expected, &format!("WRITE_CASES[{i}]"));
    }
}

#[test]
fn discover_attributes_exhaustive() {
    let mut buf = [0u8; 128];
    for (i, (req, expected)) in vectors::DISCOVER_CASES.iter().enumerate() {
        let mut server = IlluminanceMeasurementServer::new();
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(&outcome, &buf, expected, &format!("DISCOVER_CASES[{i}]"));
    }
}
