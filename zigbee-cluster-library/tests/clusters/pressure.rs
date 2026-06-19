mod helpers;
mod vectors {
    include!("../vectors/clusters/pressure.rs");
}

use helpers::assert_response;
use helpers::dispatch_bytes;
use zigbee_cluster_library::measurement::pressure::PressureMeasurementServer;

// READ_CASES[0..=2]: measured_value=[0, 1013, -1]
// READ_CASES[3]: min_measured_value=0
// READ_CASES[4]: max_measured_value=2000
// READ_CASES[5]: tolerance=100
fn make_read_server(i: usize) -> PressureMeasurementServer {
    let mut s = PressureMeasurementServer::new();
    match i {
        0 => s.set_measured_value(Some(0)).unwrap(),
        1 => s.set_measured_value(Some(1013)).unwrap(),
        2 => s.set_measured_value(Some(-1)).unwrap(),
        3 => s.set_min_measured_value(Some(0)).unwrap(),
        4 => s.set_max_measured_value(Some(2000)).unwrap(),
        5 => s.set_tolerance(100).unwrap(),
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
        let mut server = PressureMeasurementServer::new();
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(&outcome, &buf, expected, &format!("WRITE_CASES[{i}]"));
    }
}

#[test]
fn discover_attributes_exhaustive() {
    let mut buf = [0u8; 128];
    for (i, (req, expected)) in vectors::DISCOVER_CASES.iter().enumerate() {
        let mut server = PressureMeasurementServer::new();
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(&outcome, &buf, expected, &format!("DISCOVER_CASES[{i}]"));
    }
}
