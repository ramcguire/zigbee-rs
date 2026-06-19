mod helpers;
mod vectors {
    include!("../vectors/clusters/basic.rs");
}

use helpers::assert_response;
use helpers::dispatch_bytes;
use zigbee_cluster_library::common::basic::BasicConfig;
use zigbee_cluster_library::common::basic::BasicServer;

// READ_CASES: [zcl_version=3, power_source=0x01, device_enabled=false,
// device_enabled=true]
const READ_DEVICE_ENABLED: &[bool] = &[false, false, false, true];

fn make_server(device_enabled: bool) -> BasicServer {
    BasicServer::new(BasicConfig::new(3, "Acme", "Widget", 0x01, device_enabled))
}

#[test]
fn read_attributes_matches_zigpy() {
    let mut buf = [0u8; 64];
    for (i, (req, expected)) in vectors::READ_CASES.iter().enumerate() {
        let mut server = make_server(READ_DEVICE_ENABLED[i]);
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(&outcome, &buf, expected, &format!("READ_CASES[{i}]"));
    }
}

#[test]
fn write_attributes_matches_zigpy() {
    let mut buf = [0u8; 64];
    for (i, (req, expected)) in vectors::WRITE_CASES.iter().enumerate() {
        let mut server = make_server(false);
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(&outcome, &buf, expected, &format!("WRITE_CASES[{i}]"));
    }
}

#[test]
fn discover_attributes_exhaustive() {
    let mut buf = [0u8; 128];
    for (i, (req, expected)) in vectors::DISCOVER_CASES.iter().enumerate() {
        let mut server = make_server(false);
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(&outcome, &buf, expected, &format!("DISCOVER_CASES[{i}]"));
    }
}
