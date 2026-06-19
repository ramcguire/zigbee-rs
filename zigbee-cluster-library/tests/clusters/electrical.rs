mod helpers;
mod vectors {
    include!("../vectors/clusters/electrical.rs");
}

use helpers::assert_response;
use helpers::dispatch_bytes;
use zigbee_cluster_library::measurement::electrical::ElectricalMeasurementServer;

// READ_CASES[0]: voltage=0, current=0, power=0
// READ_CASES[1]: voltage=230, current=1000, power=100
// READ_CASES[2]: measurement_type=0x0000_0008 (SinglePhaseAC)
fn make_read_server(i: usize) -> ElectricalMeasurementServer {
    let mut s = ElectricalMeasurementServer::new();
    match i {
        0 => {
            s.set_rms_voltage(0);
            s.set_rms_current(0);
            s.set_active_power(0);
        }
        1 => {
            s.set_rms_voltage(230);
            s.set_rms_current(1000);
            s.set_active_power(100);
        }
        2 => {
            s.set_measurement_type(0x0000_0008);
        }
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
        let mut server = ElectricalMeasurementServer::new();
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(&outcome, &buf, expected, &format!("WRITE_CASES[{i}]"));
    }
}

#[test]
fn discover_attributes_exhaustive() {
    let mut buf = [0u8; 128];
    for (i, (req, expected)) in vectors::DISCOVER_CASES.iter().enumerate() {
        let mut server = ElectricalMeasurementServer::new();
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(&outcome, &buf, expected, &format!("DISCOVER_CASES[{i}]"));
    }
}
