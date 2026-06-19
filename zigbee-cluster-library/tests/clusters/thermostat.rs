mod helpers;
mod vectors {
    include!("../vectors/clusters/thermostat.rs");
}

use helpers::assert_response;
use helpers::dispatch_bytes;
use zigbee_cluster_library::hvac::ThermostatServer;

// READ_CASES[0]: local_temp=2150; [1]: cooling default 2600; [2]: heating
// default 2000
const READ_LOCAL_TEMPS: &[Option<i16>] = &[Some(2150), None, None];

#[test]
fn read_attributes_matches_zigpy() {
    let mut buf = [0u8; 64];
    for (i, (req, expected)) in vectors::READ_CASES.iter().enumerate() {
        let mut server = ThermostatServer::new();
        if let Some(t) = READ_LOCAL_TEMPS[i] {
            server.set_local_temperature(Some(t));
        }
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(&outcome, &buf, expected, &format!("READ_CASES[{i}]"));
    }
}

#[test]
fn commands_match_zigpy() {
    let mut buf = [0u8; 32];
    for (i, (req, expected)) in vectors::COMMAND_CASES.iter().enumerate() {
        let mut server = ThermostatServer::new();
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(&outcome, &buf, expected, &format!("COMMAND_CASES[{i}]"));
    }
}

#[test]
fn write_attributes_matches_zigpy() {
    let mut buf = [0u8; 64];
    for (i, (req, expected)) in vectors::WRITE_CASES.iter().enumerate() {
        let mut server = ThermostatServer::new();
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(&outcome, &buf, expected, &format!("WRITE_CASES[{i}]"));
    }
}

#[test]
fn discover_attributes_exhaustive() {
    let mut buf = [0u8; 128];
    for (i, (req, expected)) in vectors::DISCOVER_CASES.iter().enumerate() {
        let mut server = ThermostatServer::new();
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(&outcome, &buf, expected, &format!("DISCOVER_CASES[{i}]"));
    }
}

#[test]
fn seq_echo_command() {
    // SEQ=7 cluster-specific command; response byte 1 must echo 7.
    let req = [0x01u8, 0x07, 0x00, 0x00, 0x00]; // cluster-specific, SEQ=7, SetpointRaiseLower, Heat, +0
    let mut server = ThermostatServer::new();
    let mut buf = [0u8; 32];
    let outcome = dispatch_bytes(&mut server, &req, &mut buf);
    assert!(outcome.response_len >= 2, "response too short");
    assert_eq!(
        buf[1], 0x07,
        "SEQ not echoed: got 0x{:02X}, want 0x07",
        buf[1]
    );
}

#[test]
fn setpoint_raise_lower_adjusts_setpoints() {
    let mut buf = [0u8; 32];

    // Heat +5: delta = 5*10 = 50 centideg → heating 2000→2050, cooling unchanged
    let mut server = ThermostatServer::new();
    dispatch_bytes(&mut server, &[0x01, 0x01, 0x00, 0x00, 0x05], &mut buf);
    assert_eq!(
        server.occupied_heating_setpoint, 2050,
        "heat +5: heating setpoint"
    );
    assert_eq!(
        server.occupied_cooling_setpoint, 2600,
        "heat +5: cooling unchanged"
    );

    // Cool -3: delta = -3*10 = -30 centideg → cooling 2600→2570, heating unchanged
    let mut server = ThermostatServer::new();
    dispatch_bytes(&mut server, &[0x01, 0x01, 0x00, 0x01, 0xFD], &mut buf);
    assert_eq!(
        server.occupied_cooling_setpoint, 2570,
        "cool -3: cooling setpoint"
    );
    assert_eq!(
        server.occupied_heating_setpoint, 2000,
        "cool -3: heating unchanged"
    );

    // Both +2: delta = 2*10 = 20 centideg → heating 2000→2020, cooling 2600→2620
    let mut server = ThermostatServer::new();
    dispatch_bytes(&mut server, &[0x01, 0x01, 0x00, 0x02, 0x02], &mut buf);
    assert_eq!(
        server.occupied_heating_setpoint, 2020,
        "both +2: heating setpoint"
    );
    assert_eq!(
        server.occupied_cooling_setpoint, 2620,
        "both +2: cooling setpoint"
    );
}
