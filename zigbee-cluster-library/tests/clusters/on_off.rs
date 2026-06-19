mod helpers;
mod vectors {
    include!("../vectors/clusters/on_off.rs");
}

use helpers::assert_response;
use helpers::dispatch_bytes;
use zigbee_cluster_library::lighting::on_off::OnOffServer;

// Matches the order of READ_CASES in the generated vector file.
const READ_INITIAL_STATES: &[bool] = &[false, true];

#[test]
fn read_attributes_matches_zigpy() {
    let mut buf = [0u8; 64];
    for (i, (req, expected)) in vectors::READ_CASES.iter().enumerate() {
        let mut server = OnOffServer::new(READ_INITIAL_STATES[i]);
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(
            &outcome,
            &buf,
            expected,
            &format!("READ_CASES[{i}] state={}", READ_INITIAL_STATES[i]),
        );
    }
}

#[test]
fn commands_match_zigpy() {
    let mut buf = [0u8; 32];
    for (i, (req, expected)) in vectors::COMMAND_CASES.iter().enumerate() {
        let mut server = OnOffServer::new(false);
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(&outcome, &buf, expected, &format!("COMMAND_CASES[{i}]"));
    }
}

#[test]
fn write_attributes_matches_zigpy() {
    let mut buf = [0u8; 64];
    for (i, (req, expected)) in vectors::WRITE_CASES.iter().enumerate() {
        let mut server = OnOffServer::new(false);
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(&outcome, &buf, expected, &format!("WRITE_CASES[{i}]"));
    }
}

#[test]
fn discover_attributes_exhaustive() {
    let mut buf = [0u8; 128];
    for (i, (req, expected)) in vectors::DISCOVER_CASES.iter().enumerate() {
        let mut server = OnOffServer::new(false);
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(&outcome, &buf, expected, &format!("DISCOVER_CASES[{i}]"));
    }
}
