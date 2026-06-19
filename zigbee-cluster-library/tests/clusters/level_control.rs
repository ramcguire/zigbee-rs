mod helpers;
mod vectors {
    include!("../vectors/clusters/level_control.rs");
}

use helpers::assert_response;
use helpers::dispatch_bytes;
use zigbee_cluster_library::lighting::level_control::LevelControlServer;

// Matches values=[0, 127, 254] in gen_cluster_level_control().
const READ_VALUES: &[Option<u8>] = &[Some(0), Some(127), Some(254)];

#[test]
fn read_attributes_matches_zigpy() {
    let mut buf = [0u8; 64];
    for (i, (req, expected)) in vectors::READ_CASES.iter().enumerate() {
        let mut server = LevelControlServer::new(READ_VALUES[i]);
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(
            &outcome,
            &buf,
            expected,
            &format!("READ_CASES[{i}] level={:?}", READ_VALUES[i]),
        );
    }
}

#[test]
fn commands_match_zigpy() {
    let mut buf = [0u8; 32];
    for (i, (req, expected)) in vectors::COMMAND_CASES.iter().enumerate() {
        let mut server = LevelControlServer::new(Some(0));
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(&outcome, &buf, expected, &format!("COMMAND_CASES[{i}]"));
    }
}

#[test]
fn write_attributes_matches_zigpy() {
    let mut buf = [0u8; 64];
    for (i, (req, expected)) in vectors::WRITE_CASES.iter().enumerate() {
        let mut server = LevelControlServer::new(Some(0));
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(&outcome, &buf, expected, &format!("WRITE_CASES[{i}]"));
    }
}

#[test]
fn discover_attributes_exhaustive() {
    let mut buf = [0u8; 128];
    for (i, (req, expected)) in vectors::DISCOVER_CASES.iter().enumerate() {
        let mut server = LevelControlServer::new(Some(0));
        let outcome = dispatch_bytes(&mut server, req, &mut buf);
        assert_response(&outcome, &buf, expected, &format!("DISCOVER_CASES[{i}]"));
    }
}
