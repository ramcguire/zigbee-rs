use zigbee_cluster_library::cluster_server::ClusterServer;
use zigbee_cluster_library::cluster_server::DispatchContext;
use zigbee_cluster_library::cluster_server::DispatchOutcome;
use zigbee_cluster_library::cluster_server::zcl_cluster_dispatch;
use zigbee_cluster_library::frame::IncomingZclFrame;

pub fn unicast() -> DispatchContext {
    DispatchContext::unicast(0, None)
}

pub fn dispatch_bytes<CS: ClusterServer>(
    server: &mut CS,
    req: &[u8],
    buf: &mut [u8],
) -> DispatchOutcome {
    let (frame, _) = IncomingZclFrame::decode(req)
        .unwrap_or_else(|e| panic!("decode failed for {req:02X?}: {e:?}"));
    zcl_cluster_dispatch(server, &frame, unicast(), buf)
        .unwrap_or_else(|e| panic!("dispatch failed for {req:02X?}: {e:?}"))
}

pub fn assert_response(outcome: &DispatchOutcome, buf: &[u8], expected: &[u8], label: &str) {
    assert_eq!(
        &buf[..outcome.response_len],
        expected,
        "{label}: response mismatch\n  got:      {:02X?}\n  expected: {:02X?}",
        &buf[..outcome.response_len],
        expected,
    );
}
