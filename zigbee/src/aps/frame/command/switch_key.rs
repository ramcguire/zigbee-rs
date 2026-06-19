use zigbee_macros::impl_byte;

impl_byte! {
    /// §4.4.7.1 — APSME-SWITCH-KEY.indication payload
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SwitchKey {
        pub key_seq_number: u8,
    }
}
