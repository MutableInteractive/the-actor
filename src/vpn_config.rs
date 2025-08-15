use serde::{Deserialize, Serialize};
use tfserver::util::data_cipher::EncryptionType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConfig {
    pub key: String,
    pub hostname: String,
    pub encryption_type: EncryptionType,
    pub port: u16,
    pub garbage_packet_min_size: u64,
    pub garbage_packet_max_size: u64,
    pub max_garbage_packets_amount: u32,
    pub min_garbage_packets_amount: u32,
    pub max_packets_in_flight: u32,
    pub mtu_min: u32,
    pub mtu_max: u32,
    pub resyncer_timeout_ms: u32,
}
