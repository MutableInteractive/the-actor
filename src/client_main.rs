use std::net::{Ipv4Addr, Ipv6Addr};
use crate::front_interface::direct_tun::DirectTun;
use crate::handlers::actor_structure_type::RegisterHandlerAnswer;
use crate::receivers::auth_receiver::AuthReceiver;
use crate::receivers::register_receiver::{OnRegisterInfoReceiver, RegisterReceiver};
use crate::vpn_config::VpnConfig;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use tfserver::client::{ClientConnection, Receiver};
use tfserver::util::data_cipher::EncryptionType;

pub mod front_interface;
pub mod handlers;
pub mod operational;
pub mod receivers;
pub mod router_setup;
pub mod server;
pub mod util;
pub mod verbose;
pub mod vpn_config;

struct TunnelThread {
    direct_tun: Option<Arc<Mutex<DirectTun>>>,
    connection: Arc<Mutex<ClientConnection>>,
    config: Arc<VpnConfig>,
    ipv4assigned: Ipv4Addr,
    ipv6assigned: Ipv6Addr,
    iv: String,
    running: Arc<Mutex<AtomicBool>>,
}

impl OnRegisterInfoReceiver for TunnelThread {
    fn info_received(&mut self, iv: String, reg_info: RegisterHandlerAnswer) {
        let info = reg_info;
        self.direct_tun = Some(Arc::new(Mutex::new(DirectTun::new(
            self.config.as_ref().clone(),
            iv,
            info.ipv4.clone().to_string(),
            Some("actor-tun0".to_string()),
        ))));
    }
}

pub fn main() {
    let config = Arc::new(VpnConfig {
        key: "HelloWorldEncKey".to_string(),
        hostname: "192.168.88.247".to_string(),
        encryption_type: EncryptionType::Aes256Ctr,
        port: 8090,
        garbage_packet_min_size: 1,
        garbage_packet_max_size: 2,
        max_garbage_packets_amount: 1,
        min_garbage_packets_amount: 0,
        max_packets_in_flight: 2,
        mtu_min: 9000,
        mtu_max: 1000,
        resyncer_timeout_ms: 3,
    });

    let register_receiver = Arc::new(Mutex::new(RegisterReceiver {
        iv_current: None,
        reg_info: None,
        config: config.clone(),
    }));
    let auth_receiver = Arc::new(Mutex::new(AuthReceiver {
        auth_passed: AtomicBool::new(false),
        challenge_answer: None,
        config: config.clone(),
        iv_result: None,
        register_receiver: register_receiver.clone(),
    }));
    let mut receivers: Vec<Arc<Mutex<dyn Receiver>>> = Vec::new();
    receivers.push(auth_receiver);
    receivers.push(register_receiver);
    let mut connection = Arc::new(Mutex::new(ClientConnection::new(
        "ws://127.0.0.1:8090".to_string(),
        receivers,
    )));
    connection.lock().unwrap().start();

    loop {}
}
