use std::net::{Ipv4Addr, Ipv6Addr};
use crate::front_interface::direct_tun::DirectTun;
use crate::handlers::actor_structure_type::RegisterHandlerAnswer;
use crate::receivers::auth_receiver::AuthReceiver;
use crate::receivers::register_receiver::{OnRegisterInfoReceiver, RegisterReceiver};
use crate::vpn_config::VpnConfig;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread::spawn;
use tfserver::client::{ClientConnection, Receiver};
use tfserver::openssl::version::dir;
use tfserver::tungstenite::{Bytes, Message};
use tfserver::util::data_cipher::EncryptionType;
use crate::operational::data_pack::BytesBuff;

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
    connection: Option<Arc<Mutex<ClientConnection>>>,
    config: Arc<VpnConfig>,
    ipv4assigned: Option<Ipv4Addr>,
    ipv6assigned: Option<Ipv6Addr>,
    iv: Option<String>,
    running: Arc<Mutex<AtomicBool>>,
}

impl TunnelThread {
    pub fn start(&mut self) {
        let direct_tun = self.direct_tun.as_ref().unwrap().clone();
        let connection = self.connection.as_ref().unwrap().lock().unwrap().stop_and_move_stream();
        spawn(move || {
            let packets = direct_tun.lock().unwrap().get_packets();
            if !packets.is_empty(){
                connection.lock().unwrap().send(Message::Binary(Bytes::from(packets))).unwrap();
            }
            let answer = connection.lock().unwrap().read();
            match answer {
                Ok(message) => {
                    match message {
                        Message::Text(_) => {}
                        Message::Binary(data) => {
                            let data = tfserver::server::tcp_server_new::bytes_into_vec(data);
                            direct_tun.lock().unwrap().write_data(data);
                        }
                        Message::Ping(_) => {}
                        Message::Pong(_) => {}
                        Message::Close(_) => {}
                        Message::Frame(_) => {}
                    }
                }
                Err(_) => {}
            }
        });
    }
}


impl OnRegisterInfoReceiver for TunnelThread {
    fn info_received(&mut self, iv: String, reg_info: RegisterHandlerAnswer) {
        let info = reg_info;
        self.iv = Some(iv.clone());
        self.ipv4assigned = Some(info.ipv4.parse().unwrap());
        self.ipv6assigned = Some(info.ipv6.parse().unwrap());

        self.direct_tun = Some(Arc::new(Mutex::new(DirectTun::new(
            self.config.as_ref().clone(),
            iv,
            info.ipv4.clone().to_string(),
            Some("actor-tun0".to_string()),
        ))));
        self.start();
    }
}

pub fn main() {
    let config = Arc::new(VpnConfig {
        key: "HelloWorldEncKey".to_string(),
        hostname: "192.168.88.247".to_string(),
        encryption_type: EncryptionType::Aes256Ctr,
        port: 8090,
        garbage_packet_min_size: 1,
        garbage_packet_max_size: 25,
        max_garbage_packets_amount: 20,
        min_garbage_packets_amount: 5,
        max_packets_in_flight: 2,
        mtu_min: 9000,
        mtu_max: 1000,
        resyncer_timeout_ms: 3,
    });
    let tunnel_thread = Arc::new(Mutex::new(TunnelThread {
        direct_tun: None,
        connection: None,
        config: config.clone(),
        ipv4assigned: None,
        ipv6assigned: None,
        iv: None,
        running: Arc::new(Mutex::new(Default::default())),
    }));
    let register_receiver = Arc::new(Mutex::new(RegisterReceiver {
        iv_current: None,
        reg_info: None,
        data_send: AtomicBool::new(false),
        config: config.clone(),
        on_register_info: tunnel_thread.clone(),
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
    tunnel_thread.lock().unwrap().connection = Some(connection.clone());
    connection.lock().unwrap().start();

    loop {}
}
