use crate::handlers::actor_structure_type::ActorStructureType;
use crate::handlers::auth_handler::AuthHandler;
use crate::handlers::register_handler::RegisterHandler;
use crate::operational::packet_router::{PacketRouter, PacketRouterCreateInfo};
use crate::operational::tun_interface::{TunInterface, TunInterfaceCreateInfo};
use crate::vpn_config::VpnConfig;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tfserver::server::server_router::TcpServerRouter;
use tfserver::server::tcp_server_new::TcpServer;
use tfserver::util::data_cipher::EncryptionType;
use tfserver::util::thread_pool::ThreadPool;
use crate::server::proxy_internal_server::ProxyServerInternal;

pub mod front_interface;
pub mod handlers;
pub mod operational;
pub mod router_setup;
pub mod server;
pub mod util;
pub mod verbose;
pub mod vpn_config;

fn main() {
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
    let mut tun_info = TunInterfaceCreateInfo::default();
    let netmask = "255.255.255.0".to_string();
    let addr = Ipv4Addr::new(10, 0, 8, 1);
    tun_info.set_iff_ip(&addr);
    tun_info.set_iff_netmask(&netmask);
    tun_info.set_iff_name("tun0".to_string());
    let tun_interface = Arc::new(Mutex::new(TunInterface::new(&tun_info)));
    let create_info = PacketRouterCreateInfo {
        router_subnet: Ipv4Addr::from_str("10.0.8.1").unwrap(),
        router_subnet_ipv6: Ipv6Addr::from_str("2001:db8:3333:4444:5555:6666:7777:1").unwrap(),
        tun_interface,
        resyncer_timeout: Duration::from_millis(config.resyncer_timeout_ms as u64),
        max_packets_attempts_amount: config.max_packets_in_flight,
    };
    let packet_router = Arc::new(Mutex::new(PacketRouter::new(create_info)));
    let mut router = TcpServerRouter::new(Box::from(ActorStructureType::ClientChallengeReq));
    let proxy_server = Arc::new(Mutex::new(ProxyServerInternal::new(config.clone(), packet_router.clone(), Arc::new(Mutex::new(ThreadPool::new(15))))));

    let register_handler = Arc::new(Mutex::new(RegisterHandler {
        addresses_iv: Arc::new(Mutex::new(HashMap::new())),
        router: packet_router.clone(),
        config: config.clone(),
        pending_receivers: Arc::new(Mutex::new(HashMap::new())),
        proxy_server: proxy_server.clone(),
    }));
    router.add_route(
        Arc::new(Mutex::new(AuthHandler {
            pending_challenges: HashMap::new(),
            config: config.clone(),
            register_handler: register_handler.clone(),
        })),
        "AUTH_HANDLER".to_string(),
        vec![
            Box::from(ActorStructureType::ClientChallengeReq),
            Box::from(ActorStructureType::ClientAuthAnswer),
        ],
    );
    router.add_route(
        register_handler,
        "REGISTER_HANDLER".to_string(),
        vec![Box::from(ActorStructureType::RegisterHandlerRequest)],
    );
    router.commit_routes();
    let router = Arc::new(router);
    let server = Arc::new(Mutex::new(TcpServer::new("127.0.0.1:8090".to_string(), router, ThreadPool::new(5))));

    TcpServer::start(server);
    ProxyServerInternal::start(proxy_server);
    loop {

    }
}
