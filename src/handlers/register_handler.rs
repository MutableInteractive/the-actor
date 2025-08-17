use std::collections::HashMap;
use crate::front_interface::jni_receiver::JniReceiver;
use crate::operational::packet_router::{AddressTuple, PacketRouter};
use crate::server::receiver_info::ReceiverInfo;
use crate::vpn_config::VpnConfig;
use std::net::{SocketAddr, TcpStream};
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;
use tfserver::server::handler::Handler;
use tfserver::structures::s_type;
use tfserver::structures::s_type::StructureType;
use tfserver::tungstenite::WebSocket;
use tfserver::util::data_cipher::DataCipher;
use crate::handlers::actor_structure_type::{ActorStructureType, RegisterHandlerAnswer};
use crate::server::proxy_internal_server::ProxyServerInternal;

pub struct RegisterHandler {
    pub(crate) addresses_iv: Arc<Mutex<HashMap<SocketAddr, (String, String)>>>,
    pub(crate) router: Arc<Mutex<PacketRouter>>,
    pub(crate) config: Arc<VpnConfig>,
    pub(crate) pending_receivers: Arc<Mutex<HashMap<SocketAddr, ReceiverInfo>>>,
    pub(crate) proxy_server: Arc<Mutex<ProxyServerInternal>>,
}

impl Handler for RegisterHandler {
    fn serve_route(&mut self, client_meta: SocketAddr, s_type: Box<dyn StructureType>, data: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
        let binding = self.addresses_iv.lock().unwrap();
        let iv = binding.get(&client_meta);
        if iv.is_none() {
            return Err("No such authorized address!".as_bytes().to_vec());
        }
        let iv = iv.unwrap().clone();
        drop(binding);

        let receiver = JniReceiver::new(self.config.clone().deref(), iv.0.clone());
        let reg_data1 = self.router.lock().unwrap().register(Arc::new(Mutex::new(receiver)));
        let reg_data = RegisterHandlerAnswer{s_type: ActorStructureType::RegisterHandlerAnswer, ipv4: reg_data1.0.to_string(),
            ipv6: reg_data1.1.to_string()};
        let cipher = DataCipher::new_init(self.config.encryption_type, self.config.key.clone());
        let data = s_type::to_vec_encrypted(&reg_data, self.config.encryption_type, self.config.key.clone(), iv.0.clone().as_bytes()).unwrap();
        let receiver_info = ReceiverInfo {
            cipher,
            ipv4addr: reg_data1.0,
            ipv6addr: reg_data1.1,
            iv: iv.0.clone(),
            receiver_handle: reg_data1.2,
        };
        self.pending_receivers.lock().unwrap().insert(client_meta, receiver_info);
        Ok(data)
    }

    fn request_to_move_stream(&self) -> Option<Vec<SocketAddr>> {
        let receivers_lock = self.pending_receivers.lock().unwrap();
        if receivers_lock.is_empty() {
            return None;
        }
        let mut keys = Vec::with_capacity(receivers_lock.len());
        receivers_lock.iter().for_each(|(client_meta, _)| {
            keys.push(client_meta.clone());
        });
        Some(keys)
    }

    fn accept_stream(&mut self, mut stream: Vec<Arc<Mutex<WebSocket<TcpStream>>>>) {
        let mut receivers_lock = self.pending_receivers.lock().unwrap();
        let binding = self.proxy_server.lock().unwrap();
        let mut streams_lock = binding.streams_in_handle.lock().unwrap();
        while !stream.is_empty(){
            let stream_c = stream.pop().unwrap();
            let data = receivers_lock.remove(stream_c.lock().unwrap().get_ref().peer_addr().as_ref().unwrap()).unwrap();
            streams_lock.insert(AddressTuple::new_full(data.ipv4addr.clone(), data.ipv6addr.clone()),
                                ((stream_c, Arc::new(Mutex::new(data))), Arc::new(Mutex::new(AtomicBool::new(false)))));
        }
    }
}
