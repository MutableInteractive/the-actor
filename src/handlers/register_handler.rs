use std::collections::HashMap;
use crate::front_interface::jni_receiver::JniReceiver;
use crate::operational::packet_router::PacketRouter;
use crate::server::receiver_info::ReceiverInfo;
use crate::vpn_config::VpnConfig;
use std::net::{SocketAddr, TcpStream};
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use tfserver::server::handler::Handler;
use tfserver::structures::s_type;
use tfserver::structures::s_type::StructureType;
use tfserver::util::data_cipher::DataCipher;
use tungstenite::WebSocket;
use crate::handlers::actor_structure_type::{ActorStructureType, RegisterHandlerAnswer};



pub struct RegisterHandler {
    addresses_iv: Arc<Mutex<HashMap<SocketAddr, (String, String)>>>,
    router: Arc<Mutex<PacketRouter>>,
    config: Arc<VpnConfig>,
    pending_receivers: Arc<Mutex<HashMap<SocketAddr, ReceiverInfo>>>,
    owned_streams: Arc<Mutex<Vec<Arc<Mutex<WebSocket<TcpStream>>>>>>,
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
        stream.iter().for_each(|stream| {
            receivers_lock.remove(&stream.lock().unwrap().get_ref().peer_addr().unwrap());
        });
        drop(receivers_lock);
        let mut lock = self.owned_streams.lock().unwrap();
        while !stream.is_empty(){
            lock.push(stream.pop().unwrap());
        }
    }
}
