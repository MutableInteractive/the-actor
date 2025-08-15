use std::collections::HashMap;
use std::intrinsics::mir::Drop;
use crate::front_interface::jni_receiver::JniReceiver;
use crate::operational::data_cipher::DataCipher;
use crate::operational::packet_router::PacketRouter;
use crate::server::receiver_info::ReceiverInfo;
use crate::streams::mtu_splitter::MtuSplitter;
use crate::util::challenge_util::generate_challenge_and_encrypt;
use crate::vpn_config::VpnConfig;
use rand::random_range;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use tfserver::server::handler::Handler;
use tfserver::structures::s_type;
use crate::handlers::actor_structure_type::{ActorStructureType, RegisterHandlerAnswer};
use crate::server::handler::Handler;
use crate::streams::s_type;
use crate::streams::s_type::{StrongType, StructureType};
use crate::util::rand_utils;
use crate::verbose::logger::Logger;


pub struct RegisterHandler {
    addresses_iv: Arc<Mutex<HashMap<SocketAddr, (String, String)>>>,
    router: Arc<Mutex<PacketRouter>>,
    config: Arc<VpnConfig>,
    pending_receivers: Arc<Mutex<HashMap<SocketAddr, ReceiverInfo>>>,
    owned_streams: Arc<Mutex<Vec<Arc<Mutex<TcpStream>>>>>,
}

impl Handler for RegisterHandler {
    fn serve_route(&mut self, client_meta: SocketAddr, s_type: ActorStructureType, data: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
        let iv = self.addresses_iv.lock().unwrap().get(&client_meta);
        if iv.is_none() {
            return Err("No such authorized address!".as_bytes().to_vec());
        }
        let iv = iv.unwrap();
        let receiver = JniReceiver::new(self.config.clone().deref(), iv.0.clone());
        let mtu = random_range(self.config.mtu_min..self.config.mtu_max);
        let reg_data1 = self.router.lock().unwrap().register(Arc::new(Mutex::new(receiver)));
        let reg_data = RegisterHandlerAnswer{s_type: StructureType::RegisterHandlerAnswer, ipv4: reg_data1.0.to_string(), ipv6: reg_data1.1.to_string(), mtu};
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
        let keys = receivers_lock.keys().collect::<Vec<SocketAddr>>();
        Some(keys)
    }

    fn accept_stream(&mut self, mut stream: Vec<Arc<Mutex<TcpStream>>>) {
        let mut receivers_lock = self.pending_receivers.lock().unwrap();
        stream.iter().for_each(|stream| {
            receivers_lock.remove(&stream.lock().unwrap().peer_addr().unwrap());
        });
        drop(receivers_lock);
        let mut lock = self.owned_streams.lock().unwrap();
        while !stream.is_empty(){
            lock.push(stream.pop().unwrap());
        }
    }
}
