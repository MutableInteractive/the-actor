use crate::handlers::actor_structure_type::{
    ActorStructureType, RegisterHandlerAnswer, RegisterHandlerRequest,
};
use crate::vpn_config::VpnConfig;
use std::sync::{Arc, Mutex};
use tfserver::client::Receiver;
use tfserver::structures::s_type;
use tfserver::structures::s_type::StructureType;

pub trait OnRegisterInfoReceiver{
    fn info_received(&mut self, reg_info: RegisterHandlerAnswer);
}

pub struct RegisterReceiver {
    pub iv_current: Option<String>,
    pub(crate) reg_info: Option<RegisterHandlerAnswer>,
    pub(crate) config: Arc<VpnConfig>,
    pub on_register_info: Arc<Mutex<dyn OnRegisterInfoReceiver>>,
}

impl Receiver for RegisterReceiver {
    fn get_handler_name(&self) -> String {
        "REGISTER_HANDLER".to_string()
    }


    fn get_request(&mut self) -> Option<(Vec<u8>, Box<dyn StructureType>)> {
        if self.iv_current.is_some() && self.reg_info.is_none() {
            println!("Awaiting reg info");
            let request = RegisterHandlerRequest {
                s_type: ActorStructureType::RegisterHandlerRequest,
            };
            let register_req = s_type::to_vec(&request).unwrap();
            return Some((
                register_req,
                Box::from(ActorStructureType::RegisterHandlerRequest),
            ));
        } else {
            return None;
        }
    }

    fn receive_response(&mut self, response: Vec<u8>) {
        println!("Received reginfo");
        let response = s_type::from_encrypted_slice::<RegisterHandlerAnswer>(
            response.as_slice(),
            self.config.encryption_type,
            self.config.key.clone(),
            self.iv_current.as_ref().unwrap().as_bytes(),
        ).unwrap();
        self.on_register_info.lock().unwrap().info_received(response);
    }
}
