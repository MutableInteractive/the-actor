use crate::handlers::actor_structure_type::{
    ActorStructureType, ClientAnswerChallenge, ServerAuthoriChallenge,
};
use crate::util::challenge_util::generate_challenge_and_encrypt;
use crate::vpn_config::VpnConfig;
use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use tfserver::server::handler::Handler;
use tfserver::structures::s_type;
use tfserver::structures::s_type::{StrongType, StructureType};
use tfserver::tungstenite::WebSocket;
use crate::handlers::register_handler::RegisterHandler;

pub struct AuthHandler {
    pub pending_challenges: HashMap<SocketAddr, String>,
    pub config: Arc<VpnConfig>,
    pub register_handler: Arc<Mutex<RegisterHandler>>,
}

impl Handler for AuthHandler {
    fn serve_route(
        &mut self,
        client_meta: SocketAddr,
        s_type: Box<dyn StructureType>,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, Vec<u8>> {
        match s_type
            .as_any()
            .downcast_ref::<ActorStructureType>()
            .unwrap()
        {
            ActorStructureType::ClientChallengeReq => {
                let challenge = generate_challenge_and_encrypt(self.config.key.as_str()).unwrap();
                self.pending_challenges.insert(client_meta, challenge.0);
                let challenge = ServerAuthoriChallenge {
                    s_type: ActorStructureType::ServerAuthChallenge,
                    challenge: challenge.1,
                };
                return Ok(s_type::to_vec(&challenge).unwrap());
            }
            ActorStructureType::ClientAuthAnswer => {
                let answer_real = self.pending_challenges.get(&client_meta);
                if answer_real.is_none() {
                    return Err(String::from("no such pending client!").into_bytes());
                }
                let answer_real = answer_real.unwrap();
                let client_answer: Result<ClientAnswerChallenge, String> =
                    s_type::from_slice(data.as_slice());
                if client_answer.is_err() {
                    return Err(client_answer.err().unwrap().to_string().into_bytes());
                }
                let client_answer = client_answer.unwrap();
                if client_answer.answer == answer_real.clone() {
                    let challenge =
                        generate_challenge_and_encrypt(self.config.key.as_str()).unwrap();
                    self.register_handler.lock().unwrap().addresses_iv.lock().unwrap().insert(client_meta, challenge.clone());
                    let challenge = ServerAuthoriChallenge {
                        s_type: ActorStructureType::ServerAuthChallenge,
                        challenge: challenge.1,
                    };

                    return Ok(s_type::to_vec(&challenge).unwrap());
                }
                return Err(String::from("challenge failed!").into_bytes());
            }
            _ => {
                return Err(String::from("no such structure type!").into_bytes());
            }
        }
    }

    fn request_to_move_stream(&self) -> Option<Vec<SocketAddr>> {
        None
    }

    fn accept_stream(&mut self, stream: Vec<Arc<Mutex<WebSocket<TcpStream>>>>) {
        todo!()
    }
}
