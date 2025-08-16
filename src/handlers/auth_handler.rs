use std::collections::HashMap;
use crate::util::challenge_util::generate_challenge_and_encrypt;
use crate::vpn_config::VpnConfig;
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use tfserver::server::handler::Handler;
use tfserver::structures::s_type::{StrongType, StructureType};
use tfserver::structures::s_type;
use crate::handlers::actor_structure_type::{ActorStructureType, ClientAnswerChallenge, ServerAuthoriChallenge};

pub struct AuthHandler{
    pending_challenges: HashMap<SocketAddr, String>,
    config: Arc<VpnConfig>,
}


impl Handler for AuthHandler {
    fn serve_route(&mut self, client_meta: SocketAddr, s_type: StructureType, data: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
        match s_type {
            ActorStructureType::ClientChallengeReq => {
                let challenge = generate_challenge_and_encrypt(self.config.key.as_str()).unwrap();
                self.pending_challenges.insert(client_meta, challenge.0);
                let challenge = ServerAuthoriChallenge{s_type: ActorStructureType::ClientChallengeReq, challenge: challenge.1};
                return Ok(s_type::to_vec(&challenge).unwrap());
            }
            ActorStructureType::ClientAuthAnswer => {
                let answer_real = self.pending_challenges.get(&client_meta);
                if answer_real.is_none() {
                    return Err(String::from("no such pending client!").into_bytes());
                }
                let answer_real = answer_real.unwrap();
                let client_answer: Result<ClientAnswerChallenge, String> = s_type::from_slice(data.as_slice());
                if client_answer.is_err() {
                    return Err(client_answer.err().unwrap().to_string().into_bytes());
                }
                let client_answer = client_answer.unwrap();
                if !client_answer.answer.eq(answer_real) {
                    let challenge = generate_challenge_and_encrypt(self.config.key.as_str()).unwrap();
                    let challenge = ServerAuthoriChallenge{s_type: ActorStructureType::ServerAuthChallenge, challenge: challenge.1};
                    return Ok(s_type::to_vec(&challenge).unwrap());
                }
                return Err(String::from("unknown error!").into_bytes())
            }
            _ => {
                return Err(String::from("no such structure type!").into_bytes());
            }
        }
    }

    fn request_to_move_stream(&self) -> Option<Vec<SocketAddr>> {
        None
    }

    fn accept_stream(&mut self, stream: Vec<Arc<Mutex<TcpStream>>>) {
        todo!()
    }
}
