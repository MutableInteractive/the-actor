use crate::handlers::actor_structure_type::{ActorStructureType, ChallengeAuthReq, ClientAnswerChallenge, ServerAuthoriChallenge};
use crate::util::challenge_util::decrypt_aes_ecb_base64;
use crate::vpn_config::VpnConfig;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tfserver::client::Receiver;
use tfserver::structures::s_type;
use tfserver::structures::s_type::StructureType;

pub struct AuthReceiver {
    auth_passed: AtomicBool,
    challenge_answer: Option<ClientAnswerChallenge>,
    config: Arc<VpnConfig>,
    iv_result: Option<String>
}

impl Receiver for AuthReceiver {
    fn get_handler_name(&self) -> String {
        "AUTH_HANDLER".to_string()
    }



    fn get_request(&mut self) -> Option<(Vec<u8>, Box<dyn StructureType>)> {
        if !self.auth_passed.load(std::sync::atomic::Ordering::Relaxed)
            && !self
                .challenge_answer.is_some()
        {
            let challenge_req = ChallengeAuthReq {
                s_type: ActorStructureType::ClientChallengeReq,
            };
            Some((
                s_type::to_vec(&challenge_req).unwrap(),
                Box::from(ActorStructureType::ClientChallengeReq),
            ))
        } else if self
            .challenge_answer.is_some()
        {
            let answer = s_type::to_vec(self.challenge_answer.as_ref().unwrap()).unwrap();
            Some((answer, Box::new(ActorStructureType::ClientAuthAnswer)))
        } else {
            return None;
        }
    }

    fn receive_response(&mut self, response: Vec<u8>) {
        if !self
            .challenge_answer.is_some()
        {
            let challenge =
                s_type::from_slice::<ServerAuthoriChallenge>(response.as_slice()).unwrap();
            let challenge_answer =
                decrypt_aes_ecb_base64(self.config.key.as_str(), challenge.challenge.as_str())
                    .unwrap();
            self.challenge_answer = Some(ClientAnswerChallenge{s_type: ActorStructureType::ClientAuthAnswer, answer: challenge_answer});
        } else {
            let challenge =
                s_type::from_slice::<ServerAuthoriChallenge>(response.as_slice()).unwrap();
            let challenge_answer =
                decrypt_aes_ecb_base64(self.config.key.as_str(), challenge.challenge.as_str())
                    .unwrap();
            self.auth_passed.store(true, std::sync::atomic::Ordering::Relaxed);
            self.iv_result = Some(challenge_answer);
        }
    }
}
