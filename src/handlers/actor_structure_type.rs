use std::any::{Any, TypeId};
use std::hash::{DefaultHasher, Hash, Hasher};
use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};
use tfserver::structures::s_type::{StrongType, StructureType};

#[repr(u8)]
#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Eq, TryFromPrimitive, Copy)]
pub enum ActorStructureType {
    ClientChallengeReq,
    ClientAuthAnswer,
    ServerAuthChallenge,
    RegisterHandlerRequest,
    RegisterHandlerAnswer
}

impl ActorStructureType {
    pub fn deserialize(val: u64) -> Box<dyn StructureType> {
        Box::new(ActorStructureType::try_from(val as u8).unwrap())
    }

    pub fn serialize(refer: Box<dyn StructureType>) -> u64 {
        let res = refer
            .as_any()
            .downcast_ref::<ActorStructureType>()
            .unwrap()
            .clone() as u8 as u64;
        res
    }
}

impl StructureType for ActorStructureType {
    fn get_type_id(&self) -> TypeId {
        match self {
            ActorStructureType::ClientChallengeReq => TypeId::of::<ChallengeAuthReq>(),
            ActorStructureType::ServerAuthChallenge => TypeId::of::<ServerAuthoriChallenge>(),
            ActorStructureType::ClientAuthAnswer => TypeId::of::<ClientAnswerChallenge>(),

            ActorStructureType::RegisterHandlerRequest => TypeId::of::<RegisterHandlerRequest>(),
            ActorStructureType::RegisterHandlerAnswer => TypeId::of::<RegisterHandlerAnswer>(),
        }
    }

    fn equals(&self, other: &dyn StructureType) -> bool {
        let downcast = other.as_any().downcast_ref::<Self>();
        if downcast.is_none() {
            return false;
        }
        let downcast = downcast.unwrap();
        downcast.clone() as u8 == self.clone() as u8
    }
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn hash(&self) -> u64 {
        let mut hasher = DefaultHasher::default();
        TypeId::of::<Self>().hash(&mut hasher);
        ((*self).clone() as u8 as u64).hash(&mut hasher);
        return hasher.finish();
    }

    fn clone_unique(&self) -> Box<dyn StructureType> {
        Box::new(self.clone())
    }

    fn get_deserialize_function(&self) -> Box<dyn Fn(u64) -> Box<dyn StructureType>> {
        Box::new(ActorStructureType::deserialize)
    }

    fn get_serialize_function(&self) -> Box<dyn Fn(Box<dyn StructureType>) -> u64> {
        Box::new(ActorStructureType::serialize)
    }
}

#[derive(Serialize, Deserialize)]
pub struct ChallengeAuthReq{
    pub s_type: ActorStructureType,
}

#[derive(Serialize, Deserialize)]
pub struct ServerAuthoriChallenge{
    pub s_type: ActorStructureType,
    pub challenge: String,
}
#[derive(Serialize, Deserialize)]
pub struct ClientAnswerChallenge{
    pub s_type: ActorStructureType,
    pub answer: String,
}

#[derive(Serialize, Deserialize)]
pub struct RegisterHandlerRequest{
    pub s_type: ActorStructureType,
}

#[derive(Serialize, Deserialize)]
pub struct RegisterHandlerAnswer{
    pub(crate) s_type: ActorStructureType,
    pub(crate) ipv4: String,
    pub(crate) ipv6: String,
}

impl StrongType for RegisterHandlerRequest {
    fn get_s_type(&self) -> &dyn StructureType {
        &self.s_type
    }
}

impl StrongType for RegisterHandlerAnswer {
    fn get_s_type(&self) -> &dyn StructureType {
        &self.s_type
    }
}

impl StrongType for ChallengeAuthReq {
    fn get_s_type(&self) -> &dyn StructureType {
        &self.s_type
    }
}

impl StrongType for ClientAnswerChallenge {
    fn get_s_type(&self) -> &dyn StructureType {
        &self.s_type
    }
}

impl StrongType for ServerAuthoriChallenge {
    fn get_s_type(&self) -> &dyn StructureType {
        &self.s_type
    }
}

