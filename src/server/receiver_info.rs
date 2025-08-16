use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use tfserver::util::data_cipher::DataCipher;
use crate::operational::packet_router::PacketReceiver;

pub struct ReceiverInfo{
    pub cipher: DataCipher,
    pub ipv4addr: Ipv4Addr,
    pub ipv6addr: Ipv6Addr,
    pub iv: String,
    pub receiver_handle: Arc<Mutex<dyn PacketReceiver>>,
}