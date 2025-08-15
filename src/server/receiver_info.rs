use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use crate::front_interface::jni_receiver::JniReceiver;
use crate::operational::data_cipher::DataCipher;
use crate::operational::packet_router::PacketReceiver;
use crate::streams::mtu_splitter::MtuSplitter;

pub struct ReceiverInfo{
    pub cipher: DataCipher,
    pub ipv4addr: Ipv4Addr,
    pub ipv6addr: Ipv6Addr,
    pub iv: String,
    pub receiver_handle: Arc<Mutex<dyn PacketReceiver>>,
}