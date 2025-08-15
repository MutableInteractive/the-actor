use std::any::Any;
use crate::operational::data_cipher::DataCipher;
use crate::operational::data_pack::{DATA_PACKET, DataPack};
use crate::operational::packet_router::PacketReceiver;
use crate::util::semaphore::Semaphore;
use crate::operational::tun_interface::{IpPacket, TunInterface};
use crate::vpn_config::VpnConfig;
use std::mem;
use tfserver::util::data_cipher::DataCipher;

pub struct JniReceiver {
    data_pack: DataPack,
    data_cipher: DataCipher,
    vpn_config: VpnConfig,
    receive_buffer: Vec<u8>,
    iv: String,
    write_buffer: Vec<IpPacket>,
    write_semaphore: Semaphore,
    pending_packets: Vec<IpPacket>,
    pending_packets_semaphore: Semaphore,
}

impl JniReceiver {
    pub fn new(vpn_config: &VpnConfig, iv: String) -> JniReceiver {
        let data_pack = DataPack::new(vpn_config.clone());
        let data_cipher = DataCipher::new_init(vpn_config.encryption_type, vpn_config.key);
        Self {
            data_pack,
            data_cipher,
            vpn_config: vpn_config.clone(),
            receive_buffer: Vec::new(),
            iv,
            write_buffer: Vec::new(),
            write_semaphore: Semaphore::new(1),
            pending_packets: Vec::new(),
            pending_packets_semaphore: Semaphore::new(1),
        }
    }

    pub fn get_data(&mut self) -> Vec<u8> {
        self.pending_packets_semaphore.acquire();
        if self.pending_packets.is_empty() {
            self.pending_packets_semaphore.release();
            return Vec::new();
        }
        let start = self.receive_buffer.len();
        let packets = mem::replace(&mut self.pending_packets, Vec::new());
        let mut data = self.data_pack.post_process_data(packets);
        self.pending_packets_semaphore.release();
        let req_len =  self.data_cipher.required_buffer_size(data.len());
        let mut res_buff = Vec::with_capacity(req_len);
        unsafe{
            res_buff.set_len(req_len);
        }
        self.data_cipher.encrypt_block(&mut data, &mut res_buff, self.iv.as_bytes()).expect("Failed to encrypt data");

        res_buff
    }

    pub fn write_data(&mut self, data: &mut [u8]) {
        let mut data_buff: Vec<u8> = Vec::with_capacity(data.len());
        unsafe{
            data_buff.set_len(data.len());
        }
        let size = self.data_cipher.decrypt_block(data, &mut data_buff, self.iv.as_bytes()).expect("Error decrypting data");
        data_buff.truncate(size);
        let mut packets = self.data_pack.pre_process_data(&mut data_buff);
        data_buff.clear();
        let mut ip_packets: Vec<IpPacket> = Vec::new();
        while !packets.is_empty() {
            let packet = packets.pop().unwrap();
            if packet.packet_type == DATA_PACKET {
                ip_packets.push(IpPacket {
                    meta: TunInterface::extract_general_ip_header(packet.data.as_slice()),
                    data: packet.data,
                });
            }
        }
        self.write_semaphore.acquire();
        self.write_buffer.append(&mut ip_packets);
        self.write_semaphore.release();
    }
}

impl PacketReceiver for JniReceiver {
    fn receive_packets(&mut self, mut packet: Vec<IpPacket>) {
        self.pending_packets_semaphore.acquire();
        self.pending_packets.append(&mut packet);
        self.pending_packets_semaphore.release();
    }

    fn receive_packet(&mut self, packet: IpPacket) {
        self.pending_packets_semaphore.acquire();
        self.pending_packets.push(packet);
        self.pending_packets_semaphore.release();
    }

    fn get_packets(&mut self) -> Vec<IpPacket> {
        self.write_semaphore.acquire();
        let res = if self.write_buffer.is_empty() {
            Vec::new()
        } else {
            mem::replace(&mut self.write_buffer, Vec::new())
        };
        self.write_semaphore.release();
        res
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
