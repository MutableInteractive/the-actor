use crate::util::rand_utils::generate_random_u8_vec;
use crate::operational::tun_interface::IpPacket;
use crate::vpn_config::VpnConfig;
use rand::random_range;
use serde::{Deserialize, Serialize};

pub const DATA_PACKET: u8 = 0;
pub const GARBAGE_PACKET: u8 = 1;
pub const SYSTEM_PACKET: u8 = 2;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct DataPacket {
    pub packet_type: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct DataPackData {
    pub packets: Vec<DataPacket>,
}

pub struct DataPack {
    vpn_config: VpnConfig,
}

impl DataPack {
    pub fn new(config: VpnConfig) -> DataPack {
        Self{vpn_config: config}
    }

    pub fn post_process_data(&self, mut packets: Vec<IpPacket>) -> Vec<u8> {
        let mut res_packets = Vec::new();
        let mut garbage_packet_counter = 0;
        let garbage_amount = random_range(
            self.vpn_config.min_garbage_packets_amount..self.vpn_config.max_garbage_packets_amount,
        );
        while packets.len() > 0 {
            let packet: IpPacket = packets.pop().unwrap();
            let packed_data = DataPacket {
                packet_type: DATA_PACKET,
                data: packet.data,
            };
            res_packets.push(packed_data);

            if garbage_packet_counter < garbage_amount {
                res_packets.push(Self::generate_garbage_packet(random_range(
                    self.vpn_config.garbage_packet_min_size
                        ..self.vpn_config.garbage_packet_max_size,
                )));
                garbage_packet_counter += 1;
            }
        }
        while garbage_packet_counter < garbage_amount {
            res_packets.push(Self::generate_garbage_packet(random_range(
                self.vpn_config.garbage_packet_min_size..self.vpn_config.garbage_packet_max_size,
            )));
            garbage_packet_counter += 1;
        }
        let data_pack = DataPackData { packets: res_packets };
        rmp_serde::to_vec(&data_pack).expect("Serialization failed")
    }

    pub fn pre_process_data(&self, data: &[u8]) -> Vec<DataPacket> {
        let mut data: DataPackData = rmp_serde::from_slice(data).expect("Deserialization failed");
        let mut res_packets = Vec::new();
        for i in 0..data.packets.len() {
            if data.packets[i].packet_type != GARBAGE_PACKET {
                res_packets.push(data.packets[i].clone());
            }
        }
        res_packets
    }

    fn generate_garbage_packet(packet_size: u64) -> DataPacket {
        let data = generate_random_u8_vec(packet_size as usize);
        DataPacket {
            packet_type: GARBAGE_PACKET,
            data,
        }
    }
}
