use std::fmt;
use std::fmt::Write;
use rand::random_range;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use tfserver::bincode;

use crate::util::rand_utils::generate_random_u8_vec;
use crate::operational::tun_interface::IpPacket;
use crate::vpn_config::VpnConfig;

use tfserver::structures::s_type;
use tfserver::structures::s_type::BINCODE_CFG;

pub const DATA_PACKET: u8 = 0;
pub const GARBAGE_PACKET: u8 = 1;
pub const SYSTEM_PACKET: u8 = 2;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize,)]
pub struct BytesBuff{
    pub data: Vec<u8>,
}

impl BytesBuff {
    pub fn new(data: Vec<u8>) -> Self {
        Self{data}
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct DataPacket {
    pub packet_type: u8,
    pub(crate) data: BytesBuff
}


pub struct DataPack {
    vpn_config: VpnConfig,
}

impl DataPack {
    pub fn new(config: VpnConfig) -> DataPack {
        Self{vpn_config: config}
    }

    pub fn post_process_data(&self, mut packets: Vec<IpPacket>) -> Vec<u8> {
        let mut data = Vec::new();
        let mut garbage_packet_counter = 0;
        let garbage_amount = random_range(
            self.vpn_config.min_garbage_packets_amount..self.vpn_config.max_garbage_packets_amount,
        );
        while packets.len() > 0 {
            let current_roll = rand::random_range(0..2);
            if current_roll == 0 &&  garbage_packet_counter < garbage_amount {
                let packet = Self::generate_garbage_packet(random_range(
                    self.vpn_config.garbage_packet_min_size..self.vpn_config.garbage_packet_max_size,
                ));

                let mut temp_data = bincode::serde::encode_to_vec(&packet, BINCODE_CFG.clone()).expect("Failed to serialize packet data");
                let length_bytes: u32 = temp_data.len() as u32;
                let length_bytes: [u8; 4] = length_bytes.to_be_bytes();
                length_bytes.iter().for_each(|&x| data.push(x));
                data.append(&mut temp_data);
                garbage_packet_counter += 1;
            } else {
                let packet: IpPacket = packets.pop().unwrap();
                let packed_data = DataPacket {
                    packet_type: DATA_PACKET,
                    data: BytesBuff::new(packet.data),
                };
                let mut temp_data = bincode::serde::encode_to_vec(&packed_data, BINCODE_CFG.clone()).expect("Failed to serialize packet data");
                let length_bytes: u32 = temp_data.len() as u32;
                let length_bytes: [u8; 4] = length_bytes.to_be_bytes();
                length_bytes.iter().for_each(|&x| data.push(x));
                data.append(&mut temp_data);
            }
        }
        while garbage_packet_counter < garbage_amount {
            let packet = Self::generate_garbage_packet(random_range(
                self.vpn_config.garbage_packet_min_size..self.vpn_config.garbage_packet_max_size,
            ));
            let mut temp_data = bincode::serde::encode_to_vec(&packet, BINCODE_CFG.clone()).expect("Failed to serialize packet data");
            let length_bytes: u32 = temp_data.len() as u32;
            let length_bytes: [u8; 4] = length_bytes.to_be_bytes();
            length_bytes.iter().for_each(|&x| data.push(x));
            data.append(&mut temp_data);
            garbage_packet_counter += 1;
        }
        data
    }

    pub fn pre_process_data(&self, data: &[u8]) -> Vec<DataPacket> {
        let mut res_packets: Vec<DataPacket> = Vec::new();
        let mut i: u64 = 0;
        while i < data.len() as u64 {
            let length_bytes: [u8;4] = data[i as usize..i as usize+4].try_into().unwrap();
            let length = u32::from_be_bytes(length_bytes);
            if length > data.len() as u32 {
                return res_packets;
            }

            let start = i as usize+4;
            let end = start + length as usize;

            let data_packet: DataPacket = bincode::serde::decode_from_slice(&data[start..end], BINCODE_CFG.clone()).unwrap().0;
            if data_packet.packet_type != GARBAGE_PACKET{
                res_packets.push(data_packet);
            }
            i = i+4+(length as u64);
        }
        res_packets
    }

    fn generate_garbage_packet(packet_size: u64) -> DataPacket {
        let data = generate_random_u8_vec(packet_size as usize);
        DataPacket {
            packet_type: GARBAGE_PACKET,
            data: BytesBuff::new(data),
        }
    }
}
