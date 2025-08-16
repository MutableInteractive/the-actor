use std::mem;
use std::sync::atomic::{AtomicBool, Ordering};
use crate::operational::data_pack::{DataPack, DataPacket};
use crate::operational::tun_interface::{IpPacket, TunInterface, TunInterfaceCreateInfo};
use crate::vpn_config::VpnConfig;
use std::thread::sleep;
use std::time::Duration;
use tfserver::util::data_cipher::DataCipher;
use crate::util::semaphore::Semaphore;

pub struct DirectTun {
    vpn_config: VpnConfig,
    data_pack: DataPack,
    data_cipher: DataCipher,
    iv: String,
    write_buffer: Vec<DataPacket>,
    receive_buffer: Vec<u8>,
    tun_interface: TunInterface,
    write_semaphore: Semaphore,
    read_semaphore: Semaphore,
    running: AtomicBool,
}

impl DirectTun {
    pub fn new(vpn_config: VpnConfig, iv: String, ip_assigned: String, iff_name: Option<String>) -> DirectTun {
        let data_pack = DataPack::new(vpn_config.clone());
        let data_cipher = DataCipher::new_init(vpn_config.encryption_type, vpn_config.key.clone());
        let mut tun_info = TunInterfaceCreateInfo::default();
        let netmask = "255.255.255.0".to_string();
        tun_info.set_iff_ip(&ip_assigned);
        tun_info.set_iff_netmask(&netmask);
        if iff_name.is_some() {
            tun_info.set_iff_name(iff_name.unwrap());
        }
        let tun_interface = TunInterface::new(&tun_info);
        Self {
            vpn_config,
            data_pack,
            data_cipher,
            iv,
            write_buffer: Vec::new(),
            receive_buffer: Vec::new(),
            tun_interface,
            write_semaphore: Semaphore::new(1),
            read_semaphore: Semaphore::new(1),
            running: AtomicBool::new(true),
        }
    }
    
    pub fn get_packets(&mut self) -> Vec<u8>{
        let mut attempts_amount: u32 = 0;
        let mut packets: Vec<IpPacket> = Vec::new();
        while attempts_amount < self.vpn_config.max_packets_in_flight {
            let packet = self.tun_interface.read_packet_non_block();
            if packet.is_some() {
                packets.push(packet.unwrap());
            }
            sleep(Duration::from_millis(
                self.vpn_config.resyncer_timeout_ms as u64,
            ));
            attempts_amount += 1;
        }
        let mut data = self.data_pack.post_process_data(packets);
        let req_len = self.data_cipher.required_buffer_size(data.len());
        let mut res_buff: Vec<u8> = Vec::with_capacity(req_len);
        unsafe{
            res_buff.set_len(req_len);
        };
        self.data_cipher.encrypt_block(&mut data, &mut res_buff, self.iv.as_bytes()).unwrap();
        res_buff
    }
    
    pub fn write_data(&mut self, mut data: Vec<u8>) {
        let mut res_buffer = Vec::with_capacity(data.len());
        unsafe{
            res_buffer.set_len(data.len());
        }
        let size = self.data_cipher.decrypt_block(data.as_slice(), &mut res_buffer,self.iv.as_bytes()).expect("Failed to decrypt data");
        res_buffer.truncate(size);
        let mut data = self.data_pack.pre_process_data(res_buffer.as_slice());
        data.iter().for_each(|x|{
            self.tun_interface.write(x.data.data.as_slice());
        })
    }
    

    
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }

}
