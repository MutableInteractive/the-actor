use std::any::Any;
use crate::operational::tun_interface::{IpPacket, TunInterface};
use crate::util::semaphore::Semaphore;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::DerefMut;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;

pub trait PacketReceiver: Any + Send {
    fn receive_packets(&mut self, packet: Vec<IpPacket>);
    fn receive_packet(&mut self, packet: IpPacket);
    fn get_packets(&mut self) -> Vec<IpPacket>;

    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

pub struct PacketRouterCreateInfo {
    pub router_subnet: Ipv4Addr,
    pub router_subnet_ipv6: Ipv6Addr,
    pub tun_interface: Arc<Mutex<TunInterface>>,
    pub resyncer_timeout: Duration,
    pub max_packets_attempts_amount: u32,
}
#[derive(Clone)]
pub struct AddressTuple {
    pub ip: Ipv4Addr,
    pub ip6: Ipv6Addr,
    pub network_id: u8,
}

impl AddressTuple {
    pub fn new(ip: Ipv4Addr) -> Self {
        Self {
            ip,
            ip6: Ipv6Addr::from([0; 16]),
            network_id: ip.octets()[3],
        }
    }
    pub fn new6(ip: Ipv6Addr) -> Self {
        let subnet_mask: u128 = (1 << 64) - 1;
        let id = (ip.to_bits() & subnet_mask) as u64;
        Self {
            ip: Ipv4Addr::from([0; 4]),
            ip6: ip,
            network_id: id as u8,
        }
    }
    pub fn new_addr(ip: &IpAddr) -> Self {
        let res = match ip {
            IpAddr::V4(v4) => Self::new(v4.clone()),
            IpAddr::V6(v6) => Self::new6(v6.clone()),
        };
        res
    }

    pub fn new_full(ip: Ipv4Addr, ip6: Ipv6Addr) -> Self {
        let network_id = ip.octets()[3];
        Self {
            ip,
            ip6,
            network_id
        }
    }
}

impl PartialEq<Self> for AddressTuple {
    fn eq(&self, other: &Self) -> bool {
        if other.ip == self.ip {
            return true;
        } else if other.ip6 == self.ip6 {
            return true;
        } else {
            false
        }
    }
}

impl Hash for AddressTuple {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.network_id.hash(state);
    }
}

impl Eq for AddressTuple {}

pub struct PacketRouter {
    registered_addresses: HashMap<AddressTuple, Arc<Mutex<dyn PacketReceiver>>>,
    router_subnet: Ipv4Addr,
    router_subnet_ipv6: Ipv6Addr,
    subnet_counter: u8,
    free_addresses: Vec<AddressTuple>,
    interface: Arc<Mutex<TunInterface>>,
    resyncer_timeout: Duration,
    max_packets_attempts_amount: u32,
    receiver_semaphore: Semaphore,
}

impl PacketRouter {
    pub fn new(create_info: PacketRouterCreateInfo) -> PacketRouter {
        Self {
            registered_addresses: HashMap::new(),
            router_subnet: create_info.router_subnet,
            subnet_counter: 2,
            interface: create_info.tun_interface,
            resyncer_timeout: create_info.resyncer_timeout,
            max_packets_attempts_amount: create_info.max_packets_attempts_amount,
            router_subnet_ipv6: create_info.router_subnet_ipv6,
            receiver_semaphore: Semaphore::new(1),
            free_addresses: Vec::new(),
        }
    }

    pub fn register(
        &mut self,
        receiver: Arc<Mutex<dyn PacketReceiver>>,
    ) -> (Ipv4Addr, Ipv6Addr, Arc<Mutex<dyn PacketReceiver>>) {
        let tupple: AddressTuple = if self.free_addresses.is_empty() {
            let addr = Ipv4Addr::new(
                self.router_subnet.octets()[0],
                self.router_subnet.octets()[1],
                self.router_subnet.octets()[2],
                self.subnet_counter,
            );
            let base_segments = self.router_subnet_ipv6.segments();
            let network_prefix = ((base_segments[0] as u128) << 112)
                | ((base_segments[1] as u128) << 96)
                | ((base_segments[2] as u128) << 80)
                | ((base_segments[3] as u128) << 64);

            let full_addr = network_prefix | (self.subnet_counter as u128);
            let addr6 = Ipv6Addr::from(full_addr);
            AddressTuple {
                ip: addr,
                ip6: addr6,
                network_id: self.subnet_counter,
            }
        } else {
            self.free_addresses.pop().unwrap()
        };

        self.receiver_semaphore.acquire();
        self.registered_addresses.insert(tupple.clone(), receiver.clone());
        self.subnet_counter += 1;
        let res = (
            tupple.ip,
            tupple.ip6,
            receiver.clone(),
        );
        self.receiver_semaphore.release();
        res
    }

    pub fn deregister(&mut self, addr: Ipv4Addr) {
        let mut tupple = AddressTuple::new(addr);
        self.receiver_semaphore.acquire();
        let val = self.registered_addresses.remove(&tupple);
        let base_segments = self.router_subnet_ipv6.segments();
        let network_prefix = ((base_segments[0] as u128) << 112)
            | ((base_segments[1] as u128) << 96)
            | ((base_segments[2] as u128) << 80)
            | ((base_segments[3] as u128) << 64);

        let full_addr = network_prefix | (tupple.network_id as u128);
        let addr6 = Ipv6Addr::from(full_addr);
        tupple.ip6 = addr6;
        self.free_addresses.push(tupple);
        self.receiver_semaphore.release();
    }

    pub fn receive_packets(&mut self) {
        let mut interface = self.interface.lock().expect("Lock failed");
        let mut packets: HashMap<IpAddr, Vec<IpPacket>> = HashMap::new();
        let mut attempt_counter = 0;
        self.receiver_semaphore.acquire();
        while attempt_counter < self.max_packets_attempts_amount as usize {
            let packet = interface.read_packet_non_block();
            if packet.is_some() {
                let packet = packet.unwrap();
                if packet.meta.is_some() {
                    let key = packet.meta.as_ref().unwrap().destination.clone();
                    let tupple = AddressTuple::new_addr(&key);
                    let rec = self.registered_addresses.get_mut(&tupple);
                    if rec.is_some(){
                        let mut rec = rec.unwrap().lock().unwrap();
                        rec.receive_packet(packet);
                    }
                }
            }
            if self.resyncer_timeout.as_nanos() > 0{
                sleep(self.resyncer_timeout);
            }
            attempt_counter += 1;
        }
        self.receiver_semaphore.release();

    }
    pub fn write_packets(&mut self) {
        let mut interface = self.interface.lock().expect("Failed to lock interface");
        self.receiver_semaphore.acquire();
        self.registered_addresses
            .iter_mut()
            .for_each(|(key, receiver)| {
                receiver.lock().unwrap().get_packets().iter().for_each(|packet| {
                    interface.write(packet.data.as_slice());
                })
            });
        self.receiver_semaphore.release();
    }
}
