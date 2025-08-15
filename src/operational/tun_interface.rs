use cfg_if::cfg_if;
use etherparse::{InternetSlice, SlicedPacket};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use std::io;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::AsRawFd;
use tun::{AbstractDevice, Configuration, Device, ToAddress};

pub struct TunInterface {
    device: Device,
    iff_name: String,
    iff_ip: IpAddr,
    iff_netmask: IpAddr,
    buffer: Vec<u8>,
}
#[derive(Clone)]
pub struct IpPacketMeta {
    pub version: u8,
    pub source: std::net::IpAddr,
    pub destination: std::net::IpAddr,
    pub ttl_or_hop_limit: u8,
    pub identification: Option<u16>, // Only for IPv4
    pub checksum: Option<u16>,       // Only for IPv4
}
#[derive(Clone)]
pub struct IpPacket {
    pub meta: Option<IpPacketMeta>,
    pub data: Vec<u8>,
}

pub struct TunInterfaceCreateInfo {
    iff_name: Option<String>,
    iff_ip: IpAddr,
    iff_netmask: IpAddr,
}

impl TunInterfaceCreateInfo {
    pub fn iff_name(&self) -> &Option<String> {
        &self.iff_name
    }

    pub fn iff_ip(&self) -> &IpAddr {
        &self.iff_ip
    }

    pub fn iff_netmask(&self) -> &IpAddr {
        &self.iff_netmask
    }

    pub fn set_iff_name(&mut self, iff_name: String) {
        self.iff_name = Some(iff_name);
    }

    pub fn set_iff_ip(&mut self, iff_ip: &dyn ToAddress) {
        self.iff_ip = iff_ip.to_address().unwrap();
    }

    pub fn set_iff_netmask(&mut self, iff_netmask: &dyn ToAddress) {
        self.iff_netmask = iff_netmask.to_address().unwrap();
    }
}

impl Default for TunInterfaceCreateInfo {
    fn default() -> Self {
        Self {
            iff_name: None,
            iff_ip: IpAddr::from([0; 4]),
            iff_netmask: IpAddr::from([0; 4]),
        }
    }
}

impl TunInterface {
    pub fn new(create_info: &TunInterfaceCreateInfo) -> Self {
        let mut config = Configuration::default();
        config
            .address(create_info.iff_ip)
            .netmask(create_info.iff_netmask);
        if create_info.iff_name.is_some() {
            config.tun_name(create_info.iff_name.as_ref().unwrap().clone());
        }
        config.up();

        let mut res = Self {
            device: tun::create(&config).expect("Failed to create device"),
            iff_name: String::new(),
            iff_ip: create_info.iff_ip,
            iff_netmask: create_info.iff_netmask,
            buffer: vec![0u8; 65537],
        };
        cfg_if! {
        if #[cfg(unix)] {
                unsafe{
                    Self::set_non_blocking(&mut res.device).expect("Failed to set non-blocking");
                }

        }
            }
        let name = res.device.tun_name();
        if name.is_ok() {
            res.iff_name = name.unwrap();
        } else if create_info.iff_name.is_some() {
            res.iff_name = create_info.iff_name.as_ref().unwrap().clone();
        }
        res
    }

    cfg_if! {
    if #[cfg(unix)] {
    unsafe fn set_non_blocking<T: AsRawFd>(dev: &T) -> io::Result<()> {
        let fd = dev.as_raw_fd();
        let flags = fcntl(fd, FcntlArg::F_GETFL)
            .map(OFlag::from_bits_truncate)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))
            .map(|_| ())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
            }
        }

    pub fn read_packet_non_block(&mut self) -> Option<IpPacket> {
        let n_res = self.device.read(&mut self.buffer);
        if n_res.is_err() {
            return None;
        }
        let n = n_res.unwrap();
        let packet_vec: Vec<u8> = self.buffer[..n].to_vec();
        let meta = Self::extract_general_ip_header(&packet_vec);
        Some(IpPacket {
            meta,
            data: packet_vec,
        })
    }

    pub fn read(&mut self, buffer: &mut [u8]) {
        self.device.read(buffer).expect("Failed to read tun device");
    }

    pub fn write(&mut self, buffer: &[u8]) {
       
        self.device
            .write_all(buffer)
            .expect("Failed to write tun device");
    }

    pub fn extract_general_ip_header(packet: &[u8]) -> Option<IpPacketMeta> {
        match SlicedPacket::from_ip(packet) {
            Ok(parsed) => match parsed.net {
                Some(InternetSlice::Ipv4(header)) => Some(IpPacketMeta {
                    version: 4,
                    source: IpAddr::V4(Ipv4Addr::from(header.header().source())),
                    destination: IpAddr::V4(Ipv4Addr::from(header.header().destination_addr())),
                    ttl_or_hop_limit: header.header().ttl(),
                    identification: Some(header.header().identification()),
                    checksum: Some(header.header().header_checksum()),
                }),
                Some(InternetSlice::Ipv6(header)) => Some(IpPacketMeta {
                    version: 6,
                    source: IpAddr::V6(header.header().source_addr()),
                    destination: IpAddr::V6(header.header().destination_addr()),
                    ttl_or_hop_limit: header.header().hop_limit(),
                    identification: None,
                    checksum: None,
                }),
                _ => None,
            },
            Err(_) => None,
        }
    }
}
