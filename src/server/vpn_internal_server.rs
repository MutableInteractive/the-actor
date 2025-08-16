use crate::operational::packet_router::{AddressTuple, PacketRouter};
use crate::vpn_config::VpnConfig;
use std::collections::HashMap;
use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;
use tfserver::util::thread_pool::ThreadPool;
use crate::front_interface::jni_receiver::JniReceiver;
use crate::server::receiver_info::ReceiverInfo;

pub struct VpnServerInternal {
    running: Arc<Mutex<AtomicBool>>,
    workgroup: Arc<Mutex<ThreadPool>>,
    router: Arc<Mutex<PacketRouter>>,
    streams_in_handle:
        Arc<Mutex<HashMap<AddressTuple, ((Arc<Mutex<TcpStream>>, Arc<Mutex<ReceiverInfo>>), Arc<Mutex<AtomicBool>>)>>>,
    config: Arc<VpnConfig>,
}

impl VpnServerInternal {
    pub fn new(
        config: Arc<VpnConfig>,
        packet_router: Arc<Mutex<PacketRouter>>,
        thread_pool: Arc<Mutex<ThreadPool>>,
    ) -> Self {
        Self {
            running: Arc::new(Mutex::new(AtomicBool::new(true))),
            streams_in_handle: Arc::new(Mutex::new(HashMap::new())),
            router: packet_router,
            workgroup: thread_pool,
            config,
        }
    }

    pub fn start(mut self_ref: Arc<Mutex<Self>>) {
        let mut running_ref = self_ref.lock().unwrap().running.clone();
        let config_ref = self_ref.lock().unwrap().config.clone();
        let router_ref = self_ref.lock().unwrap().router.clone();
        let streams_ref = self_ref.lock().unwrap().streams_in_handle.clone();
        let workgroup_ref = self_ref.lock().unwrap().workgroup.clone();
        let workgroup2 = self_ref.lock().unwrap().workgroup.clone();
        workgroup_ref.lock().unwrap().execute(move || loop {
            if !running_ref.lock().unwrap().load(Relaxed) {
                break;
            }
            streams_ref.lock().unwrap().iter().for_each(|element| {
                if !element.1 .1.lock().unwrap().load(Relaxed) {
                    let in_handle_ref = element.1 .1.clone();
                    let stream_ref = element.1 .0.0.clone();
                    let info_ref = element.1 .0.1.clone();
                    in_handle_ref.lock().unwrap().store(true, Relaxed);
                    workgroup2.lock().unwrap().execute(move || {
                        let mut receiver_info_lock = info_ref.lock().unwrap();
                        let mut data = receiver_info_lock
                            .mtu_splitter
                            .receive_data(stream_ref.lock().unwrap().by_ref());
                        let mut receiver_ref =
                            receiver_info_lock.receiver_handle.lock().unwrap();
                        let receiver = receiver_ref
                            .as_any_mut()
                            .downcast_mut::<JniReceiver>()
                            .unwrap();
                        if data.is_some() {
                            let data = data.unwrap();
                            if data.len() > 0{
                                receiver.write_data(data);
                            }
                        } else {

                        }
                        sleep(Duration::from_millis(config_ref.resyncer_timeout_ms as u64));
                        let packets = receiver.get_data();
                        if packets.
                        in_handle_ref.lock().unwrap().store(false, Relaxed);
                    });
                }
            });
        });
    }
}
