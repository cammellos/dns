use crate::constants::MAX_DNS_PACKET_SIZE;
use crate::dns_parser::{extract_dns_payload, ConnectionHeader};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::net::UdpSocket;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;

pub struct UdpServer {
    running: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    socket: Arc<Mutex<UdpSocket>>,
}

impl UdpServer {
    pub fn new() -> UdpServer {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("Could not bind socket");
        socket
            .set_nonblocking(true)
            .expect("Could not set non-blocking");
        UdpServer {
            running: Arc::new(AtomicBool::new(false)),
            handle: None,
            socket: Arc::new(Mutex::new(socket)),
        }
    }

    pub fn start(&mut self) {
        let running = self.running.clone();
        let socket = self.socket.clone();

        self.handle = Some(thread::spawn(move || {
            running.store(true, Ordering::SeqCst);
            let mut buf = [0; 1024];

            while running.load(Ordering::SeqCst) {
                if let Ok((size, src)) = socket.lock().unwrap().recv_from(&mut buf) {
                    let received_data: [u8; MAX_DNS_PACKET_SIZE] =
                        buf[..MAX_DNS_PACKET_SIZE].try_into().unwrap();
                    println!("Received from {}: {:?}", src, received_data);
                    println!(
                        "Extracted: {:?}",
                        extract_dns_payload(&received_data).to_vec()
                    );
                    let header_result =
                        ConnectionHeader::from_network(extract_dns_payload(&received_data));
                    match header_result {
                        Ok(header) => {
                            println!("successfully parsed header: {:?}", header);
                            let socket = header.socket_address();
                            let mut stream_result = TcpStream::connect(socket);
                            match stream_result {
                                Ok(mut stream) => {
                                    let mut buffer = [0; 512];
                                    match stream.read(&mut buffer) {
                                        Ok(n) => {
                                            println!(
                                                "Received: {}",
                                                String::from_utf8_lossy(&buffer[..n])
                                            );
                                        }
                                        Err(e) => {
                                            println!("Failed to read from TCP stream: {}", e);
                                        }
                                    }
                                }
                                Err(err) => {
                                    println!("failed to connect to tcp: {}", err);
                                }
                            }
                        }
                        Err(error) => {
                            println!("failed to parse header: {}", error);
                        }
                    }
                } else {
                    // Sleep for a short time to avoid busy-waiting
                    thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }));
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            handle.join().expect("Failed to join server thread");
        }
    }

    pub fn port(&self) -> u16 {
        self.socket.lock().unwrap().local_addr().unwrap().port()
    }
}
