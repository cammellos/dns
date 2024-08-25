use std::io;
use std::net::{SocketAddr, UdpSocket};

pub struct UdpServer {
    socket: UdpSocket,
    port: u16,
}

impl UdpServer {
    pub fn new() -> io::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let local_addr = socket.local_addr()?;
        let port = local_addr.port();

        Ok(Self { socket, port })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn start(&self) -> io::Result<()> {
        loop {
            let (message, src_addr) = self.receive_message()?;
            let message_str = String::from_utf8_lossy(&message);

            println!("Received message: '{}' from {}", message_str, src_addr);

            let response = b"Message received";
            self.send_message(response, src_addr)?;
        }
    }

    fn receive_message(&self) -> io::Result<(Vec<u8>, SocketAddr)> {
        let mut buf = [0u8; 1024]; // Adjust size as needed
        let (size, src_addr) = self.socket.recv_from(&mut buf)?;
        let message = buf[..size].to_vec();
        Ok((message, src_addr))
    }

    fn send_message(&self, message: &[u8], addr: SocketAddr) -> io::Result<()> {
        self.socket.send_to(message, addr)?;
        Ok(())
    }
}

fn main() -> io::Result<()> {
    let server = UdpServer::new()?;
    println!("Server listening on port {}", server.port());
    server.start() // Start the server and enter the event loop
}
