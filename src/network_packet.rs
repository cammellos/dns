use crate::dns_parser::ConnectionInfo;
use crate::protocol::network_packet::NetworkPacket;

use std::error::Error;
use std::net::{SocketAddrV4, UdpSocket};

pub struct ConnectCommand {
    proxy: ConnectionInfo,
    target: ConnectionInfo,
}

impl ConnectCommand {
    pub fn new(proxy: ConnectionInfo, target: ConnectionInfo) -> ConnectCommand {
        ConnectCommand { proxy, target }
    }
    pub fn send(&self) -> Result<(), Box<dyn Error>> {
        let bytes = NetworkPacket::from_connection_info(&self.target).to_network();
        let socket_addr: SocketAddrV4;
        match self.proxy {
            ConnectionInfo::Ipv4 { address, port } => {
                socket_addr = SocketAddrV4::new(address, port);
            }
            _ => return Err("Unsupported connection info".into()),
        }
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.send_to(&bytes, socket_addr)?;
        Ok(())
    }
}

pub fn Connect(info: ConnectionInfo) {}
