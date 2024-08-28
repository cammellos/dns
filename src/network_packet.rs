use crate::constants::MAX_DNS_PACKET_SIZE;
use crate::dns_parser::ConnectionInfo;
use rand::Rng;
use std::error::Error;
use std::net::{SocketAddrV4, UdpSocket};

pub struct NetworkPacket<'a> {
    connection_info: &'a ConnectionInfo,
}

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

impl NetworkPacket<'_> {
    pub fn from_connection_info(info: &ConnectionInfo) -> NetworkPacket {
        NetworkPacket {
            connection_info: info,
        }
    }

    fn set_id(v: &mut Vec<u8>) {
        let mut rng = rand::thread_rng();
        let mut num: u16;
        loop {
            num = rng.gen();
            if num != 0 {
                break;
            }
        }

        let bytes = num.to_be_bytes();

        v.push(bytes[0]);
        v.push(bytes[1]);
    }

    pub fn to_network(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(MAX_DNS_PACKET_SIZE);

        NetworkPacket::set_id(&mut result);

        // flags
        result.push(0x01); // set query bit
        result.push(0x00);

        result.push(0x00);
        result.push(0x01); // one question

        // pad rest empty
        result.push(0x00);
        result.push(0x00);
        result.push(0x00);
        result.push(0x00);
        result.push(0x00);
        result.push(0x00);

        let info_bytes = self.connection_info.to_network();
        for item in info_bytes {
            result.push(item)
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::constants::{
        MAX_DNS_PACKET_SIZE, NETWORK_ADDRESS_TYPE_IPV4, NETWORK_ADDRESS_TYPE_IPV6,
    };
    use crate::dns_parser::ConnectionInfo;
    use crate::network_packet::NetworkPacket;

    #[test]
    fn test_network_packet_from_connection_info_ipv4() {
        let connection_info = ConnectionInfo::Ipv4 {
            address: Ipv4Addr::new(192, 168, 1, 2),
            port: 8080,
        };

        let network_packet = NetworkPacket::from_connection_info(&connection_info);
        let network_bytes = network_packet.to_network();

        assert!(network_bytes.len() < MAX_DNS_PACKET_SIZE);
        assert!(!network_bytes.is_empty());
        assert!(network_bytes[0] != 0 || network_bytes[1] != 0);

        assert_eq!(network_bytes[2], 0x01);
        assert_eq!(network_bytes[3], 0x00);
        assert_eq!(network_bytes[4], 0x00);
        assert_eq!(network_bytes[5], 0x01); // one question
        assert_eq!(network_bytes[6], 0x00);
        assert_eq!(network_bytes[7], 0x00);
        assert_eq!(network_bytes[8], 0x00);
        assert_eq!(network_bytes[9], 0x00);
        assert_eq!(network_bytes[10], 0x00);
        assert_eq!(network_bytes[11], 0x00);

        assert_eq!(network_bytes[12], 7);
        assert_eq!(network_bytes[13], NETWORK_ADDRESS_TYPE_IPV4);
        assert_eq!(network_bytes[14], 192);
        assert_eq!(network_bytes[15], 168);
        assert_eq!(network_bytes[16], 1);
        assert_eq!(network_bytes[17], 2);
        assert_eq!(network_bytes[18], 0x1f);
        assert_eq!(network_bytes[19], 0x90);
    }

    #[ignore]
    #[test]
    fn test_network_packet_from_connection_info_ipv6() {
        let connection_info = ConnectionInfo::Ipv6 {
            address: Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8),
            port: 8080,
        };

        let network_packet = NetworkPacket::from_connection_info(&connection_info);
        let network_bytes = network_packet.to_network();

        assert!(network_bytes.len() < MAX_DNS_PACKET_SIZE);
        assert!(!network_bytes.is_empty());
        assert!(network_bytes[0] != 0 || network_bytes[1] != 0);

        assert_eq!(network_bytes[2], 0x01);
        assert_eq!(network_bytes[3], 0x00);
        assert_eq!(network_bytes[4], 0x01); // one question
        assert_eq!(network_bytes[5], 0x00);
        assert_eq!(network_bytes[6], 0x00);
        assert_eq!(network_bytes[7], 0x00);
        assert_eq!(network_bytes[8], 0x00);
        assert_eq!(network_bytes[9], 0x00);
        assert_eq!(network_bytes[10], 0x00);
        assert_eq!(network_bytes[11], 0x00);

        assert_eq!(network_bytes[12], NETWORK_ADDRESS_TYPE_IPV6);
        assert_eq!(network_bytes[13], 1);
        assert_eq!(network_bytes[14], 2);
        assert_eq!(network_bytes[15], 3);
        assert_eq!(network_bytes[16], 4);
        assert_eq!(network_bytes[17], 5);
        assert_eq!(network_bytes[18], 6);
        assert_eq!(network_bytes[19], 7);
        assert_eq!(network_bytes[20], 8);
        assert_eq!(network_bytes[21], 0x1f);
        assert_eq!(network_bytes[22], 0x90);
    }

    #[ignore]
    #[test]
    fn test_network_packet_from_connection_info_domain_name() {
        assert_eq!(1, 2);
    }
}
