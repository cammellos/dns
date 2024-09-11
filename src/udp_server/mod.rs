use log;

use std::collections::HashMap;
use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::constants::{DNS_HEADER_SIZE, MAX_DNS_PACKET_SIZE};
use crate::dns_parser::{
    extract_dns_payload, wrap_ack, wrap_answer, ConnectionHeader, ConnectionInfo, ParsedData,
};

struct PacketReceiver {
    next_sequence_number: u8,
    last_sequence_number: u8,
    packets: HashMap<u8, TargetToClientPacket>,
}

impl PacketReceiver {
    pub fn new(next_sequence_number: u8) -> PacketReceiver {
        PacketReceiver {
            next_sequence_number,
            last_sequence_number: next_sequence_number,
            packets: HashMap::new(),
        }
    }

    pub fn process(&mut self, packet: TargetToClientPacket) -> Option<Vec<&TargetToClientPacket>> {
        let mut sequence_number = packet.sequence_number;
        log::debug!("processing packet: {}", packet.sequence_number);
        let mut result = vec![];
        self.add(packet);

        if sequence_number > self.last_sequence_number {
            log::debug!("setting last sequence number: {}", sequence_number);
            self.last_sequence_number = sequence_number;
        }
        if sequence_number != self.next_sequence_number {
            log::debug!(
                "packet out of order: is {} expecting {}",
                sequence_number,
                self.next_sequence_number,
            );
            return None;
        }
        log::debug!("retrieving the rest of the packets");
        while let Some(next_packet) = self.packets.get(&sequence_number) {
            log::debug!(
                "packet {} found, adding to result",
                next_packet.sequence_number
            );
            sequence_number += 1;
            result.push(next_packet);
        }
        self.next_sequence_number = sequence_number;
        log::debug!("found all packets, increasing next sequence number");
        return Some(result);
    }

    fn add(&mut self, packet: TargetToClientPacket) {
        self.packets.insert(packet.sequence_number, packet);
    }

    fn get(&self, id: u8) -> Option<&TargetToClientPacket> {
        self.packets.get(&id)
    }

    fn delete(&mut self, id: u8) {
        self.packets.remove(&id);
    }
}

struct ConnectionParams<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    client_target_stream: S,
    transaction_id: u8,
    initial_sequence_number: u8,
    connection_id: String,
    client_to_target_receiver: mpsc::Receiver<TargetToClientPacket>,
    target_to_client_sender: mpsc::Sender<TargetToClientPacket>,
}

// ConnectionHandler manages a single TCP connection.
//
struct ConnectionHandler<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    params: ConnectionParams<S>,
    packet_receiver: PacketReceiver,
}

// 1) Wait on the tcp connection and send back
// 2) Wait on a channel and send forward
// 3) Close connection if either are closed
impl<S> ConnectionHandler<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(params: ConnectionParams<S>) -> Self {
        let next_sequence_number = params.initial_sequence_number + 1;
        Self {
            params,
            packet_receiver: PacketReceiver::new(next_sequence_number),
        }
    }

    pub async fn connect(
        target: ConnectionInfo,
        client_to_target_receiver: mpsc::Receiver<TargetToClientPacket>,
        target_to_client_sender: mpsc::Sender<TargetToClientPacket>,
        transaction_id: u8,
        initial_sequence_number: u8,
        connection_id: String,
    ) -> Result<(), String> {
        match target.connect().await {
            Ok(client_target_stream) => {
                tokio::spawn(async move {
                    let params = ConnectionParams {
                        client_target_stream,
                        connection_id,
                        transaction_id,
                        initial_sequence_number,
                        client_to_target_receiver,
                        target_to_client_sender,
                    };
                    ConnectionHandler::new(params).start().await;
                });
                Ok(())
            }
            Err(e) => {
                log::error!("error connecting: {}", e);
                Err(e.to_string())
            }
        }
    }

    async fn start(mut self) {
        log::debug!(
            "starting connection handler: {}",
            self.params.transaction_id
        );
        loop {
            let mut buffer = vec![0u8; 512];
            tokio::select! {
                message = self.params.client_to_target_receiver.recv() => {
                log::debug!("received packet to forward to target");
                    if let Some(msg) = message {
                        let ack = TargetToClientPacket{
                            connection_id: self.params.connection_id.clone(),
                            sequence_number: msg.sequence_number,
                            data: wrap_ack(self.params.transaction_id, msg.sequence_number),
                        };
                        let process_result = self.packet_receiver.process(msg);
                    log::debug!("acking packet: {}", ack.sequence_number);
                    self.params.target_to_client_sender.send(ack).await.unwrap();

                    if process_result.is_none() {
                        continue;
                    }

                    for packet in process_result.unwrap() {
                        if let Err(e) = self.params.client_target_stream.write_all(&packet.data).await {
                            log::error!("failed to write to stream: {}", e);
                            return;
                        }

                    }

                } else {
                        // The sender has closed, end the connection
                        log::debug!("sender closed the channel, ending connection.");
                        return;
                    }

                }
                result = self.params.client_target_stream.read(&mut buffer) => match result {
                    Ok(n) if n > 0 => {

                        log::debug!("received: {} {}, passing back", String::from_utf8_lossy(&buffer[..n]), n);
                        let sequence_number = 0x23;
                        let packet = TargetToClientPacket{
                            connection_id: self.params.connection_id.clone(),
                            sequence_number,
                            data: wrap_answer(self.params.transaction_id, sequence_number, &buffer[0..n]),
                        };
                        self.params.target_to_client_sender.send(packet).await.unwrap();
                    }
                    Ok(_) => {
                        log::debug!("connection closed");
                        return
                    }
                    Err(e) => {
                        match e.kind() {
                            std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock => {
                                log::warn!("non critical error, continuing: {}", e);
                                continue;
                            }
                            _ => {
                                log::error!("failed to read: {}", e);
                            }
                        }
                        return
                    }
                }
            }
        }
    }
}

struct TargetToClientPacket {
    connection_id: String,
    sequence_number: u8,
    data: Vec<u8>,
}

#[derive(Debug)]
struct Connection {
    client_to_target_sender: mpsc::Sender<TargetToClientPacket>,
    transaction_id: u8,
    src: SocketAddr,
}

struct ConnectionManager {
    connections: HashMap<String, Connection>,
}

impl ConnectionManager {
    pub fn new() -> ConnectionManager {
        ConnectionManager {
            connections: HashMap::new(),
        }
    }

    pub fn add(&mut self, id: String, connection: Connection) {
        self.connections.insert(id, connection);
    }

    pub fn get(&self, id: &str) -> Option<&Connection> {
        self.connections.get(id)
    }

    pub fn delete(&mut self, id: &str) {
        self.connections.remove(id);
    }
}

// UdpServer listens for incoming UDP packets.
pub struct UdpServer {
    socket: UdpSocket,
}

#[derive(Debug)]
enum Command {
    NewConnection {
        connection_id: String,
        transaction_id: u8,
        initial_sequence_number: u8,
        header: ConnectionHeader,
    },
    ExistingConnection {
        connection_id: String,
    },
}

fn src_and_transaction_id_to_string(src: SocketAddr, transaction_id: u8) -> String {
    return format!("{}-{}", src.to_string(), transaction_id.to_string());
}

impl UdpServer {
    pub async fn new() -> UdpServer {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("Could not bind socket");
        UdpServer { socket: socket }
    }

    fn parse_received_data(
        connection_manager: &ConnectionManager,
        buf: &[u8],
        size: usize,
        src: SocketAddr,
    ) -> Result<Command, String> {
        let mut received_data: [u8; MAX_DNS_PACKET_SIZE] = [0; MAX_DNS_PACKET_SIZE];
        received_data[..size].copy_from_slice(&buf[..size]);
        log::trace!("received from {}: {:?}", src, received_data);

        let parsed_data: ParsedData;
        match extract_dns_payload(&received_data) {
            Some(data) => parsed_data = data,
            None => return Err("failed to parse payload".to_string()),
        }

        let payload = parsed_data.payload;
        let transaction_id = parsed_data.transaction_id;
        let initial_sequence_number = parsed_data.sequence_number;
        let connection_id = src_and_transaction_id_to_string(src, transaction_id);

        let connection_result = connection_manager.get(&connection_id);
        match connection_result {
            Some(_) => return Ok(Command::ExistingConnection { connection_id }),
            None => {}
        }

        log::debug!("extracted: {:?}", payload.to_vec());

        let header_result = ConnectionHeader::from_network(payload);
        match header_result {
            Ok(header) => {
                log::debug!("successfully parsed header: {:?}", header.info);

                Ok(Command::NewConnection {
                    header,
                    connection_id,
                    initial_sequence_number,
                    transaction_id,
                })
            }
            Err(error) => Err(format!("failed to parse header: {}", error)),
        }
    }

    async fn handle_new_connection(
        target: ConnectionInfo,
        client_to_target_receiver: mpsc::Receiver<TargetToClientPacket>,
        target_to_client_sender: mpsc::Sender<TargetToClientPacket>,
        transaction_id: u8,
        initial_sequence_number: u8,
        connection_id: String,
    ) {
        let connection_string = format!("target: {:?}", target);
        log::debug!("connecting to: {}", connection_string);

        // Use the new `ConnectionHandler::connect` method
        match ConnectionHandler::<tokio::net::TcpStream>::connect(
            target,
            client_to_target_receiver,
            target_to_client_sender,
            transaction_id,
            initial_sequence_number,
            connection_id,
        )
        .await
        {
            Ok(_) => log::debug!("connected to: {:?}", connection_string),
            Err(e) => log::error!("failed to connect to: {},  error: {}", connection_string, e),
        }
    }

    async fn handle_new_packet(
        connection_manager: &mut ConnectionManager,
        buf: &[u8],
        size: usize,
        src: SocketAddr,
        target_to_client_sender: mpsc::Sender<TargetToClientPacket>,
    ) -> Result<(), String> {
        log::debug!("new packet received");
        match UdpServer::parse_received_data(connection_manager, buf, size, src) {
            Ok(Command::ExistingConnection { connection_id }) => {
                log::debug!("existing connection, sending packet forward: {}", size);
                if let Some(connection) = connection_manager.get(&connection_id) {
                    connection
                        .client_to_target_sender
                        .send(TargetToClientPacket {
                            connection_id,
                            sequence_number: buf[1],
                            data: buf[DNS_HEADER_SIZE..size].to_vec(),
                        })
                        .await
                        .map_err(|e| format!("Failed to send data: {}", e))?;
                    log::debug!("sent packet forward");
                }
            }
            Ok(Command::NewConnection {
                transaction_id,
                connection_id,
                initial_sequence_number,
                header,
            }) => {
                log::debug!("new connection: {}", connection_id);
                let connection_id_copy = connection_id.clone();
                let (client_to_target_sender, client_to_target_receiver) = mpsc::channel(32);

                let connection = Connection {
                    transaction_id,
                    src,
                    client_to_target_sender,
                };

                connection_manager.add(connection_id, connection);

                tokio::spawn(UdpServer::handle_new_connection(
                    header.info,
                    client_to_target_receiver,
                    target_to_client_sender,
                    transaction_id,
                    initial_sequence_number,
                    connection_id_copy,
                ));
            }
            Err(e) => {
                return Err(format!("Failed to handle received data: {}", e));
            }
        }
        Ok(())
    }

    pub async fn start(&self) {
        let mut connection_manager = ConnectionManager::new();
        let mut buf = vec![0u8; MAX_DNS_PACKET_SIZE];
        let (target_to_client_sender, mut target_to_client_receiver) = mpsc::channel(32);

        loop {
            tokio::select! {
            result = self.socket.recv_from(&mut buf) => {
                match result {
                    Ok((size, src)) => {
                        if let Err(e) = UdpServer::handle_new_packet(
                            &mut connection_manager,
                            &buf,
                            size,
                            src,
                            target_to_client_sender.clone(),
                        )
                        .await
                        {
                            log::error!("failed to handle socket data: {}", e);
                        }
                    }
                    Err(e) => {
                        log::error!("failed to receive data: {}", e);
                    }
                }
            }
                Some(message) = target_to_client_receiver.recv() => {
                    let connection_id = message.connection_id;
                    let connection_result = connection_manager.get(&connection_id);
                    log::info!("received message on channel: {:?}", message.data);
                    match connection_result  {
                        Some(connection) => {
                            log::debug!("connection found: {}", connection_id);
                            let bytes_sent_result = self.socket.send_to(&message.data, connection.src).await;
                                match bytes_sent_result {
                                  Ok(bytes_sent) =>  log::debug!("sent {} to {}", bytes_sent, connection.src),
                                  Err(e) => log::error!("failed to send to {} with error: {}", connection.src, e),
                                }
                        }
                        None => {
                            log::warn!("connection not found: {}", connection_id);
                        }
                    }
                }
            }
        }
    }

    pub fn port(&self) -> u16 {
        self.socket.local_addr().unwrap().port()
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;
    use std::io::Error;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;
    use tokio::time::{timeout, Duration};
    use tokio_test::io::Builder;

    use test_log::test;

    use crate::dns_parser::{extract_dns_payload_from_answer, is_ack, wrap_query, ConnectionInfo};
    use crate::network_packet::NetworkPacket;
    use crate::udp_server::{
        src_and_transaction_id_to_string, Command, Connection, ConnectionHandler,
        ConnectionManager, ConnectionParams, PacketReceiver, TargetToClientPacket, UdpServer,
    };

    #[test(tokio::test)]
    async fn test_connection_handler_start() {
        let client_target_stream = Builder::new()
            .read(b"hello") // Simulate the stream reading "hello"
            .write(b"response1") // Expect the handler to write "response1"
            .read(b"hello2")
            .build();

        let (client_to_target_sender, client_to_target_receiver) = mpsc::channel(32);
        let (target_to_client_sender, mut target_to_client_receiver) = mpsc::channel(32);
        let transaction_id = 1;
        let initial_sequence_number = 2;

        let params = ConnectionParams {
            client_target_stream,
            transaction_id,
            initial_sequence_number,
            connection_id: "test".to_string(),
            client_to_target_receiver,
            target_to_client_sender,
        };

        let handler = ConnectionHandler::new(params);

        let handler_future = tokio::spawn(async move {
            handler.start().await;
        });

        // Simulate sending data to the target
        client_to_target_sender
            .send(TargetToClientPacket {
                data: b"response1".to_vec(),
                sequence_number: initial_sequence_number + 1,
                connection_id: "test".to_string(),
            })
            .await
            .unwrap();

        let mut received_packets = HashSet::new();

        // Collect the two packets
        for _ in 0..2 {
            if let Some(received) = target_to_client_receiver.recv().await {
                received_packets.insert(received.data);
            } else {
                panic!("Did not receive expected data");
            }
        }

        let mut found_payload = false;
        let mut found_ack = false;

        // Now that we have both packets, we can process them
        for data in received_packets.iter() {
            let data_slice = data.as_slice();
            if is_ack(&data_slice) {
                // Ensure only one ACK packet is received
                assert!(!found_ack, "Received duplicate ACK packet");
                found_ack = true;

                // Check the ACK packet
                assert_eq!(data_slice[0], transaction_id);
                assert_eq!(data_slice[1], initial_sequence_number + 1);
            } else if let Some(payload) = extract_dns_payload_from_answer(data_slice) {
                // Ensure only one payload packet is received
                assert!(!found_payload, "Received duplicate payload packet");
                found_payload = true;

                // Check the payload packet
                assert_eq!(data_slice[0], transaction_id);
                assert_eq!(payload.payload, b"hello".to_vec());
            } else {
                panic!("Unexpected packet content");
            }
        }

        // Ensure we received exactly one payload and one ACK
        assert!(found_payload, "Did not receive expected payload packet");
        assert!(found_ack, "Did not receive expected ACK packet");

        if let Some(received) = target_to_client_receiver.recv().await {
            let data = received.data.as_slice();
            assert_eq!(
                extract_dns_payload_from_answer(data).unwrap().payload,
                b"hello2".to_vec()
            );
        } else {
            panic!("Did not receive expected data");
        }

        let res = handler_future.await;
        assert!(res.is_ok());
    }

    #[test(tokio::test)]
    async fn test_connection_handler_target_closed() {
        let client_target_stream = Builder::new().build();

        let (_, client_to_target_receiver) = mpsc::channel(32);
        let (target_to_client_sender, mut target_to_client_receiver) = mpsc::channel(32);

        let params = ConnectionParams {
            client_target_stream,
            transaction_id: 1,
            initial_sequence_number: 2,
            connection_id: "test".to_string(),
            client_to_target_receiver,
            target_to_client_sender,
        };

        let handler = ConnectionHandler::new(params);

        let _handler_future = tokio::spawn(async move {
            handler.start().await;
        });

        if let Some(received) = target_to_client_receiver.recv().await {
            panic!(
                "received some data while we should not: {:?}",
                received.data
            );
        }
    }

    #[test(tokio::test)]
    async fn test_connection_handler_failed_to_read() {
        // Simulate a read error
        let client_target_stream = Builder::new()
            .read_error(Error::new(
                std::io::ErrorKind::Other,
                "Simulated read error",
            ))
            .read(b"test")
            .build();

        let (client_to_target_sender, client_to_target_receiver) = mpsc::channel(32);
        let (target_to_client_sender, mut target_to_client_receiver) = mpsc::channel(32);

        let params = ConnectionParams {
            client_target_stream,
            transaction_id: 1,
            initial_sequence_number: 2,
            connection_id: "test".to_string(),
            client_to_target_receiver,
            target_to_client_sender,
        };

        let handler = ConnectionHandler::new(params);

        tokio::spawn(async move {
            handler.start().await;
        });

        if let Some(received) = target_to_client_receiver.recv().await {
            panic!(
                "received some data while we should not: {:?}",
                received.data
            );
        }
    }

    #[test(tokio::test)]
    async fn test_connection_handler_interrupted() {
        // Simulate a read error
        let client_target_stream = Builder::new()
            .read_error(Error::new(
                std::io::ErrorKind::Interrupted,
                "Interrupted error",
            ))
            .read(b"test")
            .build();

        let (client_to_target_sender, client_to_target_receiver) = mpsc::channel(32);
        let (target_to_client_sender, mut target_to_client_receiver) = mpsc::channel(32);

        let params = ConnectionParams {
            client_target_stream,
            transaction_id: 1,
            initial_sequence_number: 2,
            connection_id: "test".to_string(),
            client_to_target_receiver,
            target_to_client_sender,
        };

        let handler = ConnectionHandler::new(params);

        tokio::spawn(async move {
            handler.start().await;
        });

        if let Some(received) = target_to_client_receiver.recv().await {
            let data = received.data.as_slice();
            assert_eq!(
                extract_dns_payload_from_answer(data).unwrap().payload,
                b"test".to_vec()
            );
        } else {
            panic!("interrupted error should continue reading");
        }
        // write to make sure the channel is kept open and the loop doesn't quit earlier
        let _ = client_to_target_sender
            .send(TargetToClientPacket {
                data: b"test".to_vec(),
                sequence_number: 1,
                connection_id: "test".to_string(),
            })
            .await;
    }

    #[test(tokio::test)]
    async fn test_connection_handler_close_reader() {
        // Simulate a read error
        let client_target_stream = Builder::new().write(b"test").build();

        let (client_to_target_sender, client_to_target_receiver) = mpsc::channel(32);
        let (target_to_client_sender, mut target_to_client_receiver) = mpsc::channel(32);
        drop(client_to_target_sender);

        let params = ConnectionParams {
            client_target_stream,
            transaction_id: 1,
            initial_sequence_number: 2,
            connection_id: "test".to_string(),
            client_to_target_receiver,
            target_to_client_sender,
        };
        let handler = ConnectionHandler::new(params);

        tokio::spawn(async move {
            handler.start().await;
        });

        // we wait, but it should stop as the channel is dropped
        if let Some(_) = target_to_client_receiver.recv().await {
            panic!("we should never receive anything");
        }
    }

    #[ignore] // currently tests hangs, wouldblock seems to be handled differently
    #[test(tokio::test)]
    async fn test_connection_handler_would_block() {
        // Simulate a read error
        let client_target_stream = Builder::new()
            .read_error(Error::new(
                std::io::ErrorKind::WouldBlock,
                "Would block error",
            ))
            .read(b"test")
            .build();

        let (client_to_target_sender, client_to_target_receiver) = mpsc::channel(32);
        let (target_to_client_sender, mut target_to_client_receiver) = mpsc::channel(32);

        let params = ConnectionParams {
            client_target_stream,
            transaction_id: 1,
            initial_sequence_number: 2,
            connection_id: "test".to_string(),
            client_to_target_receiver,
            target_to_client_sender,
        };

        let handler = ConnectionHandler::new(params);

        tokio::spawn(async move {
            handler.start().await;
        });

        if let Some(received) = target_to_client_receiver.recv().await {
            let data = &received.data[0..4];
            assert_eq!(data, b"test".to_vec());
        } else {
            panic!("Would block error should continue reading");
        }
    }

    #[test(tokio::test)]
    async fn test_udp_server_real_socket() {
        let tcp_server_result = start_tcp_test_server(false).await;
        assert!(tcp_server_result.is_ok(), "failed to start the server");

        let tcp_addr = tcp_server_result.unwrap();

        let actual_address = Ipv4Addr::new(127, 0, 0, 1);
        let actual_port = tcp_addr.port();
        let target = ConnectionInfo::Ipv4 {
            address: actual_address,
            port: actual_port,
        };

        let mut bytes = NetworkPacket::from_connection_info(&target).to_network();
        bytes[0] = 0x01;
        bytes[1] = 0x02;

        // Start the UDP server
        let server = UdpServer::new().await;
        let port = server.port();

        // Spawn the server to run in the background
        tokio::spawn(async move {
            server.start().await;
        });

        // Create a client socket to communicate with the server
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = format!("127.0.0.1:{}", port);

        // Send a test message to the server
        client_socket.send_to(&bytes, &server_addr).await.unwrap();

        // Prepare a buffer to receive the server's response
        let mut buf = [0u8; 512];

        // Receive the response from the server
        // Use a timeout to avoid hanging indefinitely if something goes wrong
        let response = timeout(Duration::from_secs(2), client_socket.recv_from(&mut buf)).await;

        match response {
            Ok(Ok((size, _))) => {
                // Validate the server's response
                match extract_dns_payload_from_answer(&buf[..size]) {
                    Some(parsed_data) => {
                        assert_eq!(parsed_data.transaction_id, 1);
                        assert_eq!(parsed_data.payload, b"Hello, this is the server: 0");
                    }
                    None => panic!("data malformed"),
                }
            }
            Ok(Err(e)) => panic!("Failed to receive data: {}", e),
            Err(_) => panic!("Test timed out waiting for response"),
        }
    }

    #[test]
    fn test_connection_manager() {
        let mut connection_manager = ConnectionManager::new();
        let connection_id = "test";

        match connection_manager.get(connection_id) {
            Some(_) => panic!("should not be getting anything"),
            _ => {}
        }

        let (client_to_target_sender, _) = mpsc::channel(32);

        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let connection = Connection {
            transaction_id: 1,
            src,
            client_to_target_sender,
        };

        connection_manager.add(connection_id.to_string(), connection);

        match connection_manager.get(connection_id) {
            Some(connection) => {
                assert_eq!(connection.transaction_id, 1);
                assert_eq!(connection.src, src);
            }
            _ => panic!("it should retrieve the record"),
        }

        connection_manager.delete(connection_id);

        match connection_manager.get(connection_id) {
            Some(_) => panic!("should not be getting anything"),
            _ => {}
        }
    }

    #[test]
    fn test_parse_received_data_new_connection_ipv4() {
        let mut connection_manager = ConnectionManager::new();

        let actual_address = Ipv4Addr::new(127, 0, 0, 1);
        let actual_port = 80;
        let target = ConnectionInfo::Ipv4 {
            address: actual_address,
            port: actual_port,
        };
        let initial_sequence_number = 0x03;

        let mut bytes = NetworkPacket::from_connection_info(&target).to_network();
        bytes[0] = 0x02;
        bytes[1] = initial_sequence_number;
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let result =
            UdpServer::parse_received_data(&mut connection_manager, &bytes, bytes.len(), socket);
        match result {
            Ok(Command::NewConnection {
                transaction_id,
                initial_sequence_number,
                connection_id,
                header,
            }) => {
                assert_eq!(transaction_id, 0x02);
                assert_eq!(connection_id, "127.0.0.1:8080-2".to_string());
                match header.info {
                    ConnectionInfo::Ipv4 { address, port } => {
                        assert_eq!(address, actual_address);
                        assert_eq!(port, actual_port);
                    }
                    _ => panic!("invalid connection info type"),
                }
            }
            Err(e) => panic!("failed with error: {}", e),
            _ => panic!("it should return a new connection"),
        }
    }

    #[test]
    fn test_parse_received_data_existing_connection_ipv4() {
        let mut connection_manager = ConnectionManager::new();

        let actual_address = Ipv4Addr::new(127, 0, 0, 1);
        let actual_port = 80;
        let target = ConnectionInfo::Ipv4 {
            address: actual_address,
            port: actual_port,
        };

        let transaction_id = 2;

        let mut bytes = NetworkPacket::from_connection_info(&target).to_network();
        bytes[0] = transaction_id;
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let connection_id = src_and_transaction_id_to_string(socket, transaction_id);
        let (client_to_target_sender, _) = mpsc::channel(32);

        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let connection = Connection {
            src,
            transaction_id,
            client_to_target_sender,
        };

        connection_manager.add(connection_id.clone(), connection);

        let result =
            UdpServer::parse_received_data(&connection_manager, &bytes, bytes.len(), socket);
        match result {
            Ok(Command::ExistingConnection {
                connection_id: actual_connection_id,
            }) => {
                assert_eq!(connection_id, actual_connection_id);
            }
            Ok(_) => panic!("it should return an existing connection"),
            Err(e) => panic!("failed with error: {}", e),
        }
    }

    #[test]
    fn test_parse_received_data_malformed_data() {
        let connection_manager = ConnectionManager::new();
        let buf = [0x1, 0x2];
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let result = UdpServer::parse_received_data(&connection_manager, &buf, buf.len(), socket);
        assert!(result.is_err());
    }

    use std::io::{Result, Write};
    use tokio::net::{TcpListener, TcpStream};

    async fn handle_client(mut stream: TcpStream, echo: bool) -> Result<()> {
        let mut counter = 0;
        let response = format!("Hello, this is the server: {}", counter);
        stream.write_all(response.as_bytes()).await;
        stream.flush().await;

        let mut buffer = vec![0u8; 512];
        loop {
            tokio::select! {
                result = stream.read(&mut buffer) => match result {
                    Ok(n) if n > 0 => {
                        if echo {
                            stream.write_all(&buffer[..n]).await;
                            stream.flush().await;
                        } else {
                            counter +=1;
                            let response = format!("Hello, this is the server: {}", counter);
                            stream.write_all(response.as_bytes()).await;
                            stream.flush().await;

                        }
                        log::debug!("tcp server: received: {:?} - {}, passing back", &buffer[..n], n);
                    }
                    Ok(_) => {
                        log::debug!("tcp server: connection closed");
                        return Ok(());
                    }
                    Err(e) => {
                        match e.kind() {
                            std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock => {
                                log::warn!("tcp server: non critical error, continuing: {}", e);
                            }
                            _ => {
                                log::error!("tcp server: failed to read: {}", e);
                            }
                        }
                        return Ok(())
                    }

                }
            };
        }
    }

    async fn start_tcp_test_server(echo: bool) -> Result<(SocketAddr)> {
        // Bind to a dynamic port (0 lets the OS choose an available port)
        let listener = TcpListener::bind("127.0.0.1:0").await?;

        // Get the socket address to return the port
        let addr = listener.local_addr()?;

        // Spawn a tokio task to accept and handle connections asynchronously
        let listener_task = listener;
        tokio::spawn(async move {
            loop {
                match listener_task.accept().await {
                    Ok((stream, _addr)) => {
                        // Spawn a new task to handle the client
                        tokio::task::spawn(async move {
                            if let Err(e) = handle_client(stream, echo).await {
                                log::error!("failed to handle client: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("failed to accept a connection: {}", e);
                    }
                }
            }
        });

        Ok(addr)
    }

    #[test(tokio::test)]
    async fn test_handle_socket_data_new_connection() {
        let tcp_server_result = start_tcp_test_server(false).await;
        let transaction_id = 0x01;
        let initial_sequence_number = 0x02;
        assert!(tcp_server_result.is_ok(), "failed to start the server");

        let tcp_addr = tcp_server_result.unwrap();

        let mut connection_manager = ConnectionManager::new();

        let (sender, mut receiver) = tokio::sync::mpsc::channel(32);

        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), tcp_addr.port());

        let actual_address = Ipv4Addr::new(127, 0, 0, 1);
        let actual_port = tcp_addr.port();
        let target = ConnectionInfo::Ipv4 {
            address: actual_address,
            port: actual_port,
        };

        let mut bytes = NetworkPacket::from_connection_info(&target).to_network();
        bytes[0] = transaction_id;
        bytes[1] = initial_sequence_number;
        let connection_id = format!("127.0.0.1:{}-1", actual_port);

        UdpServer::handle_new_packet(
            &mut connection_manager,
            &bytes,
            bytes.len(),
            src,
            sender.clone(),
        )
        .await
        .unwrap();

        // check that data is returned
        if let Some(received_data) = receiver.recv().await {
            let data = received_data.data.as_slice();
            match extract_dns_payload_from_answer(data) {
                Some(parsed_data) => {
                    assert_eq!(parsed_data.transaction_id, 1);
                    assert_eq!(
                        "Hello, this is the server: 0",
                        String::from_utf8_lossy(&parsed_data.payload),
                    );
                }
                None => panic!("data malformed"),
            };
        } else {
            panic!("Data was not sent to the existing connection");
        }

        // increase sequence number
        bytes[1] = initial_sequence_number + 1;
        // send more data
        UdpServer::handle_new_packet(
            &mut connection_manager,
            &bytes,
            bytes.len(),
            src,
            sender.clone(),
        )
        .await
        .unwrap();

        let mut received_packets = HashSet::new();

        // Collect the two packets
        for _ in 0..2 {
            if let Some(received) = receiver.recv().await {
                received_packets.insert(received.data);
            } else {
                panic!("Did not receive expected data");
            }
        }

        let mut found_payload = false;
        let mut found_ack = false;

        // Now that we have both packets, we can process them
        for data in received_packets.iter() {
            let data_slice = data.as_slice();
            if is_ack(&data_slice) {
                // Ensure only one ACK packet is received
                assert!(!found_ack, "Received duplicate ACK packet");
                found_ack = true;

                // Check the ACK packet
                assert_eq!(data_slice[0], transaction_id);
                assert_eq!(data_slice[1], initial_sequence_number + 1);
            } else if let Some(payload) = extract_dns_payload_from_answer(data_slice) {
                // Ensure only one payload packet is received
                assert!(!found_payload, "Received duplicate payload packet");
                found_payload = true;

                // Check the payload packet
                assert_eq!(data_slice[0], transaction_id);
                assert_eq!(payload.payload, b"Hello, this is the server: 1".to_vec());
            } else {
                panic!("Unexpected packet content");
            }
        }

        // Ensure we received exactly one payload and one ACK
        assert!(found_payload, "Did not receive expected payload packet");
        assert!(found_ack, "Did not receive expected ACK packet");
    }

    #[test(tokio::test)]
    async fn test_handle_socket_data_out_of_order() {
        let tcp_server_result = start_tcp_test_server(true).await;
        assert!(tcp_server_result.is_ok(), "failed to start the server");

        let tcp_addr = tcp_server_result.unwrap();

        let mut connection_manager = ConnectionManager::new();

        let (sender, mut receiver) = tokio::sync::mpsc::channel(32);

        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), tcp_addr.port());

        let actual_address = Ipv4Addr::new(127, 0, 0, 1);
        let actual_port = tcp_addr.port();
        let target = ConnectionInfo::Ipv4 {
            address: actual_address,
            port: actual_port,
        };

        let mut bytes = NetworkPacket::from_connection_info(&target).to_network();
        let transaction_id = bytes[0];
        let initial_sequence_number = 0x32;
        bytes[1] = initial_sequence_number;
        let connection_id = format!("127.0.0.1:{}-{}", actual_port, transaction_id);

        UdpServer::handle_new_packet(
            &mut connection_manager,
            &bytes,
            bytes.len(),
            src,
            sender.clone(),
        )
        .await
        .unwrap();

        // check that data is returned
        if let Some(received_data) = receiver.recv().await {
            let data = received_data.data.as_slice();
            match extract_dns_payload_from_answer(data) {
                Some(parsed_data) => {
                    assert_eq!(parsed_data.transaction_id, transaction_id);
                    assert_eq!(
                        "Hello, this is the server: 0",
                        String::from_utf8_lossy(&parsed_data.payload),
                    );
                }
                None => panic!("data malformed"),
            };
        } else {
            panic!("Data was not sent to the existing connection");
        }

        let second_packet: Vec<u8> =
            wrap_query(transaction_id, initial_sequence_number + 2, b"second");

        // send more data
        UdpServer::handle_new_packet(
            &mut connection_manager,
            &second_packet,
            second_packet.len(),
            src,
            sender.clone(),
        )
        .await
        .unwrap();

        let first_packet: Vec<u8> =
            wrap_query(transaction_id, initial_sequence_number + 1, b"first");

        // send more data
        UdpServer::handle_new_packet(
            &mut connection_manager,
            &first_packet,
            first_packet.len(),
            src,
            sender.clone(),
        )
        .await
        .unwrap();

        let mut received_packets = HashSet::new();

        // Collect the two packets
        for _ in 0..3 {
            if let Some(received) = receiver.recv().await {
                received_packets.insert(received.data);
            } else {
                panic!("Did not receive expected data");
            }
        }

        let mut found_payload = false;
        let mut found_ack_1 = false;
        let mut found_ack_2 = false;

        // Now that we have both packets, we can process them
        for data in received_packets.iter() {
            let data_slice = data.as_slice();
            if is_ack(&data_slice) && data_slice[1] == initial_sequence_number + 1 {
                // Ensure only one ACK packet is received
                assert!(!found_ack_1, "Received duplicate ACK packet");
                found_ack_1 = true;

                // Check the ACK packet
                assert_eq!(data_slice[0], transaction_id);
                assert_eq!(data_slice[1], initial_sequence_number + 1);
            } else if is_ack(&data_slice) && data_slice[1] == initial_sequence_number + 2 {
                // Ensure only one ACK packet is received
                assert!(!found_ack_2, "Received duplicate ACK packet");
                found_ack_2 = true;

                // Check the ACK packet
                assert_eq!(data_slice[0], transaction_id);
                assert_eq!(data_slice[1], initial_sequence_number + 2);
            } else if let Some(payload) = extract_dns_payload_from_answer(data_slice) {
                // Ensure only one payload packet is received
                assert!(!found_payload, "Received duplicate payload packet");
                found_payload = true;

                // Check the payload packet
                assert_eq!(data_slice[0], transaction_id);
                assert_eq!(payload.transaction_id, transaction_id);
                assert_eq!("firstsecond", String::from_utf8_lossy(&payload.payload),);
            } else {
                panic!("Unexpected packet content");
            }
        }

        // Ensure we received exactly one payload and one ACK
        assert!(found_payload, "Did not receive expected payload packet");
        assert!(found_ack_1, "Did not receive expected ACK 1 packet");
        assert!(found_ack_2, "Did not receive expected ACK 2 packet");
    }

    #[test]
    fn test_packet_receiver_basic_operations() {
        let sequence_number = 0x02;

        let mut packet_receiver = PacketReceiver::new(sequence_number + 1);

        match packet_receiver.get(sequence_number) {
            Some(_) => panic!("should not be getting anything"),
            _ => {}
        }

        let packet = TargetToClientPacket {
            data: b"test".to_vec(),
            sequence_number,
            connection_id: "test".to_string(),
        };

        packet_receiver.add(packet);

        match packet_receiver.get(sequence_number) {
            Some(connection) => {
                assert_eq!(connection.sequence_number, sequence_number);
            }
            _ => panic!("it should retrieve the record"),
        }

        packet_receiver.delete(sequence_number);

        match packet_receiver.get(sequence_number) {
            Some(_) => panic!("should not be getting anything"),
            _ => {}
        }
    }

    #[test]
    fn test_packet_receiver_out_of_order() {
        let sequence_number_1 = 0x01;
        let sequence_number_2 = 0x02;
        let sequence_number_3 = 0x03;
        let connection_id = "test".to_string();

        let mut packet_receiver = PacketReceiver::new(sequence_number_1);

        let packet_1 = TargetToClientPacket {
            data: b"test-1".to_vec(),
            sequence_number: sequence_number_1,
            connection_id: connection_id.clone(),
        };

        let packet_2 = TargetToClientPacket {
            data: b"test-2".to_vec(),
            sequence_number: sequence_number_2,
            connection_id: connection_id.clone(),
        };

        let packet_3 = TargetToClientPacket {
            data: b"test-3".to_vec(),
            sequence_number: sequence_number_3,
            connection_id: connection_id.clone(),
        };

        let result = packet_receiver.process(packet_3);
        assert!(result.is_none());
        assert_eq!(packet_receiver.next_sequence_number, 1);
        assert_eq!(packet_receiver.last_sequence_number, 3);

        let result = packet_receiver.process(packet_2);
        assert!(result.is_none());
        assert_eq!(packet_receiver.next_sequence_number, 1);
        assert_eq!(packet_receiver.last_sequence_number, 3);

        let result = packet_receiver.process(packet_1);
        assert!(result.is_some());

        let packets = result.unwrap();

        assert_eq!(packets.len(), 3);
        assert_eq!(packets[0].sequence_number, 1);
        assert_eq!(packets[1].sequence_number, 2);
        assert_eq!(packets[2].sequence_number, 3);

        let sequence_number_4 = 4;
        let packet_4 = TargetToClientPacket {
            data: b"test-4".to_vec(),
            sequence_number: sequence_number_4,
            connection_id: connection_id.clone(),
        };

        let result = packet_receiver.process(packet_4);
        assert!(result.is_some());
        let actual_packets = result.unwrap();
        assert_eq!(actual_packets.len(), 1);
        assert_eq!(actual_packets[0].sequence_number, 4);
    }
}
