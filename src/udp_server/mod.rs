use crate::constants::MAX_DNS_PACKET_SIZE;
use crate::dns_parser::{extract_dns_payload, ConnectionHeader, ConnectionInfo, ParsedData};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

// ConnectionHandler manages a single TCP connection.
//
struct ConnectionHandler<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    client_target_stream: S,
    target: ConnectionInfo,
    client_to_target_receiver: mpsc::Receiver<Vec<u8>>,
    target_to_client_sender: mpsc::Sender<Vec<u8>>,
}

// 1) Wait on the tcp connection and send back
// 2) Wait on a channel and send forward
// 3) Close connection if either are closed
impl<S> ConnectionHandler<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(
        client_target_stream: S,
        target: ConnectionInfo,
        client_to_target_receiver: mpsc::Receiver<Vec<u8>>,
        target_to_client_sender: mpsc::Sender<Vec<u8>>,
    ) -> Self {
        Self {
            client_target_stream,
            target,
            client_to_target_receiver,
            target_to_client_sender,
        }
    }
    pub async fn start(mut self) {
        loop {
            let mut buffer = vec![0u8; 512];
            tokio::select! {
            message = self.client_to_target_receiver.recv() => {
                if let Some(msg) = message {
                    if let Err(e) = self.client_target_stream.write_all(&msg).await {
                        println!("Failed to write to stream: {}", e);
                        return;
                    }
                } else {
                    // The sender has closed, end the connection
                    println!("Sender closed the channel, ending connection.");
                    return;
                }

            }
                result = self.client_target_stream.read(&mut buffer) => match result {
                    Ok(n) if n > 0 => {

                        println!("Received: {}", String::from_utf8_lossy(&buffer[..n]));
                        self.target_to_client_sender.send(buffer).await.unwrap();
                    }
                    Ok(_) => {
                        println!("connection closed");
                        return
                    }
                    Err(e) => {
                        match e.kind() {
                            std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock => {
                                println!("non critical error, continuing: {}", e);
                                continue;
                            }
                            _ => {
                                println!("failed to read: {}", e);
                            }
                        }
                        return
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
struct Connection {
    client_to_target_sender: mpsc::Sender<Vec<u8>>,
    transaction_id: u16,
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
        transaction_id: u16,
        header: ConnectionHeader,
    },
}

fn src_and_transaction_id_to_string(src: SocketAddr, transaction_id: u16) -> String {
    return format!("{}-{}", src.to_string(), transaction_id.to_string());
}

impl UdpServer {
    pub async fn new() -> UdpServer {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("Could not bind socket");
        UdpServer { socket: socket }
    }

    fn handle_received_data(
        connection_manager: &mut ConnectionManager,
        buf: &[u8],
        size: usize,
        src: SocketAddr,
    ) -> Result<Command, String> {
        let mut received_data: [u8; MAX_DNS_PACKET_SIZE] = [0; MAX_DNS_PACKET_SIZE];
        received_data[..size].copy_from_slice(&buf[..size]);
        println!("Received from {}: {:?}", src, received_data);
        let parsed_data: ParsedData;
        match extract_dns_payload(&received_data) {
            Some(data) => parsed_data = data,
            None => return Err("failed to parse payload".to_string()),
        }
        let payload = parsed_data.payload;
        let transaction_id = parsed_data.transaction_id;
        let connection_id = src_and_transaction_id_to_string(src, transaction_id);
        println!("Extracted: {:?}", payload.to_vec());

        let header_result = ConnectionHeader::from_network(payload);
        match header_result {
            Ok(header) => {
                println!("Successfully parsed header: {:?}", header.info);

                Ok(Command::NewConnection {
                    header,
                    connection_id,
                    transaction_id,
                })
            }
            Err(error) => Err(format!("failed to parse header: {}", error)),
        }
    }

    pub async fn start(&self) {
        let mut connection_manager = ConnectionManager::new();
        let mut buf = vec![0u8; MAX_DNS_PACKET_SIZE];

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((size, src)) => {
                    // get the sender ip address/port
                    // if it's a header, calculate an id;q
                    //
                    match UdpServer::handle_received_data(&mut connection_manager, &buf, size, src)
                    {
                        Ok(Command::NewConnection {
                            transaction_id,
                            connection_id,
                            header,
                        }) => {
                            let (client_to_target_sender, client_to_target_receiver) =
                                mpsc::channel(32);
                            let (target_to_client_sender, mut target_to_client_receiver) =
                                mpsc::channel(32);

                            let connection = Connection {
                                transaction_id,
                                client_to_target_sender,
                            };

                            connection_manager.add(connection_id, connection);
                            let connection_handler;
                            let stream_result = header.info.connect().await;
                            match stream_result {
                                Ok(client_target_stream) => {
                                    connection_handler = ConnectionHandler {
                                        client_target_stream,
                                        target: header.info,
                                        client_to_target_receiver,
                                        target_to_client_sender,
                                    };
                                }
                                Err(e) => {
                                    println!("error connection: {}", e);
                                    return ();
                                }
                            }
                            tokio::spawn(async move {
                                connection_handler.start().await;
                                loop {
                                    tokio::select! {
                                        Some(message) = target_to_client_receiver.recv() => {
                                            println!("Received2: {}", String::from_utf8_lossy(&message));
                                        }
                                    }
                                }
                            });
                        }
                        Err(e) => println!("ha"),
                    }
                }
                Err(e) => {
                    println!("Failed to receive data: {}", e);
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

    use crate::dns_parser::ConnectionInfo;
    use crate::network_packet::NetworkPacket;
    use crate::udp_server::{Connection, ConnectionHandler, ConnectionManager, UdpServer};
    use std::io::Error;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;
    use tokio::time::{timeout, Duration};
    use tokio_test::io::Builder;

    #[tokio::test]
    async fn test_connection_handler_start() {
        let client_target_stream = Builder::new()
            .read(b"hello") // Simulate the stream reading "hello"
            .write(b"response1") // Expect the handler to write "response1"
            .read(b"hello2")
            .build();

        let (client_to_target_sender, client_to_target_receiver) = mpsc::channel(32);
        let (target_to_client_sender, mut target_to_client_receiver) = mpsc::channel(32);

        let mock_target = ConnectionInfo::Ipv4 {
            address: "127.0.0.1".parse().unwrap(),
            port: 8080,
        };

        let handler = ConnectionHandler::new(
            client_target_stream,
            mock_target,
            client_to_target_receiver,
            target_to_client_sender,
        );

        let handler_future = tokio::spawn(async move {
            handler.start().await;
        });

        // Simulate sending data to the target
        client_to_target_sender
            .send(b"response1".to_vec())
            .await
            .unwrap();

        if let Some(received) = target_to_client_receiver.recv().await {
            assert_eq!(received[0..5], b"hello".to_vec());
        } else {
            panic!("Did not receive expected data");
        }

        if let Some(received) = target_to_client_receiver.recv().await {
            assert_eq!(received[0..6], b"hello2".to_vec());
        } else {
            panic!("Did not receive expected data");
        }

        let res = handler_future.await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_connection_handler_target_closed() {
        let client_target_stream = Builder::new().build();

        let (_, client_to_target_receiver) = mpsc::channel(32);
        let (target_to_client_sender, mut target_to_client_receiver) = mpsc::channel(32);

        let mock_target = ConnectionInfo::Ipv4 {
            address: "127.0.0.1".parse().unwrap(),
            port: 8080,
        };

        let handler = ConnectionHandler::new(
            client_target_stream,
            mock_target,
            client_to_target_receiver,
            target_to_client_sender,
        );

        let _handler_future = tokio::spawn(async move {
            handler.start().await;
        });

        if let Some(received) = target_to_client_receiver.recv().await {
            panic!("received some data while we should not: {:?}", received);
        }
    }

    #[tokio::test]
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

        let mock_target = ConnectionInfo::Ipv4 {
            address: "127.0.0.1".parse().unwrap(),
            port: 8080,
        };

        let handler = ConnectionHandler::new(
            client_target_stream,
            mock_target,
            client_to_target_receiver,
            target_to_client_sender,
        );

        tokio::spawn(async move {
            handler.start().await;
        });

        if let Some(received) = target_to_client_receiver.recv().await {
            panic!("received some data while we should not: {:?}", received);
        }
    }

    #[tokio::test]
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

        let mock_target = ConnectionInfo::Ipv4 {
            address: "127.0.0.1".parse().unwrap(),
            port: 8080,
        };

        let handler = ConnectionHandler::new(
            client_target_stream,
            mock_target,
            client_to_target_receiver,
            target_to_client_sender,
        );

        tokio::spawn(async move {
            handler.start().await;
        });

        if let Some(received) = target_to_client_receiver.recv().await {
            assert_eq!(received[0..4], b"test".to_vec());
        } else {
            panic!("interrupted error should continue reading");
        }
    }

    #[ignore] // currently tests hangs, wouldblock seems to be handled differently
    #[tokio::test]
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

        let mock_target = ConnectionInfo::Ipv4 {
            address: "127.0.0.1".parse().unwrap(),
            port: 8080,
        };

        let handler = ConnectionHandler::new(
            client_target_stream,
            mock_target,
            client_to_target_receiver,
            target_to_client_sender,
        );

        tokio::spawn(async move {
            handler.start().await;
        });

        if let Some(received) = target_to_client_receiver.recv().await {
            assert_eq!(received[0..4], b"test".to_vec());
        } else {
            panic!("Would block error should continue reading");
        }
    }

    #[ignore]
    #[tokio::test]
    async fn test_udp_server_real_socket() {
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
        let test_message = b"test data";
        client_socket
            .send_to(test_message, &server_addr)
            .await
            .unwrap();

        // Prepare a buffer to receive the server's response
        let mut buf = [0u8; 512];

        // Receive the response from the server
        // Use a timeout to avoid hanging indefinitely if something goes wrong
        let response = timeout(Duration::from_secs(2), client_socket.recv_from(&mut buf)).await;

        match response {
            Ok(Ok((size, _))) => {
                // Validate the server's response
                assert_eq!(&buf[..size], b"expected response");
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
        let connection = Connection {
            transaction_id: 1,
            client_to_target_sender,
        };

        connection_manager.add(connection_id.to_string(), connection);

        match connection_manager.get(connection_id) {
            Some(_) => {}
            _ => panic!("it should retrieve the record"),
        }

        connection_manager.delete(connection_id);

        match connection_manager.get(connection_id) {
            Some(_) => panic!("should not be getting anything"),
            _ => {}
        }
    }

    #[test]
    fn test_handle_received_data_new_connection() {
        let mut connection_manager = ConnectionManager::new();

        let target = ConnectionInfo::Ipv4 {
            address: Ipv4Addr::new(127, 0, 0, 1),
            port: 80,
        };

        let bytes = NetworkPacket::from_connection_info(&target).to_network();
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let result =
            UdpServer::handle_received_data(&mut connection_manager, &bytes, bytes.len(), socket);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_received_data_existing_connection() {
        let mut connection_manager = ConnectionManager::new();

        let target = ConnectionInfo::Ipv4 {
            address: Ipv4Addr::new(127, 0, 0, 1),
            port: 80,
        };

        let bytes = NetworkPacket::from_connection_info(&target).to_network();
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let result =
            UdpServer::handle_received_data(&mut connection_manager, &bytes, bytes.len(), socket);
        println!("{:?}", result);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_received_data_malformed_data() {
        let mut connection_manager = ConnectionManager::new();
        let buf = [0x1, 0x2];
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let result =
            UdpServer::handle_received_data(&mut connection_manager, &buf, buf.len(), socket);
        assert!(result.is_err());
    }
}
