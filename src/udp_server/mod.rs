use crate::constants::MAX_DNS_PACKET_SIZE;
use crate::dns_parser::{extract_dns_payload, ConnectionHeader, ConnectionInfo};
use std::collections::HashMap;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

// ConnectionHandler manages a single TCP connection.
//
struct ConnectionHandler<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream: S,
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
        stream: S,
        target: ConnectionInfo,
        client_to_target_receiver: mpsc::Receiver<Vec<u8>>,
        target_to_client_sender: mpsc::Sender<Vec<u8>>,
    ) -> Self {
        Self {
            stream,
            target,
            client_to_target_receiver,
            target_to_client_sender,
        }
    }
    pub async fn start(mut self) {
        loop {
            let mut buffer = vec![0u8; 512];
            tokio::select! {
                result = self.stream.read(&mut buffer) => match result {
                    Ok(n) if n > 0 => {

                        println!("Received: {}", String::from_utf8_lossy(&buffer[..n]));
                        self.target_to_client_sender.send(buffer).await.unwrap();
                    }
                    Ok(_) => {
                        println!("connection closed");
                        return
                    }
                    Err(e) => {
                        println!("failed to read: {}", e)
                    }
                }
            }
        }
    }
}

// ConnectionManager stores active connections.
struct Connection {
    client_to_target_sender: mpsc::Sender<Vec<u8>>,
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
}

// UdpServer listens for incoming UDP packets.
pub struct UdpServer {
    socket: UdpSocket,
}

impl UdpServer {
    pub async fn new() -> UdpServer {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("Could not bind socket");
        UdpServer { socket: socket }
    }

    pub async fn start(&self) {
        let mut connection_manager = ConnectionManager::new();
        let mut buf = vec![0u8; MAX_DNS_PACKET_SIZE];

        println!("LOOOOOP");
        loop {
            println!("STARTING LOOP");
            match self.socket.recv_from(&mut buf).await {
                Ok((size, src)) => {
                    let mut received_data: [u8; MAX_DNS_PACKET_SIZE] = [0; MAX_DNS_PACKET_SIZE];
                    received_data[..size].copy_from_slice(&buf[..size]);
                    println!("Received from {}: {:?}", src, received_data);
                    let payload = extract_dns_payload(&received_data);
                    println!("Extracted: {:?}", payload.to_vec());

                    let header_result = ConnectionHeader::from_network(payload);
                    match header_result {
                        Ok(header) => {
                            println!("Successfully parsed header: {:?}", header.info);

                            let (client_to_target_sender, client_to_target_receiver) =
                                mpsc::channel(32);
                            let (target_to_client_sender, mut target_to_client_receiver) =
                                mpsc::channel(32);

                            let connection = Connection {
                                client_to_target_sender,
                            };

                            connection_manager.add(header.info.id(), connection);

                            let connection_handler;
                            let stream_result = header.info.connect().await;
                            match stream_result {
                                Ok(stream) => {
                                    connection_handler = ConnectionHandler {
                                        stream,
                                        target: header.info,
                                        client_to_target_receiver,
                                        target_to_client_sender,
                                    };
                                }
                                Err(e) => {
                                    println!("error connecting: {}", e);
                                    continue;
                                }
                            }
                            tokio::spawn(async move {
                                println!("HEREEEE");
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
                        Err(error) => {
                            println!("Failed to parse header: {}", error);
                        }
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
    use crate::udp_server::ConnectionHandler;
    use tokio::sync::mpsc;
    use tokio_test::io::Builder;

    #[tokio::test]
    async fn test_connection_handler_start() {
        // 1. Create a mock stream
        let mock_stream = Builder::new()
            .read(b"hello") // Simulate the stream reading "hello"
            .build();

        // 2. Create the channels for communication
        let (client_to_target_sender, client_to_target_receiver) = mpsc::channel(32);
        let (target_to_client_sender, mut target_to_client_receiver) = mpsc::channel(32);

        // 3. Create a mock ConnectionInfo (you may need to adapt this part)
        let mock_target = ConnectionInfo::Ipv4 {
            address: "127.0.0.1".parse().unwrap(),
            port: 8080,
        };

        // 4. Create the ConnectionHandler with the mock stream
        let handler = ConnectionHandler::new(
            mock_stream, // Pass the mock stream
            mock_target,
            client_to_target_receiver,
            target_to_client_sender,
        );

        // 5. Spawn the start method in a task
        tokio::spawn(async move {
            handler.start().await;
        });

        // 6. Test the results
        if let Some(received) = target_to_client_receiver.recv().await {
            assert_eq!(received, b"hello".to_vec());
        } else {
            panic!("Did not receive expected data");
        }
    }
}
