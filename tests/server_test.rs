// Start dns server
// Start a tcp server
// Tell the dns server to connect to it
// Wait for udp data
//
//
use dns::dns_parser::{extract_dns_payload, ConnectionInfo};
use dns::network_packet::ConnectCommand;
use dns::udp_server::UdpServer;
use std::io::{Result, Write};
use std::net::Ipv4Addr;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

fn handle_client(mut stream: TcpStream) -> Result<()> {
    let response = b"Hello, this is the server!";
    stream.write_all(response)?;
    stream.flush()?;
    Ok(())
}

fn start_tcp_test_server() -> Result<(TcpListener, SocketAddr)> {
    // Bind to a dynamic port (0 lets the OS choose an available port)
    let listener = TcpListener::bind("127.0.0.1:0")?;

    // Get the socket address to return the port
    let addr = listener.local_addr()?;

    // Spawn a thread to accept and handle connections
    let listener_clone = listener.try_clone()?;
    thread::spawn(move || {
        for stream in listener_clone.incoming() {
            match stream {
                Ok(stream) => {
                    // Handle the client in a separate thread
                    thread::spawn(|| {
                        handle_client(stream).unwrap();
                    });
                }
                Err(e) => {
                    eprintln!("Failed to accept a connection: {}", e);
                }
            }
        }
    });

    Ok((listener, addr))
}

//fn main() -> Result<()> {
//   let (listener, addr) = start_server()?;

//  println!("Server is running on {}", addr);

// The listener is kept alive here, and the server will continue to run.
// You can close the server by dropping the listener when you want to stop it.

// Keep the main thread alive (server will run indefinitely until manually stopped)
// loop {
//    thread::sleep(std::time::Duration::from_secs(10));
//}

// Example: Uncomment the following line to stop the server
// drop(listener);

// Ok(())
//}
#[tokio::test]
async fn test_add() {
    // Start the TCP test server
    let tcp_server_result = start_tcp_test_server();
    assert!(tcp_server_result.is_ok(), "failed to start the server");

    let (tcp_listener, tcp_addr) = tcp_server_result.unwrap();

    // Initialize the UDP server
    let udp_server = UdpServer::new().await;

    let proxy_info = ConnectionInfo::Ipv4 {
        address: Ipv4Addr::new(127, 0, 0, 1),
        port: udp_server.port(),
    };
    let target_info = ConnectionInfo::Ipv4 {
        address: Ipv4Addr::new(127, 0, 0, 1),
        port: tcp_addr.port(),
    };

    let connection_command = ConnectCommand::new(proxy_info, target_info);

    assert_eq!(1, 1); // Adjust this with the actual test logic

    tokio::spawn(async move { udp_server.start().await });
    //udp_server.start().await;

    connection_command.send();
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Perform the necessary operations for the test here...
    // Example: Send data to the UDP server, check for responses, etc.

    // Signal the server to stop and await its termination
    assert_eq!(1, 2);
}
