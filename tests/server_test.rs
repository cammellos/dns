// Start dns server
// Start a tcp server
// Tell the dns server to connect to it
// Wait for udp data
//
//
use dns::udp_server::UdpServer;
use std::io::{Result, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;

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
#[test]
fn test_add() {
    let tcp_server_result = start_tcp_test_server();
    assert!(tcp_server_result.is_ok(), "failed to start the server");

    let (tcp_listener, tcp_addr) = tcp_server_result.unwrap();

    let udp_server_result = UdpServer::new();
    assert!(udp_server_result.is_ok(), "failed to initialize udp server");

    let udp_server = udp_server_result.unwrap();
    assert_eq!(1, 2);
    //let udp_server_start_result = udp_server.start();
    //assert!(
    //    udp_server_start_result.is_ok(),
    //    "failed to start udp server"
    //);
}
