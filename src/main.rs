mod constants;
mod dns_parser;
mod errors;
mod udp_server;
mod utils;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use tokio::net::UdpSocket;

    // Build the DNS query packet
    let query = utils::build_dns_query(&["www.google.co.uk", "www.guardian.co.uk"]);

    let parsed_data = dns_parser::extract_dns_payload(&query);
    if parsed_data.is_none() {
        return Ok(());
    }

    let _ = dns_parser::ConnectionHeader::from_network(parsed_data.unwrap().payload);
    // Bind a UDP socket to a local address
    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    // Connect the socket to a DNS server (e.g., Google's pup neeennblic DNS server)
    socket.connect("8.8.8.8:53").await?;

    // Send the DNS query
    socket.send(&query).await?;

    // Create a buffer to hold the response
    let mut buf = [0u8; 512]; // DNS packets can be up to 512 bytes
    let n = socket.recv(&mut buf).await?;

    // Print the raw DNS response
    println!("Received {} bytes", n);
    println!("DNS packet: {:?}", &buf[..n]);

    Ok(())
}

// 1 byte -> type (0x01 ip v4, 0x03, domain name, 0x04 ipv6 address)
// VARIABLE -> 4 bytes ip address, 1-255 bytes domain name, 16 bytes ipv6 address
// 2 bytes dst port  (is this needed? if we always have a SYN TCP packet to start with, that's not
//   needed
// SRC ip address and port is in the udp packet
