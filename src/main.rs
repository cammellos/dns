use std::error::Error;

const MAX_DNS_PACKET_SIZE: usize = 512;
const DNS_HEADER_SIZE: usize = 12;
const DNS_TYPE_CLASS_SIZE: usize = 4;
const MAX_DNS_FIRST_QNAME_SIZE: usize = 255;
const DNS_QNAME_METADATA_SIZE: usize = 2;
const MAX_DNS_SECOND_QNAME_SIZE: usize = MAX_DNS_PACKET_SIZE
    - MAX_DNS_FIRST_QNAME_SIZE
    - DNS_HEADER_SIZE
    - 2 * DNS_TYPE_CLASS_SIZE
    - 2 * DNS_QNAME_METADATA_SIZE;

fn domain_to_qname(domain: &str, buffer: &mut [u8], offset: &mut usize) {
    for part in domain.split('.') {
        let len = part.len();
        buffer[*offset] = len as u8;
        *offset += 1;
        buffer[*offset..*offset + len].copy_from_slice(part.as_bytes());
        *offset += len;
    }
    buffer[*offset] = 0; // Null terminator for the QNAME
    *offset += 1;
}

fn build_dns_query(domains: &[&str]) -> [u8; MAX_DNS_PACKET_SIZE] {
    let mut buffer = [0u8; MAX_DNS_PACKET_SIZE];
    let mut offset = 0;

    // Fill DNS Header
    // ID
    buffer[offset] = 0x12;
    buffer[offset + 1] = 0x34;
    offset += 2;

    // Flags (standard query with recursion)
    buffer[offset] = 0x01;
    buffer[offset + 1] = 0x00;
    offset += 2;

    // Number of questions (QDCOUNT)
    let qdcount = domains.len() as u16;
    buffer[offset] = (qdcount >> 8) as u8;
    buffer[offset + 1] = (qdcount & 0xFF) as u8;
    offset += 2;

    // Answer RRs: 0
    buffer[offset] = 0x00;
    buffer[offset + 1] = 0x00;
    offset += 2;

    // Authority RRs: 0
    buffer[offset] = 0x00;
    buffer[offset + 1] = 0x00;
    offset += 2;

    // Additional RRs: 0
    buffer[offset] = 0x00;
    buffer[offset + 1] = 0x00;
    offset += 2;

    // Fill Questions Section
    for domain in domains {
        domain_to_qname(domain, &mut buffer, &mut offset);

        // QTYPE: 1 (A record)
        buffer[offset] = 0x00;
        buffer[offset + 1] = 0x01;
        offset += 2;

        // QCLASS: 1 (IN - Internet)
        buffer[offset] = 0x00;
        buffer[offset + 1] = 0x01;
        offset += 2;
    }

    buffer
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    use tokio::net::UdpSocket;

    // Build the DNS query packet
    let query = build_dns_query(&["www.google.co.uk", "www.guardian.co.uk"]);

    extract_dns_payload(&query);
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

fn extract_dns_payload(buf: &[u8; MAX_DNS_PACKET_SIZE]) -> Vec<u8> {
    let number_of_questions = usize::from(buf[5]);

    // Check count
    if number_of_questions == 0 {
        return Vec::new();
    }

    // We never want to have more than 2 questions
    if number_of_questions > 2 {
        return Vec::new();
    }

    let question_1_size_index = DNS_HEADER_SIZE;
    let question_1_data_start = question_1_size_index + 1;
    let question_1_size = usize::from(buf[question_1_size_index]);
    let question_1_data_end = question_1_data_start + question_1_size;

    let question_1_data = &buf[question_1_data_start..question_1_data_end];

    if number_of_questions == 1 {
        return question_1_data.to_vec();
    }

    // if there are two questions, one needs to be maxed out
    if question_1_size != MAX_DNS_FIRST_QNAME_SIZE {
        return Vec::new();
    }

    let question_2_size_index = question_1_data_end + DNS_TYPE_CLASS_SIZE + 1;
    let question_2_data_start = question_2_size_index + 1;
    let question_2_size = usize::from(buf[question_2_size_index]);
    let question_2_data_end = question_2_data_start + question_2_size;

    if question_2_size > MAX_DNS_SECOND_QNAME_SIZE {
        return Vec::new();
    }

    let mut result = Vec::with_capacity(question_1_size + question_2_size);

    result.extend_from_slice(question_1_data);
    result.extend_from_slice(&buf[question_2_data_start..question_2_data_end]);
    result
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_extract_dns_payload_single_question() {
        let query = build_dns_query(&["reddit"]);
        let payload = extract_dns_payload(&query);
        let expected = [0x72, 0x65, 0x64, 0x64, 0x69, 0x74];
        assert_eq!(expected, *payload);
    }

    #[test]
    fn test_extract_dns_payload_single_question_maxed_out() {
        let query = build_dns_query(&[&"a".repeat(MAX_DNS_FIRST_QNAME_SIZE)]);

        let payload = extract_dns_payload(&query);

        let mut expected = vec![b'a'; MAX_DNS_FIRST_QNAME_SIZE];
        expected.extend(vec![b'b'; MAX_DNS_SECOND_QNAME_SIZE]);

        assert_eq!(vec![b'a'; MAX_DNS_FIRST_QNAME_SIZE], payload);
    }

    #[test]
    fn test_extract_dns_payload_two_questions() {
        let query = build_dns_query(&[&"a".repeat(MAX_DNS_FIRST_QNAME_SIZE), "reddit"]);

        let payload = extract_dns_payload(&query);

        let mut expected = vec![b'a'; MAX_DNS_FIRST_QNAME_SIZE];
        expected.extend(vec![b'r', b'e', b'd', b'd', b'i', b't']);

        assert_eq!(expected.len(), payload.len());
        assert_eq!(expected, payload);
    }

    #[test]
    fn test_extract_dns_payload_two_questions_maxed_out() {
        let query = build_dns_query(&[
            &"a".repeat(MAX_DNS_FIRST_QNAME_SIZE),
            &"b".repeat(MAX_DNS_SECOND_QNAME_SIZE),
        ]);

        let payload = extract_dns_payload(&query);

        let mut expected = vec![b'a'; MAX_DNS_FIRST_QNAME_SIZE];
        expected.extend(vec![b'b'; MAX_DNS_SECOND_QNAME_SIZE]);

        assert_eq!(expected.len(), payload.len());
        assert_eq!(expected, payload);
    }

    #[test]
    fn test_extract_dns_payload_empty_buffer() {
        let query: [u8; MAX_DNS_PACKET_SIZE] = [0; MAX_DNS_PACKET_SIZE];

        let payload = extract_dns_payload(&query);

        assert!(payload.is_empty());
    }

    #[test]
    fn test_extract_dns_payload_too_large() {
        let mut query = build_dns_query(&["reddit", "google"]);
        query[DNS_HEADER_SIZE] = u8::MAX;
        query[DNS_HEADER_SIZE + DNS_TYPE_CLASS_SIZE + 2 + MAX_DNS_FIRST_QNAME_SIZE] = u8::MAX;

        let payload = extract_dns_payload(&query);

        assert!(payload.is_empty());
    }

    #[test]
    fn test_extract_dns_payload_exactly_too_large() {
        let mut query = build_dns_query(&[
            &"a".repeat(MAX_DNS_FIRST_QNAME_SIZE),
            &"b".repeat(MAX_DNS_SECOND_QNAME_SIZE),
        ]);
        query[DNS_HEADER_SIZE] = u8::MAX;
        query[DNS_HEADER_SIZE + DNS_TYPE_CLASS_SIZE + 2 + MAX_DNS_FIRST_QNAME_SIZE] =
            (MAX_DNS_SECOND_QNAME_SIZE + 1) as u8;

        let payload = extract_dns_payload(&query);

        assert!(payload.is_empty());
    }
}
