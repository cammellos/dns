use crate::constants::{
    DNS_HEADER_SIZE, DNS_QNAME_METADATA_SIZE, DNS_TYPE_CLASS_SIZE, MAX_DNS_FIRST_QNAME_SIZE,
    MAX_DNS_PACKET_SIZE, MAX_DNS_SECOND_QNAME_SIZE, MAX_PAYLOAD_SIZE,
    NETWORK_ADDRESS_TYPE_DOMAIN_NAME, NETWORK_ADDRESS_TYPE_IPV4, NETWORK_ADDRESS_TYPE_IPV6,
};
use crate::errors::not_implemented;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

#[derive(Debug)]
pub enum ExtractStartConnectionHeaderError {
    InvalidAddressType(u8),
    InvalidConnectionHeader,
}

impl std::fmt::Display for ExtractStartConnectionHeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ExtractStartConnectionHeaderError::InvalidAddressType(at) => {
                write!(f, "invalid address type: {}", at)
            }
            ExtractStartConnectionHeaderError::InvalidConnectionHeader => {
                write!(f, "invalid connection header")
            }
        }
    }
}

pub struct ParsedData {
    pub transaction_id: u16,
    pub payload: Vec<u8>,
}

pub fn wrap_answer(transaction_id: u16, data: &[u8]) -> Vec<u8> {
    let mut response = Vec::with_capacity(12 + data.len()); // Reserve space for header + data

    // Insert transaction ID (big-endian format)
    response.push((transaction_id >> 8) as u8); // High byte
    response.push((transaction_id & 0xFF) as u8); // Low byte

    // DNS header flags for a standard response (e.g., 0x8180)
    response.push(0x81); // Response flag (QR = 1, opcode = 0000, AA = 1, TC = 0, RD = 1)
    response.push(0x80); // RA = 1, Z = 000, RCODE = 0000 (no error)

    // Question count (set to 1, since this is a response to a query)
    response.push(0x00);
    response.push(0x01);

    // Answer count (set to 1, assuming there's 1 answer)
    response.push(0x00);
    response.push(0x01);

    // Authority record count (set to 0)
    response.push(0x00);
    response.push(0x00);

    // Additional record count (set to 0)
    response.push(0x00);
    response.push(0x00);

    // Append the actual data (the answer section)
    response.extend_from_slice(data);

    response
}

impl std::error::Error for ExtractStartConnectionHeaderError {}

pub fn extract_dns_payload_from_answer(buf: &[u8]) -> Option<ParsedData> {
    let transaction_id = u16::from_be_bytes([buf[0], buf[1]]);

    if transaction_id == 0 {
        log::warn!("transaction id is missing");
        return None;
    }

    Some(ParsedData {
        payload: buf[DNS_HEADER_SIZE..buf.len()].to_vec(),
        transaction_id,
    })
}

pub fn create_dns_packet(transaction_id: u16, payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() == 0 {
        return None;
    }
    // Validate payload length
    if payload.len() > MAX_DNS_SECOND_QNAME_SIZE + MAX_DNS_FIRST_QNAME_SIZE {
        log::warn!(
            "payload length is greater than total available space: have {} want max: {} {}",
            payload.len(),
            MAX_DNS_SECOND_QNAME_SIZE,
            MAX_DNS_FIRST_QNAME_SIZE
        );
        return None;
    }

    // Initialize buffer with DNS header size
    let mut packet = vec![0u8; DNS_HEADER_SIZE];

    // Set transaction_id (2 bytes, big-endian)
    packet[0..2].copy_from_slice(&transaction_id.to_be_bytes());

    // Set flags and number of questions (simplified for this example)
    packet[2] = 0x01; // QR, Opcode, AA, TC, RD
    packet[3] = 0x00; // Z, RCODE
    packet[4] = 0x00; // Number of questions (will be set later)
    packet[5] = 0x01; // Number of questions (1 or 2 based on payload size)
    packet[6..8].copy_from_slice(&[0x00, 0x00]); // Number of answers
    packet[8..10].copy_from_slice(&[0x00, 0x00]); // Number of authority records
    packet[10..12].copy_from_slice(&[0x00, 0x00]); // Number of additional records

    // Add first question
    let question_1_size = payload.len().min(MAX_DNS_FIRST_QNAME_SIZE);

    // Ensure there is space for at least one question
    if DNS_HEADER_SIZE + question_1_size + DNS_TYPE_CLASS_SIZE + DNS_QNAME_METADATA_SIZE
        > MAX_DNS_PACKET_SIZE
    {
        return None;
    }

    log::debug!("adding question 1 size at index: {}", packet.len());
    // Append question 1 size and data
    packet.push(question_1_size as u8); // Size of the first question
    packet.extend_from_slice(&payload[..question_1_size]);

    // Add Null + DNS TYPE and CLASS for the first question
    let dns_type_class = [0x00, 0x00, 0x01, 0x00, 0x01]; // Type A (0x01) and Class IN (0x01)
    packet.extend_from_slice(&dns_type_class);

    // If payload is larger than what fits in one question
    if payload.len() > question_1_size {
        let question_2_size = payload.len() - question_1_size;

        // Ensure space for second question and its data
        if DNS_HEADER_SIZE + question_2_size + DNS_TYPE_CLASS_SIZE + DNS_QNAME_METADATA_SIZE
            > MAX_DNS_PACKET_SIZE
        {
            log::warn!("not enough space for the second question + data");
            return None;
        }

        // set number of questions
        packet[5] = 0x2;
        log::debug!("adding question 2 size at index: {}", packet.len());
        // Append question 2 size and data
        packet.push(question_2_size as u8); // Size of the second question
        packet.extend_from_slice(&payload[question_1_size..]);

        // Add DNS TYPE and CLASS for the second question
        packet.extend_from_slice(&dns_type_class);
    }

    // Ensure packet does not exceed the maximum size
    if packet.len() > MAX_DNS_PACKET_SIZE {
        log::warn!(
            "packet exceeds max dns packet size: have {} want {}",
            packet.len(),
            MAX_DNS_PACKET_SIZE
        );
        return None;
    }

    Some(packet)
}

pub fn extract_dns_payload(buf: &[u8; MAX_DNS_PACKET_SIZE]) -> Option<ParsedData> {
    let number_of_questions = usize::from(buf[5]);

    log::debug!(
        "extracting dns payload. number of questions: {}",
        number_of_questions
    );

    // Check count
    if number_of_questions == 0 {
        log::warn!("number of questions is 0");
        return None;
    }

    // We never want to have more than 2 questions
    if number_of_questions > 2 {
        log::warn!("number of questions is > 2");
        return None;
    }

    let transaction_id = u16::from_be_bytes([buf[0], buf[1]]);

    if transaction_id == 0 {
        log::warn!("transaction id is missing");
        return None;
    }

    let question_1_size_index = DNS_HEADER_SIZE;
    let question_1_data_start = question_1_size_index + 1;
    let question_1_size = usize::from(buf[question_1_size_index]);
    let question_1_data_end = question_1_data_start + question_1_size;
    let question_1_data = &buf[question_1_data_start..question_1_data_end];

    log::debug!(
        "question 1 size is: {}, index is at: {}",
        question_1_size,
        question_1_size_index
    );

    if number_of_questions == 1 {
        return Some(ParsedData {
            transaction_id,
            payload: question_1_data.to_vec(),
        });
    }

    // if there are two questions, one needs to be maxed out
    if question_1_size != MAX_DNS_FIRST_QNAME_SIZE {
        log::warn!("question 1 is not maxed out, but multiple questions are there");
        return None;
    }

    let question_2_size_index = question_1_data_end + DNS_TYPE_CLASS_SIZE + 1;
    let question_2_data_start = question_2_size_index + 1;
    let question_2_size = usize::from(buf[question_2_size_index]);
    let question_2_data_end = question_2_data_start + question_2_size;

    log::debug!(
        "question 2 size is: {}, index is at: {}",
        question_2_size,
        question_2_size_index
    );

    if question_2_size > MAX_DNS_SECOND_QNAME_SIZE {
        log::warn!("question 2 size is too large");
        return None;
    }

    let mut payload = Vec::with_capacity(question_1_size + question_2_size);

    payload.extend_from_slice(question_1_data);
    payload.extend_from_slice(&buf[question_2_data_start..question_2_data_end]);
    Some(ParsedData {
        transaction_id,
        payload,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConnectionInfo {
    Ipv4 { address: Ipv4Addr, port: u16 },
    Ipv6 { address: Ipv6Addr, port: u16 },
    DomainName { name: String, port: u16 },
}

impl ConnectionInfo {
    // TODO: add tests
    pub fn id(&self) -> String {
        match &self {
            ConnectionInfo::Ipv4 { address, port } => format!("{}:{}", address, port),
            _ => panic!("Unsupported connection type"),
        }
    }

    pub fn from_network(buf: Vec<u8>) -> Result<ConnectionInfo, ExtractStartConnectionHeaderError> {
        if buf.is_empty() {
            return Err(ExtractStartConnectionHeaderError::InvalidConnectionHeader);
        }

        match buf[0] {
            NETWORK_ADDRESS_TYPE_IPV4 => Ok(extract_start_connection_header_ipv4(buf)),
            NETWORK_ADDRESS_TYPE_IPV6 => Ok(ConnectionInfo::Ipv6 {
                address: Ipv6Addr::new(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0),
                port: 8080,
            }),

            NETWORK_ADDRESS_TYPE_DOMAIN_NAME => Ok(ConnectionInfo::DomainName {
                name: String::from("test"),
                port: 8080,
            }),
            _ => Err(ExtractStartConnectionHeaderError::InvalidAddressType(
                buf[0],
            )),
        }
    }

    pub fn to_network(&self) -> Vec<u8> {
        match self {
            ConnectionInfo::Ipv4 { address, port } => {
                let octets = address.octets();
                let port_bytes = port.to_be_bytes();
                vec![
                    7, // size
                    NETWORK_ADDRESS_TYPE_IPV4,
                    octets[0],
                    octets[1],
                    octets[2],
                    octets[3],
                    port_bytes[0],
                    port_bytes[1],
                ]
            }
            _ => {
                vec![]
            }
        }
    }
    pub async fn connect(&self) -> tokio::io::Result<tokio::net::TcpStream> {
        match self {
            ConnectionInfo::Ipv4 { address, port } => {
                let socket = SocketAddr::V4(SocketAddrV4::new(*address, *port));
                TcpStream::connect(socket).await
            }
            ConnectionInfo::Ipv6 { address, port } => {
                let socket = SocketAddr::V6(SocketAddrV6::new(*address, *port, 0, 0));
                TcpStream::connect(socket).await
            }
            _ => not_implemented(),
        }
    }
}

/// The initial information exchanged with the dns server.
///
/// It includes whether we are requesting an ipv4, ipv6 or a connection to a domain name
///
/// # Examples
///
/// ```
/// use dns::dns_parser::ConnectionInfo;
/// use dns::dns_parser::ConnectionHeader;
/// use std::net::Ipv4Addr;
///
/// let connection_info = ConnectionInfo::Ipv4 {
///     address: Ipv4Addr::new(192, 168, 0, 1),
///     port: 8080,
/// };
///
///
/// let connection_header = ConnectionHeader::from_network(connection_info.to_network());
/// assert!(connection_header.is_ok());
///
/// assert_eq!(connection_header.unwrap().info, connection_info);
/// ```
///
#[derive(Debug)]
pub struct ConnectionHeader {
    pub info: ConnectionInfo,
}

fn extract_port_from_u8s(high_byte: u8, low_byte: u8) -> u16 {
    ((high_byte as u16) << 8) | (low_byte as u16)
}

// TODO: add tests for shorter buffers
fn extract_start_connection_header_ipv4(buf: Vec<u8>) -> ConnectionInfo {
    ConnectionInfo::Ipv4 {
        address: Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]),
        port: extract_port_from_u8s(buf[5], buf[6]),
    }
}

impl ConnectionHeader {
    pub fn socket_address(&self) -> SocketAddrV4 {
        match self.info {
            _ => panic!("wrong type, expected ipv4"),
        }
    }
    pub fn from_network(
        buf: Vec<u8>,
    ) -> Result<ConnectionHeader, ExtractStartConnectionHeaderError> {
        let connection_info = ConnectionInfo::from_network(buf)?;
        Ok(ConnectionHeader {
            info: connection_info,
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::utils::build_dns_query;
    use test_log::test;

    #[test]
    fn test_extract_dns_payload_transaction_id() {
        let query = build_dns_query(&["reddit"]);

        let parsed_data_result = extract_dns_payload(&query);
        assert!(parsed_data_result.is_some());

        let parsed_data = parsed_data_result.unwrap();

        assert_eq!(258, parsed_data.transaction_id);
    }

    #[test]
    fn test_extract_dns_payload_no_transaction_id() {
        let mut query = build_dns_query(&["reddit"]);

        // blank transaction id
        query[0] = 0;
        query[1] = 0;

        let parsed_data_result = extract_dns_payload(&query);
        assert!(parsed_data_result.is_none());
    }

    #[test]
    fn test_extract_dns_payload_single_question() {
        let query = build_dns_query(&["reddit"]);

        let parsed_data_result = extract_dns_payload(&query);
        assert!(parsed_data_result.is_some());

        let parsed_data = parsed_data_result.unwrap();

        let expected = [0x72, 0x65, 0x64, 0x64, 0x69, 0x74];

        assert_eq!(expected, *parsed_data.payload);
    }

    #[test]
    fn test_extract_dns_payload_single_question_maxed_out() {
        let query = build_dns_query(&[&"a".repeat(MAX_DNS_FIRST_QNAME_SIZE)]);

        let parsed_data_result = extract_dns_payload(&query);
        assert!(parsed_data_result.is_some());

        let parsed_data = parsed_data_result.unwrap();

        let mut expected = vec![b'a'; MAX_DNS_FIRST_QNAME_SIZE];
        expected.extend(vec![b'b'; MAX_DNS_SECOND_QNAME_SIZE]);

        assert_eq!(vec![b'a'; MAX_DNS_FIRST_QNAME_SIZE], parsed_data.payload);
    }

    #[test]
    fn test_extract_dns_payload_two_questions() {
        let query = build_dns_query(&[&"a".repeat(MAX_DNS_FIRST_QNAME_SIZE), "reddit"]);

        let parsed_data_result = extract_dns_payload(&query);
        assert!(parsed_data_result.is_some());

        let parsed_data = parsed_data_result.unwrap();

        let mut expected = vec![b'a'; MAX_DNS_FIRST_QNAME_SIZE];
        expected.extend(vec![b'r', b'e', b'd', b'd', b'i', b't']);

        assert_eq!(expected.len(), parsed_data.payload.len());
        assert_eq!(expected, parsed_data.payload);
    }

    #[test]
    fn test_extract_dns_payload_two_questions_maxed_out() {
        let query = build_dns_query(&[
            &"a".repeat(MAX_DNS_FIRST_QNAME_SIZE),
            &"b".repeat(MAX_DNS_SECOND_QNAME_SIZE),
        ]);

        let parsed_data_result = extract_dns_payload(&query);
        assert!(parsed_data_result.is_some());

        let parsed_data = parsed_data_result.unwrap();

        let mut expected = vec![b'a'; MAX_DNS_FIRST_QNAME_SIZE];
        expected.extend(vec![b'b'; MAX_DNS_SECOND_QNAME_SIZE]);

        assert_eq!(expected.len(), parsed_data.payload.len());
        assert_eq!(expected, parsed_data.payload);
    }

    #[test]
    fn test_extract_dns_payload_empty_buffer() {
        let query: [u8; MAX_DNS_PACKET_SIZE] = [0; MAX_DNS_PACKET_SIZE];

        let parsed_data_result = extract_dns_payload(&query);
        assert!(parsed_data_result.is_none());
    }

    #[test]
    fn test_extract_dns_payload_too_large() {
        let mut query = build_dns_query(&["reddit", "google"]);
        query[DNS_HEADER_SIZE] = u8::MAX;
        query[DNS_HEADER_SIZE + DNS_TYPE_CLASS_SIZE + 2 + MAX_DNS_FIRST_QNAME_SIZE] = u8::MAX;

        let parsed_data_result = extract_dns_payload(&query);
        assert!(parsed_data_result.is_none());
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

        let parsed_data_result = extract_dns_payload(&query);
        assert!(parsed_data_result.is_none());
    }

    #[test]
    fn test_extract_connection_header_empty() {
        let input = vec![];
        let result = ConnectionHeader::from_network(input);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "invalid connection header");
    }

    #[test]
    fn test_extract_connection_header_ipv4() {
        let input = vec![NETWORK_ADDRESS_TYPE_IPV4, 192, 168, 1, 254, 0, 80];
        let result = ConnectionHeader::from_network(input).unwrap();
        match result.info {
            ConnectionInfo::Ipv4 { address, port } => {
                assert_eq!(address, Ipv4Addr::new(192, 168, 1, 254));
                assert_eq!(port, 80);
            }

            _ => panic!("wrong type, expected ipv4"),
        }
    }

    #[ignore]
    #[test]
    fn test_extract_connection_header_ipv6() {
        let input = vec![NETWORK_ADDRESS_TYPE_IPV6];
        let result = ConnectionHeader::from_network(input).unwrap();
        panic!("wrong type, expected ipv6")
    }

    #[ignore]
    #[test]
    fn test_extract_connection_header_domain_name() {
        let input = vec![
            NETWORK_ADDRESS_TYPE_DOMAIN_NAME,
            11,
            b'e',
            b'x',
            b'a',
            b'm',
            b'p',
            b'l',
            b'e',
            b'.',
            b'c',
            b'o',
            b'm',
            0,
            80,
        ];
        let result = ConnectionHeader::from_network(input).unwrap();
        match result.info {
            ConnectionInfo::DomainName { name, port } => {
                assert_eq!(name, "example.com");
                assert_eq!(port, 80);
            }
            _ => panic!("wrong type, expected domain name"),
        }
    }

    #[test]
    fn test_extract_connection_header_unknown_type() {
        let input = vec![0x04];
        let result = ConnectionHeader::from_network(input);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "invalid address type: 4");
    }

    #[test]
    fn test_connection_info_to_network_ipv4() {
        let connection_info = ConnectionInfo::Ipv4 {
            address: Ipv4Addr::new(0xa, 0xb, 0xc, 0xd),
            port: 0x1f90,
        };

        let result = connection_info.to_network();

        assert_eq!(
            vec![7, NETWORK_ADDRESS_TYPE_IPV4, 0xa, 0xb, 0xc, 0xd, 0x1f, 0x90],
            result
        );
    }

    #[ignore]
    #[test]
    fn test_connection_info_to_network_ipv6() {
        let connection_info = ConnectionInfo::Ipv6 {
            address: Ipv6Addr::new(0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8),
            port: 0x1f90,
        };

        let result = connection_info.to_network();

        assert_eq!(
            vec![NETWORK_ADDRESS_TYPE_IPV4, 0xa, 0xb, 0xc, 0xd, 0x1f, 0x90],
            result
        );
    }

    #[ignore]
    #[test]
    fn test_connection_info_to_network_domain_name() {
        let connection_info = ConnectionInfo::DomainName {
            name: String::from("www.movimenta.com"),
            port: 0x1f90,
        };

        let result = connection_info.to_network();

        assert_eq!(
            vec![
                NETWORK_ADDRESS_TYPE_DOMAIN_NAME,
                0xa,
                0xb,
                0xc,
                0xd,
                0x1f,
                0x90
            ],
            result
        );
    }

    #[test(tokio::test)]
    async fn test_connection_info_connect_domain_name() {
        let connection_info = ConnectionInfo::DomainName {
            name: String::from("www.movimenta.com"),
            port: 0x1f90,
        };

        let result = connection_info.connect().await;

        assert!(result.is_err());
    }

    #[test]
    fn test_wrap_answer_with_empty_data() {
        let transaction_id = 0x1234;
        let data: Vec<u8> = vec![];

        let response = wrap_answer(transaction_id, &data);

        // Check response length: 12 bytes for header + 0 bytes for data
        assert_eq!(response.len(), 12);

        // Check the transaction ID (0x1234)
        assert_eq!(response[0], 0x12);
        assert_eq!(response[1], 0x34);

        // Check the flags (0x8180)
        assert_eq!(response[2], 0x81); // QR = 1, AA = 1, RD = 1
        assert_eq!(response[3], 0x80); // RA = 1, RCODE = 0000

        // Check question count (0x0001)
        assert_eq!(response[4], 0x00);
        assert_eq!(response[5], 0x01);

        // Check answer count (0x0001)
        assert_eq!(response[6], 0x00);
        assert_eq!(response[7], 0x01);

        // Check authority record count (0x0000)
        assert_eq!(response[8], 0x00);
        assert_eq!(response[9], 0x00);

        // Check additional record count (0x0000)
        assert_eq!(response[10], 0x00);
        assert_eq!(response[11], 0x00);
    }

    #[test]
    fn test_wrap_answer_with_data() {
        let transaction_id = 0x5678;
        let data: Vec<u8> = vec![0x12, 0x34, 0x56, 0x78]; // Some dummy answer data

        let response = wrap_answer(transaction_id, &data);

        // Check response length: 12 bytes for header + 4 bytes for data
        assert_eq!(response.len(), 12 + data.len());

        // Check the transaction ID (0x5678)
        assert_eq!(response[0], 0x56);
        assert_eq!(response[1], 0x78);

        // Check the flags (0x8180)
        assert_eq!(response[2], 0x81); // QR = 1, AA = 1, RD = 1
        assert_eq!(response[3], 0x80); // RA = 1, RCODE = 0000

        // Check question count (0x0001)
        assert_eq!(response[4], 0x00);
        assert_eq!(response[5], 0x01);

        // Check answer count (0x0001)
        assert_eq!(response[6], 0x00);
        assert_eq!(response[7], 0x01);

        // Check authority record count (0x0000)
        assert_eq!(response[8], 0x00);
        assert_eq!(response[9], 0x00);

        // Check additional record count (0x0000)
        assert_eq!(response[10], 0x00);
        assert_eq!(response[11], 0x00);

        // Check appended data
        assert_eq!(&response[12..], &data[..]);
    }

    #[test]
    fn test_wrap_answer_with_large_data() {
        let transaction_id = 0x9ABC;
        let data: Vec<u8> = vec![0xAB; 512]; // 512 bytes of dummy data

        let response = wrap_answer(transaction_id, &data);

        // Check response length: 12 bytes for header + 512 bytes for data
        assert_eq!(response.len(), 12 + data.len());

        // Check the transaction ID (0x9ABC)
        assert_eq!(response[0], 0x9A);
        assert_eq!(response[1], 0xBC);

        // Check the flags (0x8180)
        assert_eq!(response[2], 0x81); // QR = 1, AA = 1, RD = 1
        assert_eq!(response[3], 0x80); // RA = 1, RCODE = 0000

        // Check question count (0x0001)
        assert_eq!(response[4], 0x00);
        assert_eq!(response[5], 0x01);

        // Check answer count (0x0001)
        assert_eq!(response[6], 0x00);
        assert_eq!(response[7], 0x01);

        // Check authority record count (0x0000)
        assert_eq!(response[8], 0x00);
        assert_eq!(response[9], 0x00);

        // Check additional record count (0x0000)
        assert_eq!(response[10], 0x00);
        assert_eq!(response[11], 0x00);

        // Check appended data
        assert_eq!(&response[12..], &data[..]);
    }

    #[test]
    fn test_wrap_answer_with_short_transaction_id() {
        let transaction_id = 0x01; // Single byte transaction ID
        let data: Vec<u8> = vec![];

        let response = wrap_answer(transaction_id, &data);

        // Check transaction ID is correctly padded
        assert_eq!(response[0], 0x00);
        assert_eq!(response[1], 0x01);
    }

    #[test]
    fn test_create_dns_packet_single_question() {
        let transaction_id = 12345;
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];

        let packet = create_dns_packet(transaction_id, &payload).unwrap();
        let mut buf = [0u8; MAX_DNS_PACKET_SIZE];
        buf[..packet.len()].copy_from_slice(&packet);

        let parsed = extract_dns_payload(&buf).unwrap();
        assert_eq!(parsed.transaction_id, transaction_id);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn test_create_dns_packet_multiple_questions() {
        let transaction_id = 12345;
        let payload = vec![1; MAX_DNS_FIRST_QNAME_SIZE + 1];

        let packet = create_dns_packet(transaction_id, &payload).unwrap();
        let mut buf = [0u8; MAX_DNS_PACKET_SIZE];
        buf[..packet.len()].copy_from_slice(&packet);

        let parsed = extract_dns_payload(&buf).unwrap();
        assert_eq!(parsed.transaction_id, transaction_id);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn test_create_dns_packet_truncated() {
        let transaction_id = 12345;
        let payload = vec![1; MAX_DNS_PACKET_SIZE - DNS_HEADER_SIZE + 1];

        let packet = create_dns_packet(transaction_id, &payload);
        assert!(packet.is_none()); // Payload too large for single packet
    }

    #[test]
    fn test_create_dns_packet_max_size() {
        let transaction_id = 12345;
        let payload = vec![1; MAX_PAYLOAD_SIZE];

        let packet = create_dns_packet(transaction_id, &payload).unwrap();
        let mut buf = [0u8; MAX_DNS_PACKET_SIZE];
        buf[..packet.len()].copy_from_slice(&packet);
        println!("{:?}", buf);

        let parsed = extract_dns_payload(&buf).unwrap();
        assert_eq!(parsed.transaction_id, transaction_id);
        assert_eq!(parsed.payload.len(), payload.len());
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn test_create_dns_packet_edge_cases() {
        let transaction_id = 12345;
        let empty_payload = vec![];
        let single_byte_payload = vec![1];
        let max_payload = vec![1; MAX_DNS_FIRST_QNAME_SIZE];

        // Test empty payload
        let packet = create_dns_packet(transaction_id, &empty_payload);
        assert!(packet.is_none());

        // Test single byte payload
        let packet = create_dns_packet(transaction_id, &single_byte_payload).unwrap();
        let mut buf = [0u8; MAX_DNS_PACKET_SIZE];
        buf[..packet.len()].copy_from_slice(&packet);

        let parsed = extract_dns_payload(&buf).unwrap();
        assert_eq!(parsed.transaction_id, transaction_id);
        assert_eq!(parsed.payload, single_byte_payload);

        // Test maximum payload size
        let packet = create_dns_packet(transaction_id, &max_payload).unwrap();
        let mut buf = [0u8; MAX_DNS_PACKET_SIZE];
        buf[..packet.len()].copy_from_slice(&packet);

        let parsed = extract_dns_payload(&buf).unwrap();
        assert_eq!(parsed.transaction_id, transaction_id);
        assert_eq!(parsed.payload, max_payload);
    }
}
