use crate::constants::{
    DNS_HEADER_SIZE, DNS_TYPE_CLASS_SIZE, MAX_DNS_FIRST_QNAME_SIZE, MAX_DNS_PACKET_SIZE,
    MAX_DNS_SECOND_QNAME_SIZE, NETWORK_ADDRESS_TYPE_DOMAIN_NAME, NETWORK_ADDRESS_TYPE_IPV4,
    NETWORK_ADDRESS_TYPE_IPV6,
};
use std::net::Ipv4Addr;

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

impl std::error::Error for ExtractStartConnectionHeaderError {}

pub fn extract_dns_payload(buf: &[u8; MAX_DNS_PACKET_SIZE]) -> Vec<u8> {
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

#[derive(Debug)]
enum ConnectionInfo {
    Ipv4 { address: Ipv4Addr, port: u16 },
    Ipv6 { address: [u8; 16], port: u16 },
    DomainName { name: String, port: u16 },
}

#[derive(Debug)]
pub struct ConnectionHeader {
    info: ConnectionInfo,
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
    pub fn new(buf: Vec<u8>) -> Result<ConnectionHeader, ExtractStartConnectionHeaderError> {
        if buf.is_empty() {
            return Err(ExtractStartConnectionHeaderError::InvalidConnectionHeader);
        }

        match buf[0] {
            NETWORK_ADDRESS_TYPE_IPV4 => Ok(ConnectionHeader {
                info: extract_start_connection_header_ipv4(buf),
            }),
            NETWORK_ADDRESS_TYPE_IPV6 => Ok(ConnectionHeader {
                info: ConnectionInfo::Ipv6 {
                    address: [192, 168, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
                    port: 8080,
                },
            }),

            NETWORK_ADDRESS_TYPE_DOMAIN_NAME => Ok(ConnectionHeader {
                info: ConnectionInfo::DomainName {
                    name: String::from("test"),
                    port: 8080,
                },
            }),
            _ => Err(ExtractStartConnectionHeaderError::InvalidAddressType(
                buf[0],
            )),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::utils::build_dns_query;

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

    #[test]
    fn test_extract_connection_header_empty() {
        let input = vec![];
        let result = ConnectionHeader::new(input);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "invalid connection header");
    }

    #[test]
    fn test_extract_connection_header_ipv4() {
        let input = vec![NETWORK_ADDRESS_TYPE_IPV4, 192, 168, 1, 254, 0, 80];
        let result = ConnectionHeader::new(input).unwrap();
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
        let result = ConnectionHeader::new(input).unwrap();
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
        let result = ConnectionHeader::new(input).unwrap();
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
        let result = ConnectionHeader::new(input);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "invalid address type: 4");
    }
}
