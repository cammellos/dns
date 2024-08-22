pub const MAX_DNS_PACKET_SIZE: usize = 512;
pub const DNS_HEADER_SIZE: usize = 12;
pub const DNS_TYPE_CLASS_SIZE: usize = 4;
pub const MAX_DNS_FIRST_QNAME_SIZE: usize = 255;
pub const DNS_QNAME_METADATA_SIZE: usize = 2;
pub const MAX_DNS_SECOND_QNAME_SIZE: usize = MAX_DNS_PACKET_SIZE
    - MAX_DNS_FIRST_QNAME_SIZE
    - DNS_HEADER_SIZE
    - 2 * DNS_TYPE_CLASS_SIZE
    - 2 * DNS_QNAME_METADATA_SIZE;

pub const NETWORK_ADDRESS_TYPE_IPV4: u8 = 0x01;
pub const NETWORK_ADDRESS_TYPE_IPV6: u8 = 0x02;
pub const NETWORK_ADDRESS_TYPE_DOMAIN_NAME: u8 = 0x03;
