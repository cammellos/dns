use crate::constants::MAX_DNS_PACKET_SIZE;

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

pub fn wrap_data_in_dns_queries(data: Vec<u8>) -> [u8; MAX_DNS_PACKET_SIZE] {
    let mut buffer = [0u8; MAX_DNS_PACKET_SIZE];
    buffer
}
pub fn build_dns_query(domains: &[&str]) -> [u8; MAX_DNS_PACKET_SIZE] {
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
