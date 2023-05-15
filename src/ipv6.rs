use std::net::Ipv6Addr;

pub fn ipv6_addr_from_bytes(chunk: &[u8]) -> Ipv6Addr {
    Ipv6Addr::new(
        u16::from_be_bytes([chunk[0], chunk[1]]),
        u16::from_be_bytes([chunk[2], chunk[3]]),
        u16::from_be_bytes([chunk[4], chunk[5]]),
        u16::from_be_bytes([chunk[6], chunk[7]]),
        u16::from_be_bytes([chunk[8], chunk[9]]),
        u16::from_be_bytes([chunk[10], chunk[11]]),
        u16::from_be_bytes([chunk[12], chunk[13]]),
        u16::from_be_bytes([chunk[14], chunk[15]]),
    )
}
