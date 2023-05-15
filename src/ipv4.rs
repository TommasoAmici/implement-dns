use std::net::Ipv4Addr;

pub fn ipv4_addr_from_bytes(chunk: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3])
}
