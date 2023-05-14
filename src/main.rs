use implement_dns::{build_query, DNSPacket, DomainName, TypeField};
use std::net::UdpSocket;

fn main() -> Result<(), std::io::Error> {
    let response_test = hex::decode("60568180000100010000000003777777076578616d706c6503636f6d0000010001c00c000100010000529b00045db8d822").unwrap();
    let dns_packet = DNSPacket::from(&response_test)?;
    println!("{:?}", dns_packet);

    let domain_name = DomainName::from("www.example.com");
    let query = build_query(domain_name, TypeField::A);

    let socket = UdpSocket::bind("0.0.0.0:34254").expect("couldn't bind to address");
    socket.connect("8.8.8.8:53")?;
    socket.send(query.as_slice())?;

    let mut buf = [0; 1024];
    let (_amt, _src) = socket.recv_from(&mut buf)?;

    let dns_packet = DNSPacket::from(&buf)?;
    println!("{:?}", dns_packet);

    Ok(())
}
