use implement_dns::{build_query, DomainName, TypeField};
use std::net::UdpSocket;

fn main() -> Result<(), std::io::Error> {
    let domain_name = DomainName::from("www.example.com");
    let query = build_query(&domain_name, TypeField::A);

    let socket = UdpSocket::bind("0.0.0.0:34254").expect("couldn't bind to address");
    socket.connect("8.8.8.8:53")?;
    socket.send(query.as_slice())?;

    let mut buf = [0; 1024];
    let (_amt, _src) = socket.recv_from(&mut buf)?;
    Ok(())
}
