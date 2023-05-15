use std::io::{Cursor, Error, ErrorKind, Read};
use std::net::UdpSocket;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipv4::ipv4_addr_from_bytes;
use ipv6::ipv6_addr_from_bytes;

mod ipv4;
mod ipv6;

/// TYPE fields are used in resource records.  Note that these
/// types are a subset of QTYPEs.
/// See https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u16)]
pub enum TypeField {
    /// a host address
    A = 1,
    /// an authoritative name server
    NS = 2,
    /// a mail destination (Obsolete - use MX)
    MD = 3,
    /// a mail forwarder (Obsolete - use MX)
    MF = 4,
    /// the canonical name for an alias
    CNAME = 5,
    /// marks the start of a zone of authority
    SOA = 6,
    /// a mailbox domain name (EXPERIMENTAL)
    MB = 7,
    /// a mail group member (EXPERIMENTAL)
    MG = 8,
    /// a mail rename domain name (EXPERIMENTAL)
    MR = 9,
    /// a null RR (EXPERIMENTAL)
    NULL = 10,
    /// a well known service description
    WKS = 11,
    /// a domain name pointer
    PTR = 12,
    /// host information
    HINFO = 13,
    /// mailbox or mail list information
    MINFO = 14,
    /// mail exchange
    MX = 15,
    /// text strings
    TXT = 16,
    /// aaaa host address
    AAAA = 28,
}
impl TypeField {
    /// Return the memory representation of this integer as a byte array in big-endian
    /// (network) byte order.
    fn to_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, std::io::Error> {
        let bytes = data.try_into().map_err(|_| ErrorKind::InvalidInput)?;
        let num = u16::from_be_bytes(bytes);
        match num {
            1 => Ok(TypeField::A),
            2 => Ok(TypeField::NS),
            3 => Ok(TypeField::MD),
            4 => Ok(TypeField::MF),
            5 => Ok(TypeField::CNAME),
            6 => Ok(TypeField::SOA),
            7 => Ok(TypeField::MB),
            8 => Ok(TypeField::MG),
            9 => Ok(TypeField::MR),
            10 => Ok(TypeField::NULL),
            11 => Ok(TypeField::WKS),
            12 => Ok(TypeField::PTR),
            13 => Ok(TypeField::HINFO),
            14 => Ok(TypeField::MINFO),
            15 => Ok(TypeField::MX),
            16 => Ok(TypeField::TXT),
            28 => Ok(TypeField::AAAA),
            _ => Err(Error::new(ErrorKind::Other, "Invalid TYPE field")),
        }
    }

    fn from_reader(reader: &mut Cursor<&[u8]>) -> Result<Self, std::io::Error> {
        let mut bytes = [0u8; 2];
        reader.read_exact(&mut bytes)?;
        TypeField::from_bytes(&bytes)
    }
}

/// CLASS fields appear in resource records.
#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum ClassField {
    /// the Internet
    IN = 1,
    /// the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CS = 2,
    /// the CHAOS class
    CH = 3,
    /// Hesiod [Dyer 87]
    HS = 4,
}
impl ClassField {
    /// Return the memory representation of this integer as a byte array in big-endian
    /// (network) byte order.
    fn to_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, std::io::Error> {
        let bytes = data.try_into().map_err(|_| ErrorKind::InvalidInput)?;
        let num = u16::from_be_bytes(bytes);
        match num {
            1 => Ok(ClassField::IN),
            2 => Ok(ClassField::CS),
            3 => Ok(ClassField::CH),
            4 => Ok(ClassField::HS),
            _ => Err(Error::new(ErrorKind::Other, "Invalid CLASS field")),
        }
    }

    fn from_reader(reader: &mut Cursor<&[u8]>) -> Result<Self, std::io::Error> {
        let mut bytes = [0u8; 2];
        reader.read_exact(&mut bytes)?;
        ClassField::from_bytes(&bytes)
    }
}

const DNS_HEADER_SIZE: usize = 12;

#[derive(Debug)]
pub struct DNSHeader {
    pub id: u16,
    pub flags: u16,
    pub num_questions: u16,
    pub num_answers: u16,
    pub num_authorities: u16,
    pub num_additionals: u16,
}
impl DNSHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(&self.num_questions.to_be_bytes());
        bytes.extend_from_slice(&self.num_answers.to_be_bytes());
        bytes.extend_from_slice(&self.num_authorities.to_be_bytes());
        bytes.extend_from_slice(&self.num_additionals.to_be_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, std::io::Error> {
        let id = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        let flags = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
        let num_questions = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
        let num_answers = u16::from_be_bytes(bytes[6..8].try_into().unwrap());
        let num_authorities = u16::from_be_bytes(bytes[8..10].try_into().unwrap());
        let num_additionals = u16::from_be_bytes(bytes[10..12].try_into().unwrap());

        Ok(DNSHeader {
            id,
            flags,
            num_questions,
            num_answers,
            num_authorities,
            num_additionals,
        })
    }

    pub fn from_reader(reader: &mut Cursor<&[u8]>) -> Result<Self, std::io::Error> {
        let mut bytes: [u8; DNS_HEADER_SIZE] = [0; DNS_HEADER_SIZE];
        reader.read_exact(&mut bytes)?;
        DNSHeader::from_bytes(&bytes)
    }
}

#[derive(Debug)]
pub struct DNSQuestion {
    pub name: DomainName,
    pub type_field: TypeField,
    pub class: ClassField,
}
impl DNSQuestion {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.name.to_bytes());
        bytes.extend_from_slice(&self.type_field.to_be_bytes());
        bytes.extend_from_slice(&self.class.to_be_bytes());
        bytes
    }

    pub fn from_reader(reader: &mut Cursor<&[u8]>) -> Result<Self, std::io::Error> {
        let name = DomainName::from_reader(reader)?;
        let type_field = TypeField::from_reader(reader)?;
        let class = ClassField::from_reader(reader)?;

        Ok(DNSQuestion {
            name,
            type_field,
            class,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DomainName {
    pub string: String,
}

impl DomainName {
    pub fn from(domain_name: &str) -> Self {
        let string = String::from(domain_name);
        DomainName {
            string: string.clone(),
        }
    }

    /// TODO rename as this is not simply converting to bytes, but it's actually
    /// encoding the domain name for DNS questions
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        for part in self.string.split(".") {
            bytes.push(part.len() as u8);
            bytes.extend_from_slice(part.as_bytes());
        }
        bytes.push(0);
        bytes
    }

    fn bytes_from_reader_compressed(
        length: u8,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<Vec<u8>, std::io::Error> {
        let mut offset_bytes: [u8; 1] = [0];
        reader.read_exact(&mut offset_bytes)?;
        let pointer_bytes: [u8; 2] = [length & 0b0011_1111, offset_bytes[0]];
        let pointer = u16::from_be_bytes(pointer_bytes);

        let curr_position = reader.position();
        reader.set_position(pointer as u64);
        let bytes = DomainName::bytes_from_reader(reader)?;
        reader.set_position(curr_position);

        Ok(bytes)
    }

    fn bytes_from_reader(reader: &mut Cursor<&[u8]>) -> Result<Vec<u8>, std::io::Error> {
        let mut bytes: Vec<Vec<u8>> = Vec::new();
        let mut should_read = true;
        while should_read {
            let mut length_bytes: [u8; 1] = [0; 1];
            reader.read_exact(&mut length_bytes)?;
            let length = length_bytes[0];
            // if the first two bits are 11 it means the domain name is compressed
            // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
            let is_compressed = (length & 0b1100_0000) != 0;
            if is_compressed {
                bytes.push(DomainName::bytes_from_reader_compressed(length, reader)?);
                should_read = false;
            } else if length > 0 {
                let mut buf = vec![0u8; length as usize];
                reader.read_exact(&mut buf)?;
                bytes.push(buf);
            } else {
                should_read = false;
            }
        }
        Ok(bytes.join(&u8::from(b'.')))
    }

    pub fn from_reader(reader: &mut Cursor<&[u8]>) -> Result<Self, std::io::Error> {
        let bytes: Vec<u8> = DomainName::bytes_from_reader(reader)?;
        let string = String::from_utf8(bytes.clone()).map_err(|_| ErrorKind::InvalidData)?;
        Ok(DomainName { string })
    }
}

#[derive(Debug)]
pub struct DNSRecord {
    /// the domain name
    pub name: DomainName,
    /// A, AAAA, MX, NS, TXT, etc (encoded as an integer)
    pub type_field: TypeField,
    /// always the same (1). We’ll ignore this.
    pub class: ClassField,
    /// how long to cache the query for. We’ll ignore this.
    pub ttl: u32,
    /// the record’s content, like the IP address.
    data: Vec<u8>,
    pub ipv4: Option<Vec<Ipv4Addr>>,
    pub ipv6: Option<Vec<Ipv6Addr>>,
    pub ns_name: Option<DomainName>,
}
impl DNSRecord {
    pub fn from_reader(reader: &mut Cursor<&[u8]>) -> Result<DNSRecord, std::io::Error> {
        let name = DomainName::from_reader(reader)?;
        let type_field = TypeField::from_reader(reader)?;
        let class = ClassField::from_reader(reader)?;

        let mut ttl_bytes = [0u8; 4];
        reader.read_exact(&mut ttl_bytes)?;
        let ttl = u32::from_be_bytes(ttl_bytes);

        let mut data_len_bytes = [0u8; 2];
        reader.read_exact(&mut data_len_bytes)?;

        let data_len = u16::from_be_bytes(data_len_bytes);
        let mut data = vec![0u8; data_len as usize];
        let data_position = reader.position();
        reader.read_exact(&mut data)?;

        let ns_name = if type_field == TypeField::NS {
            reader.set_position(data_position);
            Some(DomainName::from_reader(reader)?)
        } else {
            None
        };

        let ipv4: Option<Vec<Ipv4Addr>> = match type_field {
            TypeField::A => Some(
                data.chunks(4)
                    .map(|chunk| ipv4_addr_from_bytes(chunk))
                    .collect(),
            ),
            _ => None,
        };
        let ipv6: Option<Vec<Ipv6Addr>> = match type_field {
            TypeField::AAAA => Some(
                data.chunks(16)
                    .map(|chunk: &[u8]| ipv6_addr_from_bytes(&chunk))
                    .collect(),
            ),
            _ => None,
        };

        Ok(DNSRecord {
            name,
            type_field,
            class,
            ttl,
            data,
            ipv4,
            ipv6,
            ns_name,
        })
    }
}

#[derive(Debug)]
pub struct DNSPacket {
    pub header: DNSHeader,
    pub questions: Vec<DNSQuestion>,
    pub answers: Vec<DNSRecord>,
    pub authorities: Vec<DNSRecord>,
    pub additionals: Vec<DNSRecord>,
}
impl DNSPacket {
    pub fn from(data: &[u8]) -> Result<Self, std::io::Error> {
        let mut reader = Cursor::new(data);

        let header = DNSHeader::from_reader(&mut reader)?;

        let mut questions = vec![];
        for _ in 0..header.num_questions {
            questions.push(DNSQuestion::from_reader(&mut reader)?);
        }

        let mut answers = vec![];
        for _ in 0..header.num_answers {
            answers.push(DNSRecord::from_reader(&mut reader)?);
        }

        let mut authorities = vec![];
        for _ in 0..header.num_authorities {
            authorities.push(DNSRecord::from_reader(&mut reader)?);
        }

        let mut additionals = vec![];
        for _ in 0..header.num_additionals {
            additionals.push(DNSRecord::from_reader(&mut reader)?);
        }

        Ok(DNSPacket {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    pub fn get_answer(&self) -> Option<&DNSRecord> {
        self.answers.iter().find(|x| x.type_field == TypeField::A)
    }

    pub fn get_nameserver_record(&self) -> Option<&DNSRecord> {
        self.additionals
            .iter()
            .find(|x| x.type_field == TypeField::A)
    }

    pub fn get_nameserver(&self) -> Option<&DNSRecord> {
        self.authorities
            .iter()
            .find(|x| x.type_field == TypeField::NS)
    }
}

pub fn build_query(domain_name: &DomainName, type_field: TypeField) -> Vec<u8> {
    let id = rand::random::<u16>();
    let header = DNSHeader {
        id,
        flags: 0,
        num_questions: 1,
        num_answers: 0,
        num_authorities: 0,
        num_additionals: 0,
    };
    let question = DNSQuestion {
        name: domain_name.clone(),
        type_field,
        class: ClassField::IN,
    };
    let mut bytes = header.to_bytes();
    bytes.extend_from_slice(&question.to_bytes());
    bytes
}

fn send_query(socket_address: Ipv4Addr, socket_buf: &[u8]) -> Result<DNSPacket, std::io::Error> {
    let socket = UdpSocket::bind("0.0.0.0:34254").expect("couldn't bind to address");
    socket.connect(socket_address.to_string() + ":53")?;
    socket.send(socket_buf)?;

    let mut buf = [0; 1024];
    let (_amt, _src) = socket.recv_from(&mut buf)?;

    DNSPacket::from(&buf)
}

pub fn resolve(
    domain_name: &DomainName,
    type_field: TypeField,
) -> Result<Ipv4Addr, std::io::Error> {
    let mut name_server = Ipv4Addr::new(198, 41, 0, 4);
    loop {
        log::info!("Querying {} for {}", name_server, domain_name.string);
        let query = build_query(domain_name, type_field);
        let packet = send_query(name_server, query.as_slice())?;
        if let Some(answer) = packet.get_answer() {
            if let Some(ip) = answer.ipv4.as_ref().and_then(|x| x.first()) {
                return Ok(*ip);
            }
        } else if let Some(name_server_ip) = packet
            .get_nameserver_record()
            .and_then(|x| x.ipv4.as_ref().and_then(|x| x.first()))
        {
            name_server = *name_server_ip;
        } else if let Some(ns_domain) = packet.get_nameserver().and_then(|x| x.ns_name.as_ref()) {
            name_server = resolve(ns_domain, TypeField::A)?;
        } else {
            log::error!(
                "No answer found for {} at {}",
                domain_name.string,
                name_server
            );
            return Err(Error::new(
                ErrorKind::Other,
                "No answer found for domain name",
            ));
        }
    }
}
