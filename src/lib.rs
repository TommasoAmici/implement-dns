use std::io::{Cursor, Error, ErrorKind, Read};
use std::net::Ipv4Addr;

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

#[derive(Debug)]
pub struct DomainName {
    bytes: Vec<u8>,
    string: String,
}

impl DomainName {
    pub fn from(domain_name: &str) -> Self {
        let string = String::from(domain_name);
        DomainName {
            string: string.clone(),
            bytes: string.into_bytes(),
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

    fn from_reader_compressed(
        length: u8,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<Self, std::io::Error> {
        let mut offset_bytes: [u8; 1] = [0];
        reader.read_exact(&mut offset_bytes)?;
        let pointer_bytes: [u8; 2] = [length & 0b0011_1111, offset_bytes[0]];
        let pointer = u16::from_be_bytes(pointer_bytes);

        let curr_position = reader.position();
        reader.set_position(pointer as u64);
        let domain_name = DomainName::from_reader(reader)?;
        reader.set_position(curr_position);
        Ok(domain_name)
    }

    pub fn from_reader(reader: &mut Cursor<&[u8]>) -> Result<Self, std::io::Error> {
        let mut bytes: Vec<u8> = Vec::new();
        let mut should_read = true;
        while should_read {
            let mut length_bytes: [u8; 1] = [0; 1];
            reader.read_exact(&mut length_bytes)?;
            let length = length_bytes[0];
            // if the first two bits are 11 it means the domain name is compressed
            // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
            let is_compressed = (length & 0b1100_0000) != 0;
            if is_compressed {
                return DomainName::from_reader_compressed(length, reader);
            } else if length > 0 {
                let mut buf = vec![0u8; length as usize];
                reader.read_exact(&mut buf)?;
                bytes.extend_from_slice(&buf);
                bytes.extend_from_slice(".".as_bytes());
            } else {
                should_read = false
            }
        }
        let string = String::from_utf8(bytes.clone()).map_err(|_| ErrorKind::InvalidData)?;
        Ok(DomainName { bytes, string })
    }
}

#[derive(Debug)]
struct DNSRecord {
    /// the domain name
    name: DomainName,
    /// A, AAAA, MX, NS, TXT, etc (encoded as an integer)
    type_field: TypeField,
    /// always the same (1). We’ll ignore this.
    class: ClassField,
    /// how long to cache the query for. We’ll ignore this.
    ttl: u32,
    /// the record’s content, like the IP address.
    data: Vec<u8>,
    pub ipv4: Vec<Ipv4Addr>,
}
impl DNSRecord {
    pub fn from_bytes(reader: &mut Cursor<&[u8]>) -> Result<DNSRecord, std::io::Error> {
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
        reader.read_exact(&mut data)?;

        let ipv4: Vec<Ipv4Addr> = match type_field {
            TypeField::A => data
                .chunks(4)
                .map(|chunk| Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]))
                .collect(),
            _ => vec![],
        };

        Ok(DNSRecord {
            name,
            type_field,
            class,
            ttl,
            data,
            ipv4,
        })
    }
}

#[derive(Debug)]
pub struct DNSPacket {
    header: DNSHeader,
    questions: Vec<DNSQuestion>,
    answers: Vec<DNSRecord>,
    authorities: Vec<DNSRecord>,
    additionals: Vec<DNSRecord>,
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
            answers.push(DNSRecord::from_bytes(&mut reader)?);
        }

        let mut authorities = vec![];
        for _ in 0..header.num_authorities {
            authorities.push(DNSRecord::from_bytes(&mut reader)?);
        }

        let mut additionals = vec![];
        for _ in 0..header.num_additionals {
            additionals.push(DNSRecord::from_bytes(&mut reader)?);
        }

        Ok(DNSPacket {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }
}

pub fn build_query(domain_name: DomainName, type_field: TypeField) -> Vec<u8> {
    let id = rand::random::<u16>();
    let recursion_desired = 1 << 8;
    let header = DNSHeader {
        id,
        flags: recursion_desired,
        num_questions: 1,
        num_answers: 0,
        num_authorities: 0,
        num_additionals: 0,
    };
    let question = DNSQuestion {
        name: domain_name,
        type_field,
        class: ClassField::IN,
    };
    let mut bytes = header.to_bytes();
    bytes.extend_from_slice(&question.to_bytes());
    bytes
}
