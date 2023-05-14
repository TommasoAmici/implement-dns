/// TYPE fields are used in resource records.  Note that these
/// types are a subset of QTYPEs.
/// See https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
#[derive(Debug, Clone, Copy)]
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
}
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

}

#[derive(Debug)]
pub struct DNSQuestion {
    pub name: Vec<u8>,
    pub type_field: TypeField,
    pub class: ClassField,
}
impl DNSQuestion {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.name);
        bytes.extend_from_slice(&self.type_field.to_be_bytes());
        bytes.extend_from_slice(&self.class.to_be_bytes());
        bytes
    }
}

#[derive(Debug)]
pub struct DomainName(String);

impl DomainName {
    pub fn from(domain_name: &str) -> Self {
        DomainName(String::from(domain_name))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        for part in self.0.split(".") {
            bytes.push(part.len() as u8);
            bytes.extend_from_slice(part.as_bytes());
        }
        bytes.push(0);
        bytes
    }
}

pub fn build_query(domain_name: &DomainName, type_field: TypeField) -> Vec<u8> {
    // let id = rand::random::<u16>();
    let id = 0x8298;
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
        name: domain_name.to_bytes(),
        type_field,
        class: ClassField::IN,
    };
    let mut bytes = header.to_bytes();
    bytes.extend_from_slice(&question.to_bytes());
    bytes
}
