#![allow(unused)]

#[cfg(test)]
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};

const PACKET_SIZE: usize = 512;
const MAX_NAME_JUMPS: u8 = 10;

#[derive(Debug)]
struct PacketBufReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> PacketBufReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        let n = buf.len();
        assert!(0 < n && n <= PACKET_SIZE);
        Self { buf, pos: 0 }
    }

    fn read_u8(&mut self) -> Option<u8> {
        let byte = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(byte)
    }

    fn read_u16(&mut self) -> Option<u16> {
        let hi = self.read_u8()? as u16;
        let lo = self.read_u8()? as u16;
        Some(hi << 8 | lo)
    }

    fn read_u32(&mut self) -> Option<u32> {
        let hi = self.read_u16()? as u32;
        let lo = self.read_u16()? as u32;
        Some(hi << 16 | lo)
    }

    fn read_u128(&mut self) -> Option<u128> {
        let a = self.read_u32()? as u128;
        let b = self.read_u32()? as u128;
        let c = self.read_u32()? as u128;
        let d = self.read_u32()? as u128;
        Some(a << 96 | b << 64 | c << 32 | d)
    }

    fn read_name(&mut self) -> Option<String> {
        let mut name = String::new();
        let mut jumps = 0;
        let mut jumped = false;
        let mut saved_pos = 0;

        loop {
            let byte = self.read_u8()?;

            if byte & 0xC0 == 0xC0 {
                // to prevent an infinite loop by a malicious packet
                if jumps >= MAX_NAME_JUMPS {
                    return None;
                }
                jumps += 1;

                let byte_2 = self.read_u8()?;
                let new_pos = ((byte as u16 & 0x3F) << 8 | byte_2 as u16) as usize;

                if !jumped {
                    jumped = true;
                    saved_pos = self.pos;
                }

                self.pos = new_pos;
                continue;
            }

            if byte == 0x00 {
                break;
            }

            if !name.is_empty() {
                name.push('.');
            }

            for _ in 0..byte {
                name.push(self.read_u8()? as char);
            }
        }

        if jumped {
            self.pos = saved_pos;
        }

        Some(name)
    }

    #[cfg(test)]
    fn reset(&mut self) {
        self.pos = 0;
    }
}

trait FromBytes: Sized {
    fn from_bytes(reader: &mut PacketBufReader) -> Option<Self>;
}

#[derive(Debug)]
struct PacketBufWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> PacketBufWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        let n = buf.len();
        assert!(0 < n && n <= PACKET_SIZE);
        Self { buf, pos: 0 }
    }

    fn write_u8(&mut self, val: u8) -> Option<()> {
        if self.pos >= self.buf.len() {
            return None;
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Some(())
    }

    fn write_u16(&mut self, val: u16) -> Option<()> {
        self.write_u8((val >> 8) as u8)?;
        self.write_u8((val & 0xFF) as u8)?;
        Some(())
    }

    fn write_u32(&mut self, val: u32) -> Option<()> {
        self.write_u8((val >> 24) as u8)?;
        self.write_u8((val >> 16 & 0xFF) as u8)?;
        self.write_u8((val >> 8 & 0xFF) as u8)?;
        self.write_u8((val & 0xFF) as u8)?;
        Some(())
    }

    fn write_u128(&mut self, val: u128) -> Option<()> {
        self.write_u32((val >> 96) as u32)?;
        self.write_u32((val >> 64) as u32)?;
        self.write_u32((val >> 32) as u32)?;
        self.write_u32(val as u32)?;
        Some(())
    }

    fn write_name(&mut self, name: &str) -> Option<()> {
        for label in name.split('.') {
            let len = label.len();
            if len > 63 {
                return None;
            }
            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }
        self.write_u8(0)?;
        Some(())
    }
}

trait ToBytes {
    fn to_bytes(&self, writer: &mut PacketBufWriter) -> Option<()>;
}

#[derive(Debug)]
struct DnsPacket {
    header: DnsHeader,
    questions: Vec<DnsQuestion>,
    answers: Vec<DnsRecord>,
    authorities: Vec<DnsRecord>,
    resources: Vec<DnsRecord>,
}

impl DnsPacket {
    fn from_bytes(buf: &[u8]) -> Option<Self> {
        let mut reader = PacketBufReader::new(buf);

        let header = DnsHeader::from_bytes(&mut reader)?;

        let mut questions = Vec::with_capacity(header.qdcount as usize);
        for _ in 0..header.qdcount {
            questions.push(DnsQuestion::from_bytes(&mut reader)?);
        }

        let mut answers = Vec::with_capacity(header.ancount as usize);
        for _ in 0..header.ancount {
            answers.push(DnsRecord::from_bytes(&mut reader)?);
        }

        let mut authorities = Vec::with_capacity(header.nscount as usize);
        for _ in 0..header.nscount {
            authorities.push(DnsRecord::from_bytes(&mut reader)?);
        }

        let mut resources = Vec::with_capacity(header.arcount as usize);
        for _ in 0..header.arcount {
            resources.push(DnsRecord::from_bytes(&mut reader)?);
        }

        Some(DnsPacket {
            header,
            questions,
            answers,
            authorities,
            resources,
        })
    }

    fn to_bytes(&self, buf: &mut [u8]) -> Option<()> {
        assert_eq!(buf.len(), PACKET_SIZE);

        let mut temp = [0u8; PACKET_SIZE]; // to keep buf untouched on midway failures
        let mut writer = PacketBufWriter::new(&mut temp);

        self.header.to_bytes(&mut writer)?;

        for q in &self.questions {
            q.to_bytes(&mut writer)?;
        }
        for ans in &self.answers {
            ans.to_bytes(&mut writer)?;
        }
        for auth in &self.authorities {
            auth.to_bytes(&mut writer)?;
        }
        for r in &self.resources {
            r.to_bytes(&mut writer)?;
        }

        buf.copy_from_slice(&temp);

        Some(())
    }

    #[cfg(test)]
    fn from_reader<R: Read>(mut reader: R) -> Option<Self> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).ok()?;
        Self::from_bytes(&buf)
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum RCode {
    Noerror = 0,
    Formerr = 1,
    Servfail = 2,
    Nxdomain = 3,
    Notimp = 4,
    Refused = 5,
}

impl RCode {
    fn from_num(num: u8) -> RCode {
        match num {
            1 => RCode::Formerr,
            2 => RCode::Servfail,
            3 => RCode::Nxdomain,
            4 => RCode::Notimp,
            5 => RCode::Refused,
            _ => RCode::Noerror,
        }
    }
}

#[derive(Debug)]
struct DnsHeader {
    id: u16,

    // query response
    qr: bool,
    // operation code
    opcode: u8,
    // authoritative answer
    aa: bool,
    // truncated message
    tc: bool,
    // recursion desired
    rd: bool,

    // recursion available
    ra: bool,
    // reserved
    z: bool,
    // authed data
    ad: bool,
    // checking disabled
    cd: bool,
    // response code
    rcode: RCode,

    // question count
    qdcount: u16,
    // answer count
    ancount: u16,
    // authority count
    nscount: u16,
    // additional count
    arcount: u16,
}

impl FromBytes for DnsHeader {
    fn from_bytes(reader: &mut PacketBufReader) -> Option<Self> {
        let id = reader.read_u16()?;

        let byte = reader.read_u8()?;
        let qr = (byte & (1 << 7)) > 0;
        let opcode = (byte >> 3) & 0x0F;
        let aa = (byte & (1 << 2)) > 0;
        let tc = (byte & (1 << 1)) > 0;
        let rd = (byte & 1) > 0;

        let byte = reader.read_u8()?;
        let ra = (byte & (1 << 7)) > 0;
        let z = (byte & (1 << 6)) > 0;
        let ad = (byte & (1 << 5)) > 0;
        let cd = (byte & (1 << 4)) > 0;
        let rcode = RCode::from_num(byte & 0x0F);

        let qdcount = reader.read_u16()?;
        let ancount = reader.read_u16()?;
        let nscount = reader.read_u16()?;
        let arcount = reader.read_u16()?;

        Some(DnsHeader {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            ad,
            cd,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }
}

impl ToBytes for DnsHeader {
    fn to_bytes(&self, writer: &mut PacketBufWriter) -> Option<()> {
        writer.write_u16(self.id)?;

        let byte: u8 = (self.qr as u8) << 7
            | self.opcode << 3
            | (self.aa as u8) << 2
            | (self.tc as u8) << 1
            | self.rd as u8;
        writer.write_u8(byte)?;

        let byte: u8 = (self.ra as u8) << 7
            | (self.z as u8) << 6
            | (self.ad as u8) << 5
            | (self.cd as u8) << 4
            | self.rcode as u8;
        writer.write_u8(byte)?;

        writer.write_u16(self.qdcount)?;
        writer.write_u16(self.ancount)?;
        writer.write_u16(self.nscount)?;
        writer.write_u16(self.arcount)?;

        Some(())
    }
}

#[non_exhaustive]
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Clone, Copy)]
enum QueryType {
    A,
    NS,
    CNAME,
    MX,
    AAAA,
}

impl From<u16> for QueryType {
    fn from(value: u16) -> Self {
        match value {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => unimplemented!(),
        }
    }
}

impl From<QueryType> for u16 {
    fn from(value: QueryType) -> Self {
        match value {
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }
}

#[derive(Debug)]
struct DnsQuestion {
    name: String,
    r#type: QueryType,
    class: u16,
}

impl FromBytes for DnsQuestion {
    fn from_bytes(reader: &mut PacketBufReader) -> Option<Self> {
        let name = reader.read_name()?;
        let r#type = QueryType::from(reader.read_u16()?);
        let class = reader.read_u16()?;

        Some(DnsQuestion {
            name,
            r#type,
            class,
        })
    }
}

impl ToBytes for DnsQuestion {
    fn to_bytes(&self, writer: &mut PacketBufWriter) -> Option<()> {
        writer.write_name(&self.name)?;
        writer.write_u16(self.r#type.into())?;
        writer.write_u16(self.class)?;
        Some(())
    }
}

fn wire_name_len(name: &str) -> u16 {
    // sum of each label's length + 1 byte per label for the length prefix
    // + 1 for the terminator
    (name.split('.').map(|l| l.len() + 1).sum::<usize>() + 1) as u16
}

#[derive(Debug)]
struct DnsRecord {
    domain: String,
    r#type: QueryType,
    class: u16,
    ttl: u32,
    rdata: RData,
}

#[non_exhaustive]
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
enum RData {
    A { ip: Ipv4Addr },
    NS { host: String },
    CNAME { host: String },
    MX { priority: u16, host: String },
    AAAA { ip: Ipv6Addr },
}

impl FromBytes for DnsRecord {
    fn from_bytes(reader: &mut PacketBufReader) -> Option<Self> {
        let domain = reader.read_name()?;
        let r#type = QueryType::from(reader.read_u16()?);
        let class = reader.read_u16()?;
        let ttl = reader.read_u32()?;
        let _len = reader.read_u16()?;

        let rdata = match r#type {
            QueryType::A => RData::A {
                ip: Ipv4Addr::from_bits(reader.read_u32()?),
            },
            QueryType::NS => RData::NS {
                host: reader.read_name()?,
            },
            QueryType::CNAME => RData::CNAME {
                host: reader.read_name()?,
            },
            QueryType::MX => RData::MX {
                priority: reader.read_u16()?,
                host: reader.read_name()?,
            },
            QueryType::AAAA => RData::AAAA {
                ip: Ipv6Addr::from_bits(reader.read_u128()?),
            },
        };

        Some(DnsRecord {
            domain,
            r#type,
            class,
            ttl,
            rdata,
        })
    }
}

impl ToBytes for DnsRecord {
    fn to_bytes(&self, writer: &mut PacketBufWriter) -> Option<()> {
        writer.write_name(&self.domain)?;
        writer.write_u16(self.r#type.into())?;
        writer.write_u16(self.class)?;
        writer.write_u32(self.ttl)?;

        let rdlen = match &self.rdata {
            RData::A { .. } => 4,     // Ipv4addr
            RData::AAAA { .. } => 16, // Ipv6addr
            RData::NS { host } | RData::CNAME { host } => wire_name_len(host),
            RData::MX { host, .. } => 2 + wire_name_len(host), // priority + host
        };
        writer.write_u16(rdlen)?;

        match &self.rdata {
            RData::A { ip } => writer.write_u32(ip.to_bits())?,
            RData::NS { host } | RData::CNAME { host } => writer.write_name(host)?,
            RData::MX { priority, host } => {
                writer.write_u16(*priority)?;
                writer.write_name(host)?;
            }
            RData::AAAA { ip } => writer.write_u128(ip.to_bits())?,
        }

        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::io::BufReader;
    use std::net::UdpSocket;

    fn query(name: &str, qtype: QueryType) -> DnsPacket {
        let query = DnsPacket {
            header: DnsHeader {
                id: 6666,
                qr: false,
                opcode: 0,
                aa: false,
                tc: false,
                rd: true,
                ra: false,
                z: false,
                ad: false,
                cd: false,
                rcode: RCode::Noerror,
                qdcount: 1,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![DnsQuestion {
                name: name.to_string(),
                r#type: qtype,
                class: 1,
            }],
            answers: vec![],
            authorities: vec![],
            resources: vec![],
        };

        let mut req_buf = [0u8; PACKET_SIZE];
        query.to_bytes(&mut req_buf).unwrap();

        let socket = UdpSocket::bind(("0.0.0.0", 0)).unwrap();
        socket.send_to(&req_buf, ("8.8.8.8", 53)).unwrap();

        let mut res_buf = [0u8; PACKET_SIZE];
        socket.recv_from(&mut res_buf).unwrap();

        DnsPacket::from_bytes(&res_buf).unwrap()
    }

    #[test]
    fn from_raw_bytes() {
        let bytes = [155, 81, 129, 128];
        let mut reader = PacketBufReader::new(&bytes[..]);

        let one = reader.read_u8().unwrap();
        assert_eq!(one, 155);
        reader.reset();

        let two = reader.read_u16().unwrap();
        assert_eq!(two, 155 << 8 | 81);
        reader.reset();

        let three = reader.read_u32().unwrap();
        assert_eq!(three, 155 << 24 | 81 << 16 | 129 << 8 | 128);
    }

    #[test]
    fn parse_response_packet() {
        let f = File::open("response_packet.txt").unwrap();
        let reader = BufReader::new(f);
        let packet = DnsPacket::from_reader(reader).unwrap();

        assert_eq!(packet.header.id, 39761);
        assert!(packet.header.qr);
        assert_eq!(packet.header.opcode, 0);
        assert!(!packet.header.aa);
        assert!(!packet.header.tc);
        assert!(packet.header.rd);
        assert!(packet.header.ra);
        assert!(!packet.header.z);
        assert!(!packet.header.ad);
        assert!(!packet.header.cd);
        assert_eq!(packet.header.rcode, RCode::Noerror);
        assert_eq!(packet.header.qdcount, 1);
        assert_eq!(packet.header.ancount, 1);
        assert_eq!(packet.header.nscount, 0);
        assert_eq!(packet.header.arcount, 0);

        let q = &packet.questions[0];
        assert_eq!(q.name, "google.com");
        assert_eq!(q.r#type, QueryType::A);
        assert_eq!(q.class, 1);

        let rec = &packet.answers[0];
        assert_eq!(rec.domain, "google.com");
        assert_eq!(rec.r#type, QueryType::A);
        assert_eq!(rec.class, 1);
        assert_eq!(rec.ttl, 150);
        let RData::A { ip } = &rec.rdata else {
            panic!("not A record")
        };
        assert_eq!(*ip, Ipv4Addr::new(142, 250, 197, 142));

        assert!(packet.authorities.is_empty());
        assert!(packet.resources.is_empty());
    }

    #[test]
    fn parse_query_packet() {
        let f = File::open("query_packet.txt").unwrap();
        let reader = BufReader::new(f);
        let packet = DnsPacket::from_reader(reader).unwrap();

        assert!(!packet.header.qr);
        assert_eq!(packet.header.qdcount, 1);
        assert_eq!(packet.header.ancount, 0);
        assert_eq!(packet.header.nscount, 0);
        assert_eq!(packet.header.arcount, 0);

        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].name, "google.com");
        assert_eq!(packet.questions[0].r#type, QueryType::A);
        assert_eq!(packet.questions[0].class, 1);

        assert!(packet.answers.is_empty());
        assert!(packet.authorities.is_empty());
        assert!(packet.resources.is_empty());
    }

    #[test]
    #[ignore]
    fn stub_resolver() {
        let response = query("google.com", QueryType::A);

        assert_eq!(response.header.id, 6666);
        assert!(response.header.qr);
        assert_eq!(response.header.opcode, 0);
        assert!(response.header.rd);
        assert!(response.header.ra);
        assert_eq!(response.header.rcode, RCode::Noerror);
        assert_eq!(response.header.qdcount, 1);
        assert!(response.header.ancount >= 1);

        assert_eq!(response.questions.len(), 1);
        assert_eq!(response.questions[0].name, "google.com");
        assert_eq!(response.questions[0].r#type, QueryType::A);
        assert_eq!(response.questions[0].class, 1);

        assert!(!response.answers.is_empty());
        let rec = &response.answers[0];
        assert_eq!(rec.domain, "google.com");
        assert_eq!(rec.r#type, QueryType::A);
        assert_eq!(rec.class, 1);

        println!("{:#?}", response);
    }

    #[test]
    #[ignore]
    fn lookup_yahoo_a() {
        let response = query("www.yahoo.com", QueryType::A);

        assert_eq!(response.header.rcode, RCode::Noerror);
        assert!(response.header.ancount >= 2);

        // First answer should be a CNAME pointing away from www.yahoo.com
        let first = &response.answers[0];
        assert_eq!(first.domain, "www.yahoo.com");
        assert!(matches!(first.rdata, RData::CNAME { .. }));

        // Remaining answers should be A records
        for rec in &response.answers[1..] {
            assert!(matches!(rec.rdata, RData::A { .. }));
        }

        println!("{:#?}", response);
    }

    #[test]
    #[ignore]
    fn lookup_yahoo_mx() {
        let response = query("yahoo.com", QueryType::MX);

        assert_eq!(response.header.rcode, RCode::Noerror);
        assert!(response.header.ancount >= 1);

        for rec in &response.answers {
            assert_eq!(rec.r#type, QueryType::MX);
            let RData::MX { priority, host } = &rec.rdata else {
                panic!("expected MX record");
            };
            assert!(*priority > 0);
            assert!(!host.is_empty());
        }

        println!("{:#?}", response);
    }

    #[test]
    #[ignore]
    fn lookup_google_aaaa() {
        let response = query("google.com", QueryType::AAAA);

        assert_eq!(response.header.rcode, RCode::Noerror);
        assert!(response.header.ancount >= 1);

        let rec = &response.answers[0];
        assert_eq!(rec.domain, "google.com");
        assert_eq!(rec.r#type, QueryType::AAAA);
        let RData::AAAA { ip } = &rec.rdata else {
            panic!("expected AAAA record");
        };
        assert!(ip.to_string().contains(':'));

        println!("{:#?}", response);
    }
}
