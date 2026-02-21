#[cfg(test)]
use std::io::Read;
use std::net::Ipv4Addr;
use std::str;

const PACKET_SIZE: usize = 512;
const MAX_NAME_JUMPS: u8 = 10;

#[derive(Debug)]
struct PacketBuf<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> PacketBuf<'a> {
    fn new(buf: &'a [u8]) -> Self {
        let n = buf.len();
        assert!(0 < n && n <= PACKET_SIZE);
        Self { buf, pos: 0 }
    }

    fn read_range(&mut self, start: usize, n: usize) -> Option<&[u8]> {
        let bytes = self.buf.get(start..start + n)?;
        self.pos += n;
        Some(bytes)
    }

    fn read<T: FromBytes>(&mut self) -> Option<T> {
        T::from_bytes(self)
    }

    #[cfg(test)]
    fn reset(&mut self) {
        self.pos = 0;
    }

    fn header(&mut self) -> Option<DnsHeader> {
        let id: u16 = self.read()?;

        let byte: u8 = self.read()?;
        let qr = (byte & (1 << 7)) > 0;
        let opcode = (byte >> 3) & 0x0F;
        let aa = (byte & (1 << 2)) > 0;
        let tc = (byte & (1 << 1)) > 0;
        let rd = (byte & (1 << 0)) > 0;

        let byte: u8 = self.read()?;
        let ra = (byte & 1 << 7) > 0;
        let z = (byte & 1 << 6) > 0;
        let ad = (byte & 1 << 5) > 0;
        let cd = (byte & 1 << 4) > 0;
        let rcode = RCode::from_num(byte & 0x0F);

        let qdcount: u16 = self.read()?;
        let ancount: u16 = self.read()?;
        let nscount: u16 = self.read()?;
        let arcount: u16 = self.read()?;

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

    fn read_label(&mut self, mut byte: u8) -> Option<String> {
        let mut name = String::new();

        loop {
            let bytes = self.read_range(self.pos, byte as usize)?;
            name.push_str(str::from_utf8(bytes).ok()?);

            byte = self.read()?;
            if byte == 0x00 {
                break;
            }
            name.push('.');
        }

        Some(name)
    }

    fn question(&mut self) -> Option<DnsQuestion> {
        let byte: u8 = self.read()?;

        let name = self.read_label(byte)?;
        let r#type: u16 = self.read()?;
        let class: u16 = self.read()?;

        Some(DnsQuestion {
            name,
            r#type: QueryType::from(r#type),
            class,
        })
    }

    fn record(&mut self) -> Option<DnsRecord> {
        let mut jumps = 0;
        let mut jumped = false;
        let mut saved_pos = 0;
        let mut byte: u8 = self.read()?;

        let name = loop {
            if byte ^ 0xC0 != 0x00 {
                break self.read_label(byte)?;
            }

            // to prevent an infinite loop by a malicious packet
            if jumps >= MAX_NAME_JUMPS {
                return None;
            }
            jumps += 1;

            let byte_2: u8 = self.read()?;
            let new_pos = (((byte ^ 0xC0) as u16) << 8 | byte_2 as u16) as usize;

            if !jumped {
                jumped = true;
                saved_pos = self.pos;
            }

            self.pos = new_pos; // reset
            byte = self.read()?;
        };

        if jumped {
            self.pos = saved_pos;
        }

        let r#type: u16 = self.read()?;
        let class: u16 = self.read()?;
        let ttl: u32 = self.read()?;
        let len: u16 = self.read()?;
        let ip: u32 = self.read()?;

        Some(DnsRecord::A {
            domain: name,
            r#type: QueryType::from(r#type),
            class,
            ttl,
            len,
            ip: Ipv4Addr::from_bits(ip),
        })
    }
}

trait FromBytes: Sized {
    fn from_bytes(packet_buf: &mut PacketBuf) -> Option<Self>;
}

impl FromBytes for u8 {
    fn from_bytes(packet_buf: &mut PacketBuf) -> Option<Self> {
        let byte = *packet_buf.buf.get(packet_buf.pos)?;
        packet_buf.pos += 1;
        Some(byte)
    }
}

impl FromBytes for u16 {
    fn from_bytes(packet_buf: &mut PacketBuf) -> Option<Self> {
        let bytes = packet_buf.read_range(packet_buf.pos, 2)?.try_into().ok()?;
        Some(u16::from_be_bytes(bytes))
    }
}

impl FromBytes for u32 {
    fn from_bytes(packet_buf: &mut PacketBuf) -> Option<Self> {
        let bytes = packet_buf.read_range(packet_buf.pos, 4)?.try_into().ok()?;
        Some(u32::from_be_bytes(bytes))
    }
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
        let mut packet_buf = PacketBuf::new(buf);

        let header = packet_buf.header()?;

        let mut questions = Vec::with_capacity(header.qdcount as usize);
        for _ in 0..header.qdcount {
            questions.push(packet_buf.question()?);
        }

        let mut answers = Vec::with_capacity(header.ancount as usize);
        for _ in 0..header.ancount {
            answers.push(packet_buf.record()?);
        }

        let mut authorities = Vec::with_capacity(header.nscount as usize);
        for _ in 0..header.nscount {
            authorities.push(packet_buf.record()?);
        }

        let mut resources = Vec::with_capacity(header.arcount as usize);
        for _ in 0..header.arcount {
            resources.push(packet_buf.record()?);
        }

        Some(DnsPacket {
            header,
            questions,
            answers,
            authorities,
            resources,
        })
    }

    #[cfg(test)]
    fn from_reader<R: Read>(mut reader: R) -> Option<Self> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).ok()?;
        Self::from_bytes(&buf)
    }
}

#[derive(Debug, PartialEq)]
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

#[non_exhaustive]
#[derive(Debug, PartialEq)]
enum QueryType {
    A,
}

impl From<u16> for QueryType {
    fn from(value: u16) -> Self {
        match value {
            1 => QueryType::A,
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug)]
struct DnsQuestion {
    name: String,
    r#type: QueryType,
    class: u16,
}

#[non_exhaustive]
#[derive(Debug)]
enum DnsRecord {
    A {
        domain: String,
        r#type: QueryType,
        class: u16,
        ttl: u32,
        len: u16,
        ip: Ipv4Addr,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::io::BufReader;

    #[test]
    fn from_raw_bytes() {
        let bytes = [155, 81, 129, 128];
        let mut packet_buf = PacketBuf::new(&bytes[..]);

        let one: u8 = packet_buf.read().unwrap();
        assert_eq!(one, 155);
        packet_buf.reset();

        let two: u16 = packet_buf.read().unwrap();
        assert_eq!(two, 155 << 8 | 81);
        packet_buf.reset();

        let three: u32 = packet_buf.read().unwrap();
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

        let DnsRecord::A {
            domain,
            r#type,
            class,
            ttl,
            len,
            ip,
        } = &packet.answers[0];
        assert_eq!(domain, "google.com");
        assert_eq!(*r#type, QueryType::A);
        assert_eq!(*class, 1);
        assert_eq!(*ttl, 150);
        assert_eq!(*len, 4);
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
}
