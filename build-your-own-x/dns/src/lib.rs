const PACKET_SIZE: usize = 512;

#[derive(Debug)]
struct PacketBuf<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> PacketBuf<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::io::{self, BufReader, Read};

    fn from_reader<R: Read>(mut reader: R) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Ok(buf)
    }

    #[test]
    fn from_raw_bytes() {
        let mut bytes = [155, 81, 129, 128];
        let mut packet_buf = PacketBuf::new(&mut bytes[..]);

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
    fn parse_static() {
        let f = File::open("response_packet.txt").unwrap();
        let reader = BufReader::new(f);

        let mut buf = from_reader(reader).unwrap();
        let mut packet_buf = PacketBuf::new(&mut buf);

        let header = packet_buf.header().unwrap();
        assert_eq!(header.id, 39761);
        assert!(header.qr);
        assert_eq!(header.opcode, 0);
        assert!(!header.aa);
        assert!(!header.tc);
        assert!(header.rd);
        assert!(header.ra);
        assert!(!header.z);
        assert!(!header.ad);
        assert!(!header.cd);
        assert_eq!(header.rcode, RCode::Noerror);
        assert_eq!(header.qdcount, 1);
        assert_eq!(header.ancount, 1);
        assert_eq!(header.nscount, 0);
        assert_eq!(header.arcount, 0);
    }
}
