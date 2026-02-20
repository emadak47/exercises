const PACKET_SIZE: usize = 512;

#[derive(Debug)]
struct PacketBuf<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> PacketBuf<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        let n = buf.len();
        assert!(0 < n && n < PACKET_SIZE);
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
