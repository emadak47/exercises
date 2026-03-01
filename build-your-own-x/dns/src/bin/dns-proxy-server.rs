use std::io;
use std::net::UdpSocket;

use dns::{DnsPacket, PACKET_SIZE, RCode, lookup};

fn handle_query(socket: &UdpSocket) -> io::Result<DnsPacket> {
    let mut req_buf = [0u8; PACKET_SIZE];
    let (_, src_addr) = socket.recv_from(&mut req_buf)?;

    let mut req = DnsPacket::from_bytes(&req_buf).unwrap();

    let mut resp = DnsPacket::new_empty();
    resp.header.id = req.header.id;
    resp.header.rd = true;
    resp.header.ra = true;

    if let Some(ques) = req.questions.pop() {
        //println!("Received query: {ques:?}");

        if let Ok(result) = lookup(&ques.name, ques.r#type) {
            resp.questions.push(ques);
            resp.header.rcode = req.header.rcode;

            for rec in result.answers {
                //println!("Answer: {:?}", rec);
                resp.answers.push(rec);
            }
            for rec in result.authorities {
                //println!("Authority: {:?}", rec);
                resp.authorities.push(rec);
            }
            for rec in result.resources {
                //println!("Resource: {:?}", rec);
                resp.resources.push(rec);
            }
        } else {
            resp.header.rcode = RCode::Servfail;
        }
    } else {
        resp.header.rcode = RCode::Formerr;
    }

    let mut resp_buf = [0u8; PACKET_SIZE];
    resp.to_bytes(&mut resp_buf);

    socket.send_to(&resp_buf, src_addr).map(|_| resp)
}

fn main() -> io::Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    loop {
        match handle_query(&socket) {
            Ok(resp) => println!("Sent back {resp:#?}\n"),
            Err(e) => eprintln!("An error occurred: {e}"),
        }
    }
}
