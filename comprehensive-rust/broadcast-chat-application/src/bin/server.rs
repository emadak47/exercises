use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use std::error::Error;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast::{channel, Sender};
use tokio_websockets::{Message, ServerBuilder, WebSocketStream};

async fn handle_connection(
    addr: SocketAddr,
    mut ws_stream: WebSocketStream<TcpStream>,
    bcast_tx: Sender<(SocketAddr, String)>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut bcast_rx = bcast_tx.subscribe();

    // Consider it a non-recoverable error if it couldn't be read/written from/to ws_stream
    loop {
        tokio::select! {
            val = ws_stream.next() => {
                match val {
                    Some(Ok(msg)) => {
                        if let Some(text) = msg.as_text() {
                            let _ = bcast_tx.send((addr, text.to_string()));
                        };
                    }
                    Some(Err(e)) => return Err(e.into()),
                    None => return Ok(()), // stream ended
                }
            }

            val2 = bcast_rx.recv() => {
                match val2 {
                    Ok(msg) => {
                        if msg.0 != addr {
                            ws_stream.send(Message::text(msg.1)).await?;
                        }
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let (bcast_tx, _) = channel(16);

    let listener = TcpListener::bind("127.0.0.1:2000").await?;
    println!("listening on port 2000");

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("New connection from {addr:?}");
        let bcast_tx = bcast_tx.clone();
        tokio::spawn(async move {
            // Wrap the raw TCP stream into a websocket.
            let (_req, ws_stream) = ServerBuilder::new().accept(socket).await?;

            handle_connection(addr, ws_stream, bcast_tx).await
        });
    }
}
