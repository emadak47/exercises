use futures_util::stream::StreamExt;
use futures_util::SinkExt;
use http::Uri;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_websockets::{ClientBuilder, Message};

#[tokio::main]
async fn main() -> Result<(), tokio_websockets::Error> {
    let (mut ws_stream, _) = ClientBuilder::from_uri(Uri::from_static("ws://127.0.0.1:2000"))
        .connect()
        .await?;

    let stdin = tokio::io::stdin();
    let mut stdin = BufReader::new(stdin).lines();

    loop {
        tokio::select! {
            val = ws_stream.next() => {
                match val {
                    Some(Ok(msg)) => {
                        if let Some(text) = msg.as_text() {
                            println!("Message from server: {text}");
                        };
                    }
                    Some(Err(e)) => return Err(e),
                    None => return Ok(()), // stream ended
                }
            }

            line = stdin.next_line() => {
                match line {
                    Ok(None) => {},
                    Ok(Some(msg)) => ws_stream.send(Message::text(msg)).await?,
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
}
