//! Accept path.
use crate::edge::peek::PeekBackoff;

async fn peek_header(stream: &TcpStream) -> Result<usize, Error> {
    let mut backoff = PeekBackoff::new();
    loop {
        match stream.peek(&mut buf) {
            Ok(n) if n > 0 => return Ok(n),
            _ => backoff.wait().await?,
        }
    }
}
