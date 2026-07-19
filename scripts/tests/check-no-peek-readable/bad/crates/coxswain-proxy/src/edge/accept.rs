//! Accept path.
async fn peek_header(stream: &TcpStream) -> Result<usize, Error> {
    loop {
        // MSG_PEEK never clears read-readiness, so this spins a core forever.
        stream.readable().await?;
        match stream.peek(&mut buf) {
            Ok(n) if n > 0 => return Ok(n),
            _ => continue,
        }
    }
}
