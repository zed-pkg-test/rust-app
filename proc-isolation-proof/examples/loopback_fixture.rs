//! Minimal HTTP fixture used by sandbox network-boundary tests.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

fn handle(mut stream: TcpStream) -> std::io::Result<()> {
    let mut request = [0_u8; 1024];
    let _ = stream.read(&mut request)?;
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")?;
    stream.flush()
}

fn main() -> std::io::Result<()> {
    let address = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:18080".to_owned());
    let listener = TcpListener::bind(&address)?;
    eprintln!("loopback fixture listening on {address}");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = handle(stream) {
                    eprintln!("loopback fixture connection error: {error}");
                }
            }
            Err(error) => eprintln!("loopback fixture accept error: {error}"),
        }
    }

    Ok(())
}
