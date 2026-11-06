use std::{
    io::{prelude::*},
    net::{TcpListener, TcpStream},
    thread,
    sync::Arc,
};
use openssl::ssl::{SslMethod, SslAcceptor, SslStream, SslFiletype};

fn main() -> std::io::Result<()> {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor.set_private_key_file("certs/cert.key", SslFiletype::PEM).unwrap();
    acceptor.set_certificate_chain_file("certs/cert.pem").unwrap();
    acceptor.check_private_key().unwrap();
    let acceptor = Arc::new(acceptor.build());

    let host = "127.0.0.1";
    let port = 7878;
    let addr = format!("{}:{}", host, port);
    println!("Starting server on {addr}");

    let listener = TcpListener::bind(addr).unwrap();

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let peer = stream.peer_addr().unwrap();
                let acceptor = acceptor.clone();
                println!("New connection from {peer}");
                thread::spawn(move || {
                    let ssl_stream = acceptor.accept(stream).unwrap();
                    handle_connection(ssl_stream);
                });
            }
            Err(e) => eprintln!("Connection failed: {e}"),
        }
    }

    Ok(())
}

fn handle_connection(mut ssl_stream: SslStream<TcpStream>) {
    let peer = ssl_stream.get_ref().peer_addr().unwrap();
    let mut buffer = [0u8; 4096];

    loop {
        match ssl_stream.read(&mut buffer) {
            Ok(0) => {
                // client disconnected
                println!("Connection closed by {peer}");
                break;
            }
            Ok(bytes_read) => {
                // print raw data as string
                let data = String::from_utf8_lossy(&buffer[..bytes_read]);
                print!("{data}");

                // optional: flush stdout so output appears immediately
                std::io::stdout().flush().unwrap();
            }
            Err(e) => {
                eprintln!("Error reading from {peer}: {e}");
                break;
            }
        }
    }
}