use clap::{App, Arg};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let app = App::new("ghcp")
        .arg(
            Arg::with_name("verbosity")
                .long("verbose")
                .short("v")
                .multiple(true)
                .help("verbosity level"),
        )
        .get_matches();

    tracing_subscriber::fmt()
        .with_max_level(match app.occurrences_of("verbosity") {
            0 => tracing::Level::INFO,
            1 => tracing::Level::DEBUG,
            _ => tracing::Level::TRACE,
        })
        .init();

    let socket = UdpSocket::bind("0.0.0.0:9999").await?;

    let mut session = fluss::Session::new();

    let mut buf = vec![0; 2048];
    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        println!("\n{:?} bytes received from {:?}", len, addr);

        let (_, packet) = fluss::parse(&buf).unwrap();
        for fluss::session::Set(id, fields) in session.feed(&packet) {
            println!("set id {}", id);
            for field in fields {
                println!(
                    "  {:>30}: {:?}",
                    session.get_field_name(&field).unwrap_or("<?>"),
                    field.1
                );
            }
        }
    }
}
