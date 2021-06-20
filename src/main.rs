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

    let publisher = fluss::publish::ElasticPublisher::new(elasticsearch::Elasticsearch::default());

    let socket = UdpSocket::bind("0.0.0.0:9999").await?;

    let session = fluss::ipfix::Session::new(fluss::produce::IpfixParser::new());

    let mut buf = vec![0; u16::MAX as usize];
    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        tracing::info!("{:?} bytes received from {:?}", len, addr);

        let packet = fluss::ipfix::parse(&buf[0..len])?;
        for rs in session.parse(&packet) {
            publisher.publish(&rs).await?;
        }
    }
}
