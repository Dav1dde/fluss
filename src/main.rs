use clap::{App, Arg};
use fluss::ipfix::{
    parser::{DataSet, FieldSpecifier},
    Parser,
};
use tokio::net::UdpSocket;

enum Either<Left, Right> {
    Left(Left),
    Right(Right),
}

impl<'a, L, R, T> Parser<'a> for Either<L, R>
where
    L: Parser<'a, Output = T>,
    R: Parser<'a, Output = T>,
{
    type Output = T;

    fn parse(&self, fields: &[FieldSpecifier], set: &DataSet<'a>) -> Option<Self::Output> {
        match self {
            Self::Left(left) => left.parse(fields, set),
            Self::Right(right) => right.parse(fields, set),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let app = App::new("fluss")
        .arg(
            Arg::with_name("verbosity")
                .long("verbose")
                .short("v")
                .multiple(true)
                .help("verbosity level"),
        )
        .arg(
            Arg::with_name("debug")
                .long("debug")
                .short("d")
                .takes_value(false)
                .help("enables additional debug output, does not change verbosity"),
        )
        .arg(
            Arg::with_name("listen")
                .long("listen")
                .short("l")
                .default_value("0.0.0.0:2055")
                .help("listen/bind port for netflow traffic"),
        )
        .arg(
            Arg::with_name("publisher")
                .long("publisher")
                .short("p")
                .possible_values(&["console", "elastic"])
                .default_value("console")
                .help("publisher for flow data"),
        )
        .get_matches();

    tracing_subscriber::fmt()
        .with_max_level(match app.occurrences_of("verbosity") {
            0 => tracing::Level::INFO,
            1 => tracing::Level::DEBUG,
            _ => tracing::Level::TRACE,
        })
        .init();

    let publisher: Box<dyn fluss::publish::Publisher> = match app.value_of("publisher") {
        Some("elastic") => Box::new(fluss::publish::ElasticPublisher::new(
            elasticsearch::Elasticsearch::default(),
        )),
        Some("console") => Box::new(fluss::publish::ConsolePublisher::new()),
        _ => panic!("unknown or no publisher"),
    };

    let listen = app.value_of("listen").unwrap();
    let socket = UdpSocket::bind(listen).await?;
    tracing::info!("listening for netflow traffic on: {}", listen);

    let parser = fluss::produce::IpfixParser::new();
    let parser = match app.is_present("debug") {
        true => Either::Left(fluss::ipfix::DebugParser::new(parser)),
        false => Either::Right(parser),
    };
    let session = fluss::ipfix::Session::new(parser);

    let mut buf = vec![0; u16::MAX as usize];
    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        tracing::info!("{:?} bytes received from {:?}", len, addr);

        let packet = fluss::ipfix::parse(&buf[0..len])?;

        for flow in session.parse(&packet) {
            publisher.publish(&flow).await?;
        }
    }
}
