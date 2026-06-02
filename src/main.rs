use anyhow::{Error, Result};
use clap::Parser;
use quinn::{Endpoint, ServerConfig, rustls::pki_types::PrivatePkcs8KeyDer};
use rustls::ClientConfig;
use rustls::crypto::ring::default_provider;
use rustls::{RootCertStore, pki_types::CertificateDer};
use sheen;
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
};
use tokio;
use tokio::time::sleep;

const SERVER_NAME: &str = "localhost";
const LOCALHOST_V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const CLIENT_ADDR: SocketAddr = SocketAddr::new(LOCALHOST_V4, 5000);
const SERVER_ADDR: SocketAddr = SocketAddr::new(LOCALHOST_V4, 5001);

#[derive(Parser)]
#[command(version, about = "A CLI tool for wave")]
struct Args {
    #[arg(short = 'c')]
    client: bool,

    #[arg(short = 's')]
    server: bool,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    sheen::init();
    let args = Args::parse();
    default_provider()
        .install_default()
        .expect("failed to install default crypto provider");
    let cert_der;
    let key_der;

    if args.server {
        let cert_path = Path::new("./certs/cert.der");
        let key_path = Path::new("./certs/key.der");

        if cert_path.exists() && key_path.exists() {
            let cert_bytes = fs::read(cert_path)?;
            let key_bytes = fs::read(key_path)?;
            cert_der = vec![CertificateDer::from(cert_bytes)];
            key_der = PrivatePkcs8KeyDer::from(key_bytes);
            sheen::info!("Certificates Loaded!");
        } else {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            cert_der = vec![cert.cert.der().clone()];
            key_der = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
            fs::create_dir_all("./certs")?;
            fs::write(cert_path, cert_der[0].as_ref())?;
            fs::write(key_path, key_der.secret_pkcs8_der())?;
            sheen::info!("New Certificates Generated!");
        }

        let server_config = ServerConfig::with_single_cert(cert_der, key_der.into()).unwrap();
        server(server_config).await?;
    } else {
        client().await?;
    }
    Ok(())
}

async fn server(config: ServerConfig) -> Result<(), Error> {
    sheen::info!("In Server Mode");
    // Bind this endpoint to a UDP socket on the given server address.
    let endpoint = Endpoint::server(config, SERVER_ADDR)?;

    // Start iterating over incoming connections.
    while let Some(conn) = endpoint.accept().await {
        let connection = conn.await?;
        let mut uni = connection.accept_uni().await?;
        sheen::info!("server accepted stream");
        let mut buf = [0u8; 1024];
        uni.read(&mut buf).await?;
        println!("{}", String::from_utf8_lossy(&buf));
    }

    Ok(())
}

async fn client() -> Result<(), anyhow::Error> {
    sheen::info!("In Client Mode");
    // Bind this endpoint to a UDP socket on the given client address.
    let mut endpoint = Endpoint::client(CLIENT_ADDR)?;

    let cert_path = Path::new("./certs/cert.der");
    let cert_bytes = fs::read(cert_path)?;
    let der = CertificateDer::from(cert_bytes);
    let mut root_store = RootCertStore::empty();
    root_store.add(der)?;

    let client_config_rustls = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_config_rustls)?,
    ));

    endpoint.set_default_client_config(client_config);

    // Connect to the server passing in the server name which is supposed to be in the server certificate.
    let connection = endpoint.connect(SERVER_ADDR, SERVER_NAME)?.await?;

    // Start transferring, receiving data, see data transfer page.
    let mut uni = connection.open_uni().await?;
    sheen::info!("client initiated stream");
    uni.write("hello".as_bytes()).await?;
    uni.finish()?;

    sleep(Duration::from_secs(5)).await;

    Ok(())
}
