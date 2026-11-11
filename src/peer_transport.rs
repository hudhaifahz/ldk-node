//! Optional, local SOCKS routes. Complete proxy setup before starting the Lightning handshake.
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

use bitcoin::secp256k1::PublicKey;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) const PROXY_CONNECT_TIMEOUT: Duration = Duration::from_secs(125);

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SocksRoute {
	pub proxy: SocketAddr,
	pub host: String,
	pub port: u16,
}

pub(crate) fn load_routes(storage_dir: &str) -> io::Result<HashMap<PublicKey, SocksRoute>> {
	let path = Path::new(storage_dir).join("peer_transport_overrides.json");
	let bytes = match std::fs::read(path) {
		Ok(bytes) => bytes,
		Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(HashMap::new()),
		Err(e) => return Err(e),
	};
	parse_routes(&bytes)
}

fn parse_routes(bytes: &[u8]) -> io::Result<HashMap<PublicKey, SocksRoute>> {
	let raw: HashMap<String, SocksRoute> = serde_json::from_slice(bytes).map_err(|_| {
		io::Error::new(io::ErrorKind::InvalidData, "Invalid peer transport configuration")
	})?;
	let mut routes = HashMap::new();
	for (key, route) in raw {
		let node_id = key
			.parse::<PublicKey>()
			.map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid peer public key"))?;
		// Only local proxies and v3 onion destinations are supported. Never resolve onion DNS locally.
		let onion = route.host.strip_suffix(".onion").unwrap_or("");
		if !route.proxy.ip().is_loopback()
			|| route.proxy.port() == 0
			|| route.port == 0
			|| onion.len() != 56
			|| !onion.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
		{
			return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid local onion route"));
		}
		routes.insert(node_id, route);
	}
	Ok(routes)
}

pub(crate) async fn connect(route: &SocksRoute) -> io::Result<TcpStream> {
	connect_with_timeout(route, PROXY_CONNECT_TIMEOUT).await
}

async fn connect_with_timeout(route: &SocksRoute, timeout: Duration) -> io::Result<TcpStream> {
	tokio::time::timeout(timeout, async {
		let mut stream = tokio::net::TcpStream::connect(route.proxy).await?;
		stream.write_all(&[5, 1, 0]).await?;
		let mut greeting = [0; 2];
		stream.read_exact(&mut greeting).await?;
		if greeting != [5, 0] {
			return Err(io::Error::new(
				io::ErrorKind::ConnectionRefused,
				"SOCKS authentication rejected",
			));
		}
		let host = route.host.as_bytes();
		let len = u8::try_from(host.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
		let mut request = vec![5, 1, 0, 3, len];
		request.extend_from_slice(host);
		request.extend_from_slice(&route.port.to_be_bytes());
		stream.write_all(&request).await?;
		let mut reply = [0; 4];
		stream.read_exact(&mut reply).await?;
		if reply[0] != 5 || reply[1] != 0 || reply[2] != 0 {
			return Err(io::Error::new(
				io::ErrorKind::ConnectionRefused,
				"SOCKS connection rejected",
			));
		}
		let address_len = match reply[3] {
			1 => 4,
			3 => stream.read_u8().await? as usize,
			4 => 16,
			_ => {
				return Err(io::Error::new(
					io::ErrorKind::InvalidData,
					"Invalid SOCKS address type",
				))
			},
		};
		let mut address_and_port = vec![0; address_len + 2];
		stream.read_exact(&mut address_and_port).await?;
		stream.into_std()
	})
	.await
	.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Tor connection timed out"))?
}

#[cfg(test)]
mod tests {
	use super::*;
	const KEY: &str = "02c911ba09b21441200e0424279720ec13290b36cd51f4ab1a80cbb40b3baf0fe1";
	fn route(proxy: SocketAddr) -> SocksRoute {
		SocksRoute { proxy, host: format!("{}.onion", "a".repeat(56)), port: 9735 }
	}

	#[test]
	fn rejects_invalid_or_nonlocal_routes() {
		for proxy in ["8.8.8.8:9050", "127.0.0.1:0"] {
			let value = format!(
				r#"{{"{KEY}":{{"proxy":"{proxy}","host":"{}.onion","port":9735}}}}"#,
				"a".repeat(56)
			);
			assert!(parse_routes(value.as_bytes()).is_err());
		}
		assert!(parse_routes(b"invalid").is_err());
		assert!(parse_routes(b"{}").unwrap().is_empty());
	}

	#[tokio::test]
	async fn waits_for_complete_proxy_reply_without_consuming_lightning_data() {
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let route = route(listener.local_addr().unwrap());
		let server = tokio::spawn(async move {
			let (mut stream, _) = listener.accept().await.unwrap();
			let mut greeting = [0; 3];
			stream.read_exact(&mut greeting).await.unwrap();
			assert_eq!(greeting, [5, 1, 0]);
			stream.write_all(&[5, 0]).await.unwrap();
			let mut request = vec![0; 5 + 62 + 2];
			stream.read_exact(&mut request).await.unwrap();
			assert_eq!(&request[..5], &[5, 1, 0, 3, 62]);
			assert_eq!(&request[67..], &9735u16.to_be_bytes());
			tokio::time::sleep(Duration::from_millis(80)).await;
			// Fragmented reply, with application bytes in the same final write.
			stream.write_all(&[5, 0]).await.unwrap();
			tokio::time::sleep(Duration::from_millis(20)).await;
			stream.write_all(&[0, 1, 127, 0, 0, 1, 0, 1, 42]).await.unwrap();
		});
		let start = std::time::Instant::now();
		let stream = connect_with_timeout(&route, Duration::from_secs(2)).await.unwrap();
		assert!(start.elapsed() >= Duration::from_millis(100));
		let mut stream = tokio::net::TcpStream::from_std(stream).unwrap();
		assert_eq!(stream.read_u8().await.unwrap(), 42);
		server.await.unwrap();
	}

	#[tokio::test]
	async fn timeout_and_rejection_do_not_return_a_lightning_stream() {
		for reject in [true, false] {
			let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
			let route = route(listener.local_addr().unwrap());
			let server = tokio::spawn(async move {
				let (mut stream, _) = listener.accept().await.unwrap();
				let mut greeting = [0; 3];
				stream.read_exact(&mut greeting).await.unwrap();
				if reject {
					stream.write_all(&[5, 255]).await.unwrap();
				} else {
					tokio::time::sleep(Duration::from_secs(1)).await;
				}
			});
			let error = connect_with_timeout(&route, Duration::from_millis(50)).await.unwrap_err();
			assert_eq!(
				error.kind(),
				if reject { io::ErrorKind::ConnectionRefused } else { io::ErrorKind::TimedOut }
			);
			server.abort();
		}
	}
}
