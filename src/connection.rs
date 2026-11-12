// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::collections::hash_map::{self, HashMap};
use std::net::ToSocketAddrs;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::secp256k1::PublicKey;
use lightning::ln::msgs::SocketAddress;

use crate::logger::{log_error, log_info, LdkLogger};
use crate::peer_transport::{self, SocksRoute};
use crate::types::PeerManager;
use crate::Error;

pub(crate) struct ConnectionManager<L: Deref + Clone + Sync + Send>
where
	L::Target: LdkLogger,
{
	pending_connections:
		Mutex<HashMap<PublicKey, Vec<tokio::sync::oneshot::Sender<Result<(), Error>>>>>,
	peer_manager: Arc<PeerManager>,
	logger: L,
	proxy_routes: HashMap<PublicKey, SocksRoute>,
}

impl<L: Deref + Clone + Sync + Send> ConnectionManager<L>
where
	L::Target: LdkLogger,
{
	pub(crate) fn new(
		peer_manager: Arc<PeerManager>, logger: L, proxy_routes: HashMap<PublicKey, SocksRoute>,
	) -> Self {
		let pending_connections = Mutex::new(HashMap::new());
		Self { pending_connections, peer_manager, logger, proxy_routes }
	}

	pub(crate) async fn connect_peer_if_necessary(
		&self, node_id: PublicKey, addr: SocketAddress,
	) -> Result<(), Error> {
		if self.peer_manager.peer_by_node_id(&node_id).is_some() {
			return Ok(());
		}

		self.do_connect_peer(node_id, addr).await
	}

	pub(crate) async fn do_connect_peer(
		&self, node_id: PublicKey, addr: SocketAddress,
	) -> Result<(), Error> {
		// First, we check if there is already an outbound connection in flight, if so, we just
		// await on the corresponding watch channel. The task driving the connection future will
		// send us the result..
		let pending_ready_receiver_opt = self.register_or_subscribe_pending_connection(&node_id);
		if let Some(pending_connection_ready_receiver) = pending_ready_receiver_opt {
			return pending_connection_ready_receiver.await.map_err(|e| {
				debug_assert!(false, "Failed to receive connection result: {:?}", e);
				log_error!(self.logger, "Failed to receive connection result: {:?}", e);
				Error::ConnectionFailed
			})?;
		}

		log_info!(self.logger, "Connecting to peer: {}@{}", node_id, addr);

		// Always clear the pending entry, including when shutdown cancels this future.
		let _pending_guard = PendingConnectionGuard { manager: self, node_id: Some(node_id) };
		let connection_future = async {
			if let Some(route) = self.proxy_routes.get(&node_id) {
				// SOCKS success must precede setup_outbound, which starts LDK's handshake timer.
				match peer_transport::connect(route).await {
					Ok(stream) => Ok(Some(Box::pin(lightning_net_tokio::setup_outbound(
						Arc::clone(&self.peer_manager),
						node_id,
						stream,
					))
						as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>)),
					Err(error) => {
						log_error!(
							self.logger,
							"Tor transport failed for peer {}: {}",
							node_id,
							error
						);
						Err(Error::ConnectionFailed)
					},
				}
			} else {
				// Preserve the normal resolver, error contract and direct TCP transport.
				let socket_addr = addr
					.to_socket_addrs()
					.map_err(|_| Error::InvalidSocketAddress)?
					.next()
					.ok_or(Error::InvalidSocketAddress)?;
				Ok(lightning_net_tokio::connect_outbound(
					Arc::clone(&self.peer_manager),
					node_id,
					socket_addr,
				)
				.await
				.map(|future| {
					Box::pin(future)
						as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
				}))
			}
		};

		let res = match connection_future.await {
			Ok(Some(connection_closed_future)) => {
				let mut connection_closed_future = Box::pin(connection_closed_future);
				loop {
					tokio::select! {
						_ = &mut connection_closed_future => {
							log_info!(self.logger, "Peer connection closed: {}@{}", node_id, addr);
							break Err(Error::ConnectionFailed);
						},
						_ = tokio::time::sleep(Duration::from_millis(10)) => {},
					};

					match self.peer_manager.peer_by_node_id(&node_id) {
						Some(_) => break Ok(()),
						None => continue,
					}
				}
			},
			Err(error) => Err(error),
			Ok(None) => {
				log_error!(self.logger, "Failed to connect to peer: {}@{}", node_id, addr);
				Err(Error::ConnectionFailed)
			},
		};

		_pending_guard.complete(res);

		res
	}

	fn register_or_subscribe_pending_connection(
		&self, node_id: &PublicKey,
	) -> Option<tokio::sync::oneshot::Receiver<Result<(), Error>>> {
		let mut pending_connections_lock = self.pending_connections.lock().unwrap();
		match pending_connections_lock.entry(*node_id) {
			hash_map::Entry::Occupied(mut entry) => {
				let (tx, rx) = tokio::sync::oneshot::channel();
				entry.get_mut().push(tx);
				Some(rx)
			},
			hash_map::Entry::Vacant(entry) => {
				entry.insert(Vec::new());
				None
			},
		}
	}

	fn propagate_result_to_subscribers(&self, node_id: &PublicKey, res: Result<(), Error>) {
		// Send the result to any other tasks that might be waiting on it by now.
		let mut pending_connections_lock = self.pending_connections.lock().unwrap();
		if let Some(connection_ready_senders) = pending_connections_lock.remove(node_id) {
			for sender in connection_ready_senders {
				let _ = sender.send(res);
			}
		}
	}
}

// Dropping an in-flight connection releases waiters and permits a later retry.
struct PendingConnectionGuard<'a, L: Deref + Clone + Sync + Send>
where
	L::Target: LdkLogger,
{
	manager: &'a ConnectionManager<L>,
	node_id: Option<PublicKey>,
}
impl<L: Deref + Clone + Sync + Send> Drop for PendingConnectionGuard<'_, L>
where
	L::Target: LdkLogger,
{
	fn drop(&mut self) {
		if let Some(node_id) = self.node_id.take() {
			self.manager.propagate_result_to_subscribers(&node_id, Err(Error::ConnectionFailed));
		}
	}
}

impl<L: Deref + Clone + Sync + Send> PendingConnectionGuard<'_, L>
where
	L::Target: LdkLogger,
{
	fn complete(mut self, result: Result<(), Error>) {
		if let Some(node_id) = self.node_id.take() {
			self.manager.propagate_result_to_subscribers(&node_id, result);
		}
	}
}
