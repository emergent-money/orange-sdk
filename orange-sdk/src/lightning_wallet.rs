use crate::bitcoin::OutPoint;
use crate::bitcoin::hashes::Hash;
use crate::dyn_store::{DynStore, LdkNodeStore};
use crate::event::{EventQueue, LdkEventHandler, TrustedWalletHandle};
use crate::logging::Logger;
use crate::runtime::Runtime;
use crate::store::{TxMetadataStore, TxStatus};
use crate::{ChainSource, InitFailure, PaymentType, WalletConfig, store};

use bitcoin_payment_instructions::PaymentMethod;
use bitcoin_payment_instructions::amount::Amount;

use ldk_node::bitcoin::base64::Engine;
use ldk_node::bitcoin::base64::prelude::BASE64_STANDARD;
use ldk_node::bitcoin::io;
use ldk_node::bitcoin::secp256k1::PublicKey;
use ldk_node::bitcoin::{Address, Network};
use ldk_node::config::{AsyncPaymentsRole, BackgroundSyncConfig, SyncTimeoutsConfig};
use ldk_node::lightning::ln::channelmanager::PaymentId;
use ldk_node::lightning::ln::msgs::SocketAddress;
use ldk_node::lightning::util::logger::Logger as _;
use ldk_node::lightning::{log_debug, log_error, log_info};
use ldk_node::lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription, Description};
use ldk_node::lightning_types::payment::PaymentHash;
use ldk_node::payment::{
	ConfirmationStatus, PaymentDetails, PaymentDirection, PaymentKind, PaymentStatus,
};
use ldk_node::{NodeError, UserChannelId};

use graduated_rebalancer::{LightningBalance, ReceivedLightningPayment};

use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::sync::{Notify, watch};

#[derive(Debug, Clone, Copy)]
pub(crate) struct LightningWalletBalance {
	pub(crate) lightning: Amount,
	pub(crate) onchain: Amount,
}

pub(crate) struct LightningWalletImpl {
	pub(crate) ldk_node: Arc<ldk_node::Node>,
	logger: Arc<Logger>,
	store: Arc<dyn DynStore>,
	payment_receipt_flag: watch::Receiver<()>,
	channel_pending_receipt_flag: watch::Receiver<u128>,
	splice_pending_inbox: Arc<SplicePendingInbox>,
	inbound_payment_ids: Arc<InboundPaymentIds>,
	lsp_node_id: PublicKey,
	lsp_socket_addr: SocketAddress,
}

pub(crate) struct LightningWallet {
	pub(crate) inner: Arc<LightningWalletImpl>,
}

const DEFAULT_INVOICE_EXPIRY_SECS: u32 = 86_400; // 24 hours

impl LightningWallet {
	pub(super) async fn init(
		runtime: Arc<Runtime>, config: WalletConfig, store: Arc<dyn DynStore>,
		event_queue: Arc<EventQueue>, tx_metadata: TxMetadataStore, trusted: TrustedWalletHandle,
		logger: Arc<Logger>,
	) -> Result<Self, InitFailure> {
		let handle = runtime.get_handle();
		handle
			.spawn(Self::init_inner(
				runtime,
				config,
				store,
				event_queue,
				tx_metadata,
				trusted,
				logger,
			))
			.await
			.map_err(|e| {
				io::Error::new(io::ErrorKind::Other, format!("LDK initialization task failed: {e}"))
			})?
	}

	async fn init_inner(
		runtime: Arc<Runtime>, config: WalletConfig, store: Arc<dyn DynStore>,
		event_queue: Arc<EventQueue>, tx_metadata: TxMetadataStore, trusted: TrustedWalletHandle,
		logger: Arc<Logger>,
	) -> Result<Self, InitFailure> {
		log_info!(logger, "Creating LDK node...");
		let anchor_channels_config = ldk_node::config::AnchorChannelsConfig {
			trusted_peers_no_reserve: vec![config.lsp.1],
			enable_zero_fee_commitments: true,
			..Default::default()
		};
		let ldk_node_config = ldk_node::config::Config {
			anchor_channels_config,
			// The Lightning leg of a wrapped receive is a `receive_for_hash` invoice whose
			// preimage orange-sdk holds, not ldk-node. Since lightningdevkit/ldk-node#948
			// creating such an invoice no longer stores a payment record, so when it is paid
			// ldk-node knows neither the payment nor its preimage, and with this flag off it
			// fails the HTLCs back on arrival without emitting `Event::PaymentClaimable`: every
			// Lightning leg would be refused. With it on, ldk-node records the payment and emits
			// the event, and `LdkEventHandler` claims it (only a known wrapped receive, for at
			// least its amount, whose trusted leg is unpaid) or fails it back at once. Failing
			// back at once also bounds ldk-node's warning about this flag: a payer holding one
			// of our invoices cannot keep HTLC slots held for longer than it takes us to handle
			// the event.
			manually_handle_unknown_bolt11_payments: true,
			..Default::default()
		};
		let mut builder = ldk_node::Builder::from_config(ldk_node_config);
		builder.set_network(config.network);
		let node_entropy = config.seed.to_node_entropy();

		match config.rgs_url {
			Some(url) => {
				builder.set_gossip_source_rgs(url);
			},
			None => {
				match config.network {
					Network::Bitcoin => {
						builder.set_gossip_source_rgs(
							"https://rapidsync.lightningdevkit.org/snapshot".to_string(),
						);
					},
					Network::Testnet => {
						builder.set_gossip_source_rgs(
							"https://rapidsync.lightningdevkit.org/testnet/snapshot".to_string(),
						);
					},
					Network::Testnet4 => {},
					Network::Signet => {},
					Network::Regtest => {
						// We don't want to run an RGS server in tests so just enable p2p gossip
						builder.set_gossip_source_p2p();
					},
				}
			},
		}

		let (lsp_socket_addr, lsp_node_id, lsp_token) = config.lsp;
		builder.add_liquidity_source(lsp_node_id, lsp_socket_addr.clone(), lsp_token, true);
		match config.chain_source {
			ChainSource::Esplora { url, username, password } => {
				let sync_config = if config.network == Network::Regtest {
					ldk_node::config::EsploraSyncConfig {
						background_sync_config: Some(BackgroundSyncConfig {
							onchain_wallet_sync_interval_secs: 2,
							lightning_wallet_sync_interval_secs: 2,
							fee_rate_cache_update_interval_secs: 30,
						}),
						timeouts_config: SyncTimeoutsConfig::default(),
						..Default::default()
					}
				} else {
					ldk_node::config::EsploraSyncConfig::default()
				};

				match (&username, &password) {
					(Some(username), Some(password)) => {
						let mut headers = HashMap::with_capacity(1);
						headers.insert(
							"Authorization".to_string(),
							format!(
								"Basic {}",
								BASE64_STANDARD.encode(format!("{username}:{password}"))
							),
						);
						builder.set_chain_source_esplora_with_headers(
							url,
							headers,
							Some(sync_config),
						)
					},
					(None, None) => builder.set_chain_source_esplora(url, Some(sync_config)),
					_ => {
						return Err(InitFailure::LdkNodeStartFailure(
							NodeError::WalletOperationFailed,
						));
					},
				}
			},
			ChainSource::Electrum(url) => {
				let sync_config = if config.network == Network::Regtest {
					Some(ldk_node::config::ElectrumSyncConfig {
						timeouts_config: SyncTimeoutsConfig::default(),
						background_sync_config: Some(BackgroundSyncConfig {
							onchain_wallet_sync_interval_secs: 2,
							lightning_wallet_sync_interval_secs: 2,
							fee_rate_cache_update_interval_secs: 30,
						}),
						..Default::default()
					})
				} else {
					None
				};
				builder.set_chain_source_electrum(url, sync_config)
			},
			ChainSource::BitcoindRPC { host, port, user, password } => {
				builder.set_chain_source_bitcoind_rpc(host, port, user, password, None)
			},
		};

		builder.set_async_payments_role(Some(AsyncPaymentsRole::Client))?;

		builder.set_custom_logger(Arc::clone(&logger) as Arc<dyn ldk_node::logger::LogWriter>);

		// ldk-node now refuses a runtime that is not multi-threaded (its blocking calls use
		// `block_in_place`). Fail initialization rather than let it run on a different runtime.
		builder.set_runtime(runtime.get_handle())?;

		if let Some(url) = config.scorer_url {
			builder.set_pathfinding_scores_source(url);
		}

		let ldk_node =
			Arc::new(builder.build_with_store(node_entropy, LdkNodeStore(Arc::clone(&store)))?);
		let (payment_receipt_sender, payment_receipt_flag) = watch::channel(());
		let (channel_pending_sender, channel_pending_receipt_flag) = watch::channel(0);
		let splice_pending_inbox = Arc::new(SplicePendingInbox {
			pending: Mutex::new(HashMap::new()),
			notify: Notify::new(),
		});
		let inbound_payment_ids = Arc::new(InboundPaymentIds::default());
		let ev_handler = Arc::new(LdkEventHandler {
			event_queue,
			ldk_node: Arc::clone(&ldk_node),
			tx_metadata,
			store: Arc::clone(&store),
			trusted,
			payment_receipt_sender,
			channel_pending_sender,
			splice_pending_inbox: Arc::clone(&splice_pending_inbox),
			inbound_payment_ids: Arc::clone(&inbound_payment_ids),
			logger: Arc::clone(&logger),
		});
		let inner = Arc::new(LightningWalletImpl {
			ldk_node,
			logger,
			store,
			payment_receipt_flag,
			channel_pending_receipt_flag,
			splice_pending_inbox,
			inbound_payment_ids,
			lsp_node_id,
			lsp_socket_addr,
		});

		inner.ldk_node.start()?;

		runtime.spawn_cancellable_background_task(async move {
			loop {
				let event = ev_handler.ldk_node.next_event_async().await;
				log_debug!(ev_handler.logger, "Got ldk-node event {event:?}");
				ev_handler.handle_ldk_node_event(event).await;
			}
		});

		Ok(Self { inner })
	}

	pub(crate) async fn await_channel_pending(&self, channel_id: u128) {
		let mut flag = self.inner.channel_pending_receipt_flag.clone();
		flag.mark_unchanged();
		flag.wait_for(|t| t == &channel_id).await.expect("channel pending not received");
	}

	pub(crate) async fn await_splice_pending(&self, channel_id: u128) -> OutPoint {
		self.inner.splice_pending_inbox.wait_for(channel_id).await
	}

	pub(crate) fn get_on_chain_address(&self) -> Result<Address, NodeError> {
		self.inner.ldk_node.onchain_payment().new_address()
	}

	pub(crate) async fn get_bolt11_invoice(
		&self, amount: Option<Amount>,
	) -> Result<Bolt11Invoice, NodeError> {
		let desc = Bolt11InvoiceDescription::Direct(Description::empty());
		if let Some(amt) = amount {
			if self.estimate_receivable_balance() >= amt {
				self.inner.ldk_node.bolt11_payment().receive(
					amt.milli_sats(),
					&desc,
					DEFAULT_INVOICE_EXPIRY_SECS,
				)
			} else {
				self.inner.ldk_node.bolt11_payment().receive_via_jit_channel(
					amt.milli_sats(),
					&desc,
					DEFAULT_INVOICE_EXPIRY_SECS,
					None,
				)
			}
		} else if self.estimate_receivable_balance() // if we can receive at least 100k sats, don't use JIT
			>= Amount::from_sats(100_000).expect("valid amount")
		{
			self.inner
				.ldk_node
				.bolt11_payment()
				.receive_variable_amount(&desc, DEFAULT_INVOICE_EXPIRY_SECS)
		} else {
			self.inner.ldk_node.bolt11_payment().receive_variable_amount_via_jit_channel(
				&desc,
				DEFAULT_INVOICE_EXPIRY_SECS,
				None,
			)
		}
	}

	/// Returns an invoice on this node for `payment_hash`, to be claimed manually once the payment
	/// arrives (see [`ldk_node::payment::Bolt11Payment::receive_for_hash`]), or `None` if `amount`
	/// exceeds what we can receive over our existing channels.
	///
	/// Unlike [`Self::get_bolt11_invoice`] this never requests a JIT channel: the payer of this
	/// invoice is expected to be the LSP itself, which cannot pay an invoice whose route hint is its
	/// own JIT-channel intercept.
	pub(crate) async fn get_bolt11_invoice_for_hash(
		&self, amount: Amount, payment_hash: PaymentHash,
	) -> Result<Option<Bolt11Invoice>, NodeError> {
		if self.estimate_receivable_balance() < amount {
			return Ok(None);
		}
		let desc = Bolt11InvoiceDescription::Direct(Description::empty());
		self.inner
			.ldk_node
			.bolt11_payment()
			.receive_for_hash(amount.milli_sats(), &desc, DEFAULT_INVOICE_EXPIRY_SECS, payment_hash)
			.map(Some)
	}

	/// Looks up whether the inbound BOLT 11 payment for `payment_hash` has been received.
	///
	/// Since lightningdevkit/ldk-node#948 an inbound payment's record is created only when its
	/// HTLCs arrive, under the id LDK derives from them, so it can no longer be found as
	/// `PaymentId(payment_hash)`. We first try the id the event handler saw for this hash;
	/// failing that (the event has not been handled yet, or was handled before a restart) we
	/// search the payment store, newest first, stopping at the first received payment.
	fn inbound_receipt(&self, payment_hash: PaymentHash) -> Result<InboundReceipt, NodeError> {
		if let Some(id) = self.inner.inbound_payment_ids.get(&payment_hash) {
			if let Some(payment) = self.inner.ldk_node.payment(&id)? {
				if is_inbound_bolt11_for(&payment, payment_hash)
					&& payment.status == PaymentStatus::Succeeded
				{
					return Ok(InboundReceipt::Received(payment));
				}
			}
		}

		let mut search = InboundReceiptSearch::default();
		let mut page_token = None;
		loop {
			let page = self.inner.ldk_node.list_payments(page_token)?;
			for payment in page.payments {
				if let Some(received) = search.observe(payment, payment_hash) {
					return Ok(InboundReceipt::Received(received));
				}
			}
			match page.next_page_token {
				Some(token) => page_token = Some(token),
				None => return Ok(search.outcome()),
			}
		}
	}

	/// Lists every payment in the node's payment store, newest first, walking all its pages.
	///
	/// The store keeps only recently used payments in memory, so this reads the rest from the
	/// KV store; a failed read fails the whole listing rather than returning part of it.
	pub(crate) fn list_payments(&self) -> Result<Vec<PaymentDetails>, NodeError> {
		let mut payments = Vec::new();
		let mut page_token = None;
		loop {
			let page = self.inner.ldk_node.list_payments(page_token)?;
			payments.extend(page.payments);
			match page.next_page_token {
				Some(token) => page_token = Some(token),
				None => return Ok(payments),
			}
		}
	}

	pub(crate) fn get_balance(&self) -> LightningWalletBalance {
		let balances = self.inner.ldk_node.list_balances();
		LightningWalletBalance {
			lightning: Amount::from_sats(balances.total_lightning_balance_sats)
				.expect("invalid amount"),
			onchain: Amount::from_sats(balances.total_onchain_balance_sats)
				.expect("invalid amount"),
		}
	}

	pub(crate) fn estimate_receivable_balance(&self) -> Amount {
		// Estimate the amount we can receive. Note that this is pretty rough and generally an
		// overestimate.
		let amt =
			self.inner.ldk_node.list_channels().iter().map(|chan| chan.inbound_capacity_msat).max();
		Amount::from_milli_sats(amt.unwrap_or(0)).expect("invalid amount")
	}

	pub(crate) async fn estimate_fee(
		&self, _method: &PaymentMethod, _amount: Amount,
	) -> Result<Amount, NodeError> {
		// TODO: Implement this in ldk-node!
		Ok(Amount::ZERO)
	}

	pub(crate) async fn pay(
		&self, method: &PaymentMethod, amount: Amount,
	) -> Result<PaymentId, NodeError> {
		match method {
			PaymentMethod::LightningBolt11(inv) => self
				.inner
				.ldk_node
				.bolt11_payment()
				.send_using_amount(inv, amount.milli_sats(), None),
			PaymentMethod::LightningBolt12(offer) => self
				.inner
				.ldk_node
				.bolt12_payment()
				.send_using_amount(offer, amount.milli_sats(), None, None, None),
			PaymentMethod::OnChain(address) => {
				let amount_sats = amount.sats().map_err(|_| NodeError::InvalidAmount)?;

				let balance = self.inner.ldk_node.list_balances();

				// if we have enough onchain balance, send onchain
				if balance.spendable_onchain_balance_sats > amount_sats {
					self.inner
						.ldk_node
						.onchain_payment()
						.send_to_address(address, amount_sats, None)
						.map(|txid| PaymentId(*txid.as_ref()))
				} else {
					// otherwise try to pay via splice out

					// find existing channel to splice out of
					let channels = self.inner.ldk_node.list_channels();
					let channel =
						channels.iter().find(|c| c.counterparty.node_id == self.inner.lsp_node_id);

					match channel {
						None => {
							log_error!(self.inner.logger, "No existing channel to splice out of");
							Err(NodeError::InsufficientFunds)
						},
						Some(chan) => {
							// No minimum fee rate: as before, ldk-node uses its channel-funding
							// estimate.
							self.inner.ldk_node.splice_out(
								&chan.user_channel_id,
								chan.counterparty.node_id,
								address,
								amount_sats,
								None,
							)?;

							let funding_txo =
								self.await_splice_pending(chan.user_channel_id.0).await;

							let id = PaymentId(funding_txo.txid.to_byte_array());
							let details = PaymentDetails {
								id,
								kind: PaymentKind::Onchain {
									txid: funding_txo.txid,
									status: ConfirmationStatus::Unconfirmed, // todo how do we update this?
									tx_type: None,
								},
								amount_msat: Some(amount_sats * 1_000),
								fee_paid_msat: Some(69), // todo get real fee
								direction: PaymentDirection::Outbound,
								status: PaymentStatus::Succeeded,
								latest_update_timestamp: SystemTime::now()
									.duration_since(SystemTime::UNIX_EPOCH)
									.unwrap()
									.as_secs(),
							};

							store::write_splice_out(self.inner.store.as_ref(), &details).await;
							Ok(id)
						},
					}
				}
			},
		}
	}

	/// Pays `amount` toward `invoice` as a single part of a multi-path payment (MPP), declaring the
	/// invoice's own amount as the MPP total. The remainder is expected to be paid out of another
	/// wallet over the same payment hash. This requires an amount-bearing invoice.
	pub(crate) fn pay_bolt11_underpaying(
		&self, invoice: &Bolt11Invoice, amount: Amount,
	) -> Result<PaymentId, NodeError> {
		self.inner.ldk_node.bolt11_payment().send_using_amount_underpaying(
			invoice,
			amount.milli_sats(),
			None,
		)
	}

	pub(crate) async fn splice_all_into_channel(&self) -> Result<UserChannelId, NodeError> {
		// find existing channel to splice into
		let channels = self.inner.ldk_node.list_channels();
		let channel = channels.iter().find(|c| c.counterparty.node_id == self.inner.lsp_node_id);

		match channel {
			Some(chan) => {
				// No minimum fee rate: as before, ldk-node uses its channel-funding estimate.
				self.inner.ldk_node.splice_in_with_all(
					&chan.user_channel_id,
					chan.counterparty.node_id,
					None,
				)?;
				Ok(chan.user_channel_id)
			},
			None => {
				log_error!(self.inner.logger, "No existing channel to splice into");
				Err(NodeError::WalletOperationFailed)
			},
		}
	}

	pub(crate) async fn open_channel_with_lsp(&self) -> Result<UserChannelId, NodeError> {
		// No push amount, no fee rate (as before, ldk-node uses its channel-funding estimate) and
		// the default channel config.
		let id = self.inner.ldk_node.open_channel_with_all(
			self.inner.lsp_node_id,
			self.inner.lsp_socket_addr.clone(),
			None,
			None,
			None,
		)?;

		Ok(id)
	}

	pub(crate) fn close_channels(&self) -> Result<(), NodeError> {
		let channels = self.inner.ldk_node.list_channels();
		for chan in channels {
			if chan.is_usable {
				self.inner
					.ldk_node
					.close_channel(&chan.user_channel_id, chan.counterparty.node_id)?;
			} else {
				self.inner.ldk_node.force_close_channel(
					&chan.user_channel_id,
					chan.counterparty.node_id,
					None,
				)?;
			}
		}
		Ok(())
	}

	/// Check if the wallet is currently connected to the LSP.
	pub(crate) fn is_connected_to_lsp(&self) -> bool {
		self.inner
			.ldk_node
			.list_peers()
			.into_iter()
			.find(|p| p.node_id == self.inner.lsp_node_id)
			.is_some_and(|p| p.is_connected)
	}

	pub(crate) fn stop(&self) {
		let _ = self.inner.ldk_node.stop();
	}
}

impl graduated_rebalancer::LightningWallet for LightningWallet {
	type Error = NodeError;

	fn get_balance(&self) -> LightningBalance {
		let bal = self.get_balance();
		LightningBalance { lightning: bal.lightning, onchain: bal.onchain }
	}

	fn get_bolt11_invoice(
		&self, amount: Option<Amount>,
	) -> Pin<Box<dyn Future<Output = Result<Bolt11Invoice, Self::Error>> + Send + '_>> {
		Box::pin(async move { self.get_bolt11_invoice(amount).await })
	}

	fn pay(
		&self, method: PaymentMethod, amount: Amount,
	) -> Pin<Box<dyn Future<Output = Result<[u8; 32], Self::Error>> + Send + '_>> {
		Box::pin(async move { self.pay(&method, amount).await.map(|p| p.0) })
	}

	fn await_payment_receipt(
		&self, payment_hash: [u8; 32],
	) -> Pin<Box<dyn Future<Output = Option<ReceivedLightningPayment>> + Send + '_>> {
		Box::pin(async move {
			let payment_hash = PaymentHash(payment_hash);
			let mut flag = self.inner.payment_receipt_flag.clone();
			loop {
				// Mark the flag seen before looking, not after: a receipt handled while we look
				// then wakes the wait below instead of being missed.
				flag.mark_unchanged();
				match self.inbound_receipt(payment_hash) {
					Ok(InboundReceipt::Received(payment)) => {
						let fee_paid_msat = match payment.kind {
							PaymentKind::Bolt11 { counterparty_skimmed_fee_msat, .. } => {
								counterparty_skimmed_fee_msat
							},
							_ => None,
						};
						// The id ldk-node stored the payment under, which `list_transactions` and
						// the rebalance metadata key on; it is not the payment hash.
						return Some(ReceivedLightningPayment { id: payment.id.0, fee_paid_msat });
					},
					Ok(InboundReceipt::Failed) => return None,
					Ok(InboundReceipt::NotYet) => {},
					Err(e) => {
						log_error!(
							self.inner.logger,
							"Failed to look up the payment for hash {payment_hash} while waiting for it: {e}"
						);
						return None;
					},
				}
				if flag.changed().await.is_err() {
					// The event handler is gone, so no receipt will be signalled any more.
					return None;
				}
			}
		})
	}

	fn has_channel_with_lsp(&self) -> bool {
		let channels = self.inner.ldk_node.list_channels();
		channels.iter().any(|c| c.counterparty.node_id == self.inner.lsp_node_id)
	}

	fn open_channel_with_lsp(
		&self,
	) -> Pin<Box<dyn Future<Output = Result<u128, Self::Error>> + Send + '_>> {
		Box::pin(async move { self.open_channel_with_lsp().await.map(|c| c.0) })
	}

	fn await_channel_pending(
		&self, channel_id: u128,
	) -> Pin<Box<dyn Future<Output = OutPoint> + Send + '_>> {
		Box::pin(async move {
			loop {
				let channels = self.inner.ldk_node.list_channels();
				let chan = channels
					.into_iter()
					.find(|c| c.user_channel_id.0 == channel_id && c.funding_txo.is_some());
				match chan {
					Some(c) => return c.funding_txo.expect("channel has no funding txo"),
					None => {
						self.await_channel_pending(channel_id).await;
						// Wait for the next channel pending event
					},
				}
			}
		})
	}

	fn splice_to_lsp_channel(
		&self,
	) -> Pin<Box<dyn Future<Output = Result<u128, Self::Error>> + Send + '_>> {
		Box::pin(async move { self.splice_all_into_channel().await.map(|c| c.0) })
	}

	fn await_splice_pending(
		&self, channel_id: u128,
	) -> Pin<Box<dyn Future<Output = OutPoint> + Send + '_>> {
		// `ChannelDetails.funding_txo` from `list_channels` still reports the old funding
		// outpoint between `SplicePending` and `SpliceLocked`, so we return the new outpoint
		// from the event itself rather than reading it back from the channel.
		Box::pin(async move { self.await_splice_pending(channel_id).await })
	}
}

impl From<PaymentStatus> for TxStatus {
	fn from(o: PaymentStatus) -> TxStatus {
		match o {
			PaymentStatus::Pending => TxStatus::Pending,
			PaymentStatus::Succeeded => TxStatus::Completed,
			PaymentStatus::Failed => TxStatus::Failed,
		}
	}
}

impl From<&PaymentDetails> for PaymentType {
	fn from(d: &PaymentDetails) -> PaymentType {
		match (&d.kind, d.direction == PaymentDirection::Outbound) {
			(PaymentKind::Bolt11 { preimage, .. }, true) => {
				if d.status == PaymentStatus::Succeeded {
					debug_assert!(preimage.is_some());
				}
				PaymentType::OutgoingLightningBolt11 { payment_preimage: *preimage }
			},
			(PaymentKind::Bolt12Offer { preimage, .. }, true) => {
				PaymentType::OutgoingLightningBolt12 { payment_preimage: *preimage }
			},
			(
				PaymentKind::Bolt12Refund { preimage, .. }
				| PaymentKind::Spontaneous { preimage, .. },
				true,
			) => {
				debug_assert!(false);
				PaymentType::OutgoingLightningBolt12 { payment_preimage: *preimage }
			},
			(PaymentKind::Onchain { txid, .. }, true) => {
				PaymentType::OutgoingOnChain { txid: Some(*txid) }
			},
			(PaymentKind::Onchain { txid, .. }, false) => {
				PaymentType::IncomingOnChain { txid: Some(*txid) }
			},
			(_, false) => PaymentType::IncomingLightning {},
		}
	}
}

/// Pending `SplicePending` events keyed by `user_channel_id`, consumed by
/// `await_splice_pending`. A per-channel queue rather than a `watch` so each consumer takes its own
/// event: `watch` would let a second splice on the same channel observe the previous splice's stale
/// outpoint instead of waiting for the new `SplicePending`.
pub(crate) struct SplicePendingInbox {
	pub(crate) pending: Mutex<HashMap<u128, VecDeque<OutPoint>>>,
	pub(crate) notify: Notify,
}

impl SplicePendingInbox {
	pub(crate) fn deliver(&self, channel_id: u128, funding_txo: OutPoint) {
		self.pending.lock().unwrap().entry(channel_id).or_default().push_back(funding_txo);
		self.notify.notify_waiters();
	}

	pub(crate) async fn wait_for(&self, channel_id: u128) -> OutPoint {
		loop {
			// Register interest BEFORE checking the queue so a `notify_waiters` racing with the
			// check still wakes us up.
			let notified = self.notify.notified();
			tokio::pin!(notified);
			notified.as_mut().enable();
			if let Some(txo) = {
				let mut pending = self.pending.lock().unwrap();
				if let Some(queue) = pending.get_mut(&channel_id) {
					let txo = queue.pop_front();
					if queue.is_empty() {
						pending.remove(&channel_id);
					}
					txo
				} else {
					None
				}
			} {
				return txo;
			}
			notified.await;
		}
	}
}

/// The payment ids ldk-node reported for inbound payments, keyed by payment hash, as seen by
/// [`LdkEventHandler`] since start.
///
/// An inbound payment's id is derived by LDK from its HTLCs, so the id for a hash is only known
/// once the payment arrives. Entries are never removed; the map is in memory only and holds one
/// small entry per inbound payment handled since start.
#[derive(Default)]
pub(crate) struct InboundPaymentIds {
	ids: Mutex<HashMap<PaymentHash, PaymentId>>,
}

impl InboundPaymentIds {
	/// Records the id of a payment that has been received (`Event::PaymentReceived`). This wins
	/// over any id recorded for the hash before.
	pub(crate) fn record_received(&self, payment_hash: PaymentHash, payment_id: PaymentId) {
		self.ids.lock().unwrap().insert(payment_hash, payment_id);
	}

	/// Records the id of a payment that is waiting to be claimed (`Event::PaymentClaimable`),
	/// unless an id is already known for the hash: a later payment to the same hash, which is
	/// failed back, must not hide one that was received.
	pub(crate) fn record_claimable(&self, payment_hash: PaymentHash, payment_id: PaymentId) {
		self.ids.lock().unwrap().entry(payment_hash).or_insert(payment_id);
	}

	pub(crate) fn get(&self, payment_hash: &PaymentHash) -> Option<PaymentId> {
		self.ids.lock().unwrap().get(payment_hash).copied()
	}
}

/// Whether an inbound BOLT 11 payment has been received, as far as the payment store says.
enum InboundReceipt {
	/// The payment was received.
	Received(PaymentDetails),
	/// Every inbound payment for the hash was failed back, and none was received.
	Failed,
	/// Nothing for the hash has arrived yet, or it is still pending.
	NotYet,
}

fn is_inbound_bolt11_for(payment: &PaymentDetails, payment_hash: PaymentHash) -> bool {
	payment.direction == PaymentDirection::Inbound
		&& matches!(payment.kind, PaymentKind::Bolt11 { hash, .. } if hash == payment_hash)
}

/// Searches payments for a received inbound BOLT 11 payment to a hash. More than one inbound
/// payment can exist for a hash (a payment failed back and paid again arrives under a new id),
/// so the payment counts as received if any of them was, and as failed only if all of them were.
#[derive(Default)]
struct InboundReceiptSearch {
	seen: bool,
	any_not_failed: bool,
}

impl InboundReceiptSearch {
	/// Returns `payment` if it is a received inbound BOLT 11 payment for `payment_hash`.
	fn observe(
		&mut self, payment: PaymentDetails, payment_hash: PaymentHash,
	) -> Option<PaymentDetails> {
		if !is_inbound_bolt11_for(&payment, payment_hash) {
			return None;
		}
		self.seen = true;
		match payment.status {
			PaymentStatus::Succeeded => Some(payment),
			PaymentStatus::Pending => {
				self.any_not_failed = true;
				None
			},
			PaymentStatus::Failed => None,
		}
	}

	fn outcome(self) -> InboundReceipt {
		if self.seen && !self.any_not_failed {
			InboundReceipt::Failed
		} else {
			InboundReceipt::NotYet
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use ldk_node::bitcoin::Txid;
	use ldk_node::bitcoin::hex::DisplayHex;
	use ldk_node::lightning::util::persist::{
		KVStore, PageToken, PaginatedKVStore, PaginatedListResponse,
	};
	use ldk_node::lightning::util::ser::Writeable;
	use std::sync::atomic::{AtomicUsize, Ordering};

	fn dummy_outpoint(seed: u8) -> OutPoint {
		let bytes = [seed; 32];
		OutPoint { txid: Txid::from_byte_array(bytes), vout: seed as u32 }
	}

	#[test]
	fn splice_pending_inbox_preserves_distinct_events_for_same_channel() {
		let inbox =
			SplicePendingInbox { pending: Mutex::new(HashMap::new()), notify: Notify::new() };
		let channel_id = 7;
		let first = dummy_outpoint(0xaa);
		let second = dummy_outpoint(0xbb);

		inbox.deliver(channel_id, first);
		inbox.deliver(channel_id, second);

		let mut pending = inbox.pending.lock().unwrap();
		let queue = pending.get_mut(&channel_id).expect("channel should have pending events");

		assert_eq!(queue.pop_front(), Some(first));
		assert_eq!(queue.pop_front(), Some(second));
		assert!(queue.is_empty());
	}

	const HASH: [u8; 32] = [0x11; 32];
	const OTHER_HASH: [u8; 32] = [0x22; 32];

	fn payment(
		id: [u8; 32], kind: PaymentKind, direction: PaymentDirection, status: PaymentStatus,
	) -> PaymentDetails {
		PaymentDetails {
			id: PaymentId(id),
			kind,
			amount_msat: Some(21_000),
			fee_paid_msat: None,
			direction,
			status,
			latest_update_timestamp: 1_700_000_000,
		}
	}

	fn bolt11(hash: [u8; 32], skimmed_fee_msat: Option<u64>) -> PaymentKind {
		PaymentKind::Bolt11 {
			hash: PaymentHash(hash),
			preimage: None,
			secret: None,
			counterparty_skimmed_fee_msat: skimmed_fee_msat,
		}
	}

	fn search(payments: Vec<PaymentDetails>) -> (Option<PaymentDetails>, InboundReceipt) {
		let mut search = InboundReceiptSearch::default();
		for p in payments {
			if let Some(received) = search.observe(p, PaymentHash(HASH)) {
				return (Some(received), InboundReceipt::NotYet);
			}
		}
		(None, search.outcome())
	}

	/// An inbound payment is stored under the id LDK derives from its HTLCs, so the search must
	/// match on the payment hash and direction, never on `PaymentId(hash)`.
	#[test]
	fn inbound_receipt_search_matches_hash_not_id() {
		let derived_id = [0x33; 32];
		let (received, _) = search(vec![
			// Our own outbound payment to the hash, stored under `PaymentId(hash)` as BOLT 11
			// sends still are: not a receipt.
			payment(HASH, bolt11(HASH, None), PaymentDirection::Outbound, PaymentStatus::Succeeded),
			// A received payment to another hash.
			payment(
				[0x44; 32],
				bolt11(OTHER_HASH, None),
				PaymentDirection::Inbound,
				PaymentStatus::Succeeded,
			),
			// A keysend that happens to carry the hash: not the invoice payment we wait for.
			payment(
				[0x55; 32],
				PaymentKind::Spontaneous { hash: PaymentHash(HASH), preimage: None },
				PaymentDirection::Inbound,
				PaymentStatus::Succeeded,
			),
			payment(
				derived_id,
				bolt11(HASH, Some(1_000)),
				PaymentDirection::Inbound,
				PaymentStatus::Succeeded,
			),
		]);
		let received = received.expect("the inbound BOLT 11 payment is a receipt");
		assert_eq!(received.id, PaymentId(derived_id));
		assert_ne!(received.id, PaymentId(HASH));
	}

	/// A hash paid again after a failed attempt has a failed and a received payment: it counts as
	/// received, whichever order the store lists them in.
	#[test]
	fn inbound_receipt_search_prefers_any_received_payment() {
		let failed = payment(
			[0x01; 32],
			bolt11(HASH, None),
			PaymentDirection::Inbound,
			PaymentStatus::Failed,
		);
		let received = payment(
			[0x02; 32],
			bolt11(HASH, None),
			PaymentDirection::Inbound,
			PaymentStatus::Succeeded,
		);
		for payments in [vec![failed.clone(), received.clone()], vec![received.clone(), failed]] {
			let (found, _) = search(payments);
			assert_eq!(found, Some(received.clone()));
		}
	}

	#[test]
	fn inbound_receipt_search_outcome_without_a_received_payment() {
		let inbound =
			|id, status| payment([id; 32], bolt11(HASH, None), PaymentDirection::Inbound, status);

		// Nothing for the hash yet: keep waiting.
		let (found, outcome) = search(vec![payment(
			HASH,
			bolt11(HASH, None),
			PaymentDirection::Outbound,
			PaymentStatus::Failed,
		)]);
		assert!(found.is_none());
		assert!(matches!(outcome, InboundReceipt::NotYet));

		// Still pending: keep waiting.
		let (_, outcome) = search(vec![inbound(1, PaymentStatus::Pending)]);
		assert!(matches!(outcome, InboundReceipt::NotYet));

		// One failed attempt and one still pending: keep waiting for the pending one.
		let (_, outcome) =
			search(vec![inbound(1, PaymentStatus::Failed), inbound(2, PaymentStatus::Pending)]);
		assert!(matches!(outcome, InboundReceipt::NotYet));

		// Every inbound payment for the hash failed: give up, as for a failed payment before.
		let (_, outcome) =
			search(vec![inbound(1, PaymentStatus::Failed), inbound(2, PaymentStatus::Failed)]);
		assert!(matches!(outcome, InboundReceipt::Failed));
	}

	#[test]
	fn inbound_payment_ids_prefer_the_received_payment() {
		let hash = PaymentHash(HASH);
		let (first, second) = (PaymentId([0x01; 32]), PaymentId([0x02; 32]));

		let ids = InboundPaymentIds::default();
		assert_eq!(ids.get(&hash), None);
		ids.record_claimable(hash, first);
		assert_eq!(ids.get(&hash), Some(first));
		// The payment that was received replaces one that was only claimable.
		ids.record_received(hash, second);
		assert_eq!(ids.get(&hash), Some(second));
		// A later claimable payment to the same hash (which is failed back) does not hide it.
		ids.record_claimable(hash, first);
		assert_eq!(ids.get(&hash), Some(second));
	}

	/// ldk-node's payment namespace (`PAYMENT_INFO_PERSISTENCE_PRIMARY_NAMESPACE`, crate-private
	/// there).
	const PAYMENTS_NAMESPACE: &str = "payments";

	/// A SQLite store that counts the reads and listed pages of ldk-node's payment namespace.
	struct CountingStore {
		inner: ldk_node::io::sqlite_store::SqliteStore,
		payment_reads: Arc<AtomicUsize>,
		payment_pages: Arc<AtomicUsize>,
	}

	impl KVStore for CountingStore {
		fn read(
			&self, p: &str, s: &str, k: &str,
		) -> impl Future<Output = Result<Vec<u8>, io::Error>> + Send + 'static {
			if p == PAYMENTS_NAMESPACE {
				self.payment_reads.fetch_add(1, Ordering::SeqCst);
			}
			KVStore::read(&self.inner, p, s, k)
		}

		fn write(
			&self, p: &str, s: &str, k: &str, buf: Vec<u8>,
		) -> impl Future<Output = Result<(), io::Error>> + Send + 'static {
			KVStore::write(&self.inner, p, s, k, buf)
		}

		fn remove(
			&self, p: &str, s: &str, k: &str, lazy: bool,
		) -> impl Future<Output = Result<(), io::Error>> + Send + 'static {
			KVStore::remove(&self.inner, p, s, k, lazy)
		}

		fn list(
			&self, p: &str, s: &str,
		) -> impl Future<Output = Result<Vec<String>, io::Error>> + Send + 'static {
			KVStore::list(&self.inner, p, s)
		}
	}

	impl PaginatedKVStore for CountingStore {
		fn list_paginated(
			&self, p: &str, s: &str, page_token: Option<PageToken>,
		) -> impl Future<Output = Result<PaginatedListResponse, io::Error>> + Send + 'static {
			if p == PAYMENTS_NAMESPACE {
				self.payment_pages.fetch_add(1, Ordering::SeqCst);
			}
			PaginatedKVStore::list_paginated(&self.inner, p, s, page_token)
		}
	}

	/// What one full `list_payments` scan costs since the payment store became a bounded cache
	/// (ldk-node 0a3cd95): the cache holds up to 1000 payments but is warmed with only the 50
	/// newest at start, and listing never adds what it reads to it. So after a restart every scan
	/// (the rebalancer's on each on-chain sync change, `list_transactions`, a waiting
	/// `await_payment_receipt` on each wake-up) reads every payment but the 50 newest from the KV
	/// store, again on every scan; only a lookup by id caches a payment. With SQLite (and VSS)
	/// pages of 50 keys, a scan also lists ceil(n / 50) pages.
	///
	/// This pins those numbers so a change in ldk-node's caching shows up here.
	#[tokio::test(flavor = "multi_thread")]
	async fn full_payment_listing_reads_every_payment_beyond_the_warm_cache() {
		for (n, expected_pages, expected_reads) in [(50, 1, 0), (500, 10, 450)] {
			let dir = std::env::temp_dir().join(format!(
				"orange-sdk-list-cost-test-{n}-{}",
				SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos()
			));
			let payment_reads = Arc::new(AtomicUsize::new(0));
			let payment_pages = Arc::new(AtomicUsize::new(0));
			let store = CountingStore {
				inner: ldk_node::io::sqlite_store::SqliteStore::new(
					dir.join("kv"),
					Some("ldk.sqlite".to_string()),
					None,
				)
				.expect("sqlite store"),
				payment_reads: Arc::clone(&payment_reads),
				payment_pages: Arc::clone(&payment_pages),
			};

			// Payments written by an earlier run, oldest first.
			let ids: Vec<PaymentId> = (0..n as u32)
				.map(|i| {
					let mut id = [0u8; 32];
					id[..4].copy_from_slice(&i.to_be_bytes());
					PaymentId(id)
				})
				.collect();
			for id in &ids {
				let details = payment(
					id.0,
					bolt11(id.0, None),
					PaymentDirection::Inbound,
					PaymentStatus::Succeeded,
				);
				KVStore::write(
					&store,
					PAYMENTS_NAMESPACE,
					"",
					&id.0.to_lower_hex_string(),
					details.encode(),
				)
				.await
				.expect("write payment");
			}

			let mut builder = ldk_node::Builder::new();
			builder.set_network(Network::Regtest);
			builder.set_storage_dir_path(dir.join("ldk").to_str().unwrap().to_string());
			let node_entropy = ldk_node::entropy::NodeEntropy::from_seed_bytes([9; 64]);
			let node = builder.build_with_store(node_entropy, store).expect("build ldk-node");

			let scan = || {
				let (reads, pages) =
					(payment_reads.load(Ordering::SeqCst), payment_pages.load(Ordering::SeqCst));
				let mut listed = 0;
				let mut page_token = None;
				loop {
					let page = node.list_payments(page_token).expect("list payments");
					listed += page.payments.len();
					match page.next_page_token {
						Some(token) => page_token = Some(token),
						None => break,
					}
				}
				assert_eq!(listed, n);
				(
					payment_reads.load(Ordering::SeqCst) - reads,
					payment_pages.load(Ordering::SeqCst) - pages,
				)
			};

			let (first_reads, first_pages) = scan();
			let (second_reads, second_pages) = scan();
			println!(
				"n={n}: scan 1 read {first_reads} payments over {first_pages} pages, scan 2 read {second_reads} over {second_pages}"
			);
			assert_eq!((first_reads, first_pages), (expected_reads, expected_pages));
			// Listing does not warm the cache: the next scan reads the same payments again.
			assert_eq!((second_reads, second_pages), (expected_reads, expected_pages));

			// A lookup by id does cache the payment, saving one read on later scans.
			let reads = payment_reads.load(Ordering::SeqCst);
			assert!(node.payment(&ids[0]).expect("payment lookup").is_some());
			let lookup_reads = payment_reads.load(Ordering::SeqCst) - reads;
			let (after_lookup_reads, _) = scan();
			if n > 50 {
				assert_eq!(lookup_reads, 1);
				assert_eq!(after_lookup_reads, expected_reads - 1);
			} else {
				assert_eq!(lookup_reads, 0);
				assert_eq!(after_lookup_reads, 0);
			}
		}
	}
}
