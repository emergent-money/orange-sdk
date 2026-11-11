use crate::logging::Logger;
use crate::store::{self, MppOutcome, PaymentId, RebalanceEnabledCache, TxMetadataStore, TxType};
use crate::trusted_wallet::{DynTrustedWalletInterface, TrustedError};

use crate::dyn_store::DynStore;
use ldk_node::bitcoin::hashes::Hash;
use ldk_node::bitcoin::secp256k1::PublicKey;
use ldk_node::bitcoin::{OutPoint, Txid};
use ldk_node::lightning::events::{ClosureReason, PaymentFailureReason};
use ldk_node::lightning::ln::channelmanager::PaymentId as LdkPaymentId;
use ldk_node::lightning::ln::types::ChannelId;
use ldk_node::lightning::util::logger::Logger as _;
use ldk_node::lightning::util::persist::KVStore;
use ldk_node::lightning::util::ser::{Readable, Writeable, Writer};
use ldk_node::lightning::{
	impl_writeable_tlv_based_enum, log_debug, log_error, log_info, log_warn,
};
use ldk_node::lightning_types::payment::{PaymentHash, PaymentPreimage};
use ldk_node::payment::{ConfirmationStatus, PaymentKind, PaymentStatus};
use ldk_node::{CustomTlvRecord, UserChannelId};

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::{Mutex, Notify, watch};

/// The event queue will be persisted under this key.
pub(crate) const EVENT_QUEUE_PERSISTENCE_PRIMARY_NAMESPACE: &str = "";
pub(crate) const EVENT_QUEUE_PERSISTENCE_SECONDARY_NAMESPACE: &str = "";
pub(crate) const EVENT_QUEUE_PERSISTENCE_KEY: &str = "orange_events";

/// An event emitted by [`Wallet`], which should be handled by the user.
///
/// [`Wallet`]: [`crate::Wallet`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
	/// An outgoing payment was successful.
	PaymentSuccessful {
		/// A local identifier used to track the payment.
		payment_id: PaymentId,
		/// The hash of the payment.
		payment_hash: PaymentHash,
		/// The preimage to the `payment_hash`.
		///
		/// Note that this serves as a payment receipt.
		payment_preimage: PaymentPreimage,
		/// The total fee which was spent at intermediate hops in this payment.
		fee_paid_msat: Option<u64>,
	},
	/// An outgoing payment has failed.
	PaymentFailed {
		/// A local identifier used to track the payment.
		payment_id: PaymentId,
		/// The hash of the payment.
		///
		/// This will be `None` if the payment failed before receiving an invoice when paying a
		/// BOLT12 [`Offer`].
		///
		/// [`Offer`]: ldk_node::lightning::offers::offer::Offer
		payment_hash: Option<PaymentHash>,
		/// The reason why the payment failed.
		///
		/// Will be `None` if the failure reason is not known.
		reason: Option<PaymentFailureReason>,
	},
	/// A payment has been received.
	PaymentReceived {
		/// A local identifier used to track the payment.
		payment_id: PaymentId,
		/// The hash of the payment.
		payment_hash: PaymentHash,
		/// The value, in msats, that has been received.
		amount_msat: u64,
		/// Custom TLV records received on the payment
		custom_records: Vec<CustomTlvRecord>,
		/// The value, in msats, that was skimmed off of this payment as an extra fee taken by LSP.
		/// Typically, this is only present for payments that result in opening a channel.
		lsp_fee_msats: Option<u64>,
	},
	/// A payment has been received.
	OnchainPaymentReceived {
		/// A local identifier used to track the payment.
		payment_id: PaymentId,
		/// The transaction ID.
		txid: Txid,
		/// The value, in sats, that has been received.
		amount_sat: u64,
		/// The confirmation status of this payment.
		status: ConfirmationStatus,
	},
	/// A channel is ready to be used.
	ChannelOpened {
		/// The `channel_id` of the channel.
		channel_id: ChannelId,
		/// The `user_channel_id` of the channel.
		user_channel_id: UserChannelId,
		/// The `node_id` of the channel counterparty.
		counterparty_node_id: PublicKey,
		/// The outpoint of the channel's funding transaction.
		funding_txo: OutPoint,
	},
	/// A channel has been closed.
	///
	/// When a channel is closed, we will disable automatic rebalancing
	/// so new channels will not be opened until it is explicitly enabled again.
	ChannelClosed {
		/// The `channel_id` of the channel.
		channel_id: ChannelId,
		/// The `user_channel_id` of the channel.
		user_channel_id: UserChannelId,
		/// The `node_id` of the channel counterparty.
		counterparty_node_id: PublicKey,
		/// Why the channel was closed.
		///
		/// Will be `None` if the closure reason is not known.
		reason: Option<ClosureReason>,
	},
	/// A rebalance from our trusted wallet has been initiated.
	RebalanceInitiated {
		/// The `payment_id` of the transaction that triggered the rebalance.
		trigger_payment_id: PaymentId,
		/// The `payment_id` of the rebalance payment sent from the trusted wallet.
		trusted_rebalance_payment_id: [u8; 32],
		/// The amount, in msats, of the rebalance payment.
		amount_msat: u64,
	},
	/// A rebalance from our trusted wallet was successful.
	RebalanceSuccessful {
		/// The `payment_id` of the transaction that triggered the rebalance.
		trigger_payment_id: PaymentId,
		/// The `payment_id` of the rebalance payment sent from the trusted wallet.
		trusted_rebalance_payment_id: [u8; 32],
		/// The `payment_id` of the rebalance payment sent to the LN wallet.
		ln_rebalance_payment_id: [u8; 32],
		/// The amount, in msats, of the rebalance payment.
		amount_msat: u64,
		/// The fee paid, in msats, for the rebalance payment.
		fee_msat: u64,
	},
	/// We have initiated a splice and are waiting for it to confirm.
	SplicePending {
		/// The `channel_id` of the channel.
		channel_id: ChannelId,
		/// The `user_channel_id` of the channel.
		user_channel_id: UserChannelId,
		/// The `node_id` of the channel counterparty.
		counterparty_node_id: PublicKey,
		/// The outpoint of the channel's splice funding transaction.
		new_funding_txo: OutPoint,
	},
}

impl_writeable_tlv_based_enum!(Event,
	(0, PaymentSuccessful) => {
		(0, payment_id, required),
		(2, payment_hash, required),
		(4, payment_preimage, required),
		(5, fee_paid_msat, option),
	},
	(1, PaymentFailed) => {
		(0, payment_id, required),
		(1, payment_hash, option),
		(3, reason, upgradable_option),
	},
	(2, PaymentReceived) => {
		(0, payment_id, required),
		(2, payment_hash, required),
		(4, amount_msat, required),
		(5, custom_records, optional_vec),
		(7, lsp_fee_msats, option),
	},
	(3, OnchainPaymentReceived) => {
		(0, payment_id, required),
		(2, txid, required),
		(4, amount_sat, required),
		(6, status, required),
	},
	(4, ChannelOpened) => {
		(0, channel_id, required),
		(2, user_channel_id, required),
		(4, counterparty_node_id, required),
		(6, funding_txo, required),
	},
	(5, ChannelClosed) => {
		(0, channel_id, required),
		(2, user_channel_id, required),
		(4, counterparty_node_id, required),
		(5, reason, upgradable_option),
	},
	(6, RebalanceInitiated) => {
		(0, trigger_payment_id, required),
		(2, trusted_rebalance_payment_id, required),
		(4, amount_msat, required),
	},
	(7, RebalanceSuccessful) => {
		(0, trigger_payment_id, required),
		(2, trusted_rebalance_payment_id, required),
		(4, ln_rebalance_payment_id, required),
		(6, amount_msat, required),
		(8, fee_msat, required),
	},
	(8, SplicePending) => {
		(1, channel_id, required),
		(3, counterparty_node_id, required),
		(5, user_channel_id, required),
		(7, new_funding_txo, required),
	},
);

/// A queue for events emitted by the [`Wallet`].
///
/// [`Wallet`]: [`crate::Wallet`]
pub struct EventQueue {
	queue: Arc<Mutex<VecDeque<Event>>>,
	pending_mpp_events: Arc<Mutex<HashMap<PaymentHash, Vec<Event>>>>,
	/// Signals a waiting [`EventQueue::next_event_async`] that the queue changed. A push or an
	/// acknowledgement calls [`Notify::notify_one`] after releasing the queue lock; the waiter
	/// registers before it checks the queue, so no change can slip between its check and its
	/// wait.
	notify: Arc<Notify>,
	kv_store: Arc<dyn DynStore>,
	rebalance_enabled: RebalanceEnabledCache,
	tx_metadata: TxMetadataStore,
	logger: Arc<Logger>,
}

impl EventQueue {
	/// Builds the queue over `kv_store`, starting from the events a previous run left unhandled.
	///
	/// The queue is persisted under [`EVENT_QUEUE_PERSISTENCE_KEY`] after every push and every
	/// [`EventQueue::event_handled`], so the stored copy is exactly the set of events the user has
	/// not acknowledged yet. Loading it means an event emitted shortly before a shutdown, or one
	/// the user never got to handle, is delivered on the next run instead of being dropped.
	///
	/// Delivery is at-least-once: an LDK event is persisted here before it is acknowledged to
	/// ldk-node, so a crash between the two delivers it again after a restart, once from this
	/// queue and once from ldk-node's own replay. Consumers must be idempotent, as ldk-node
	/// already requires of its event handlers.
	///
	/// A missing key is a fresh wallet and starts empty. Any other read error, or a stored queue
	/// that does not decode, fails the build: the wallet must not silently start without events
	/// it owes the user.
	pub(crate) async fn new(
		kv_store: Arc<dyn DynStore>, tx_metadata: TxMetadataStore, logger: Arc<Logger>,
	) -> Result<Self, ldk_node::lightning::io::Error> {
		let persisted = match KVStore::read(
			kv_store.as_ref(),
			EVENT_QUEUE_PERSISTENCE_PRIMARY_NAMESPACE,
			EVENT_QUEUE_PERSISTENCE_SECONDARY_NAMESPACE,
			EVENT_QUEUE_PERSISTENCE_KEY,
		)
		.await
		{
			Ok(bytes) => {
				EventQueueDeserWrapper::read(&mut &bytes[..])
					.map_err(|e| {
						log_error!(logger.as_ref(), "Failed to deserialize event queue: {}", e);
						ldk_node::lightning::io::Error::new(
							ldk_node::lightning::io::ErrorKind::InvalidData,
							"Failed to deserialize EventQueue",
						)
					})?
					.0
			},
			Err(e) if e.kind() == ldk_node::lightning::io::ErrorKind::NotFound => VecDeque::new(),
			Err(e) => {
				log_error!(logger.as_ref(), "Failed to read event queue from store: {}", e);
				return Err(e);
			},
		};
		if !persisted.is_empty() {
			log_info!(
				logger.as_ref(),
				"Loaded {} unhandled event(s) from the store",
				persisted.len()
			);
		}
		let queue = Arc::new(Mutex::new(persisted));
		let pending_mpp_events = Arc::new(Mutex::new(HashMap::new()));
		let notify = Arc::new(Notify::new());
		let rebalance_enabled = RebalanceEnabledCache::new(Arc::clone(&kv_store));
		Ok(Self {
			queue,
			pending_mpp_events,
			notify,
			kv_store,
			rebalance_enabled,
			tx_metadata,
			logger,
		})
	}

	pub(crate) async fn get_rebalance_enabled(&self) -> bool {
		self.rebalance_enabled.get().await
	}

	pub(crate) async fn set_rebalance_enabled(&self, enabled: bool) {
		self.rebalance_enabled.set(enabled).await;
	}

	/// Starts buffering terminal events for a multi-path payment while its leg metadata is being
	/// registered.
	pub(crate) async fn begin_mpp_setup(&self, payment_hash: PaymentHash) {
		self.pending_mpp_events.lock().await.entry(payment_hash).or_default();
	}

	/// Stops buffering terminal events for a multi-path payment and re-processes any events that
	/// arrived before the leg metadata was registered.
	pub(crate) async fn finish_mpp_setup(
		&self, payment_hash: PaymentHash,
	) -> Result<(), ldk_node::lightning::io::Error> {
		let pending_events = self.pending_mpp_events.lock().await.remove(&payment_hash);
		if let Some(events) = pending_events {
			for event in events {
				self.add_event(event).await?;
			}
		}
		Ok(())
	}

	pub(crate) async fn add_event(
		&self, event: Event,
	) -> Result<(), ldk_node::lightning::io::Error> {
		// Outgoing payments split across the trusted and lightning wallets emit a terminal event per
		// leg. Record each leg's result onto the shared, persisted metadata; the leg that completes
		// the payment yields the single combined event we surface instead of the per-leg ones.
		match &event {
			Event::PaymentSuccessful { payment_id, payment_preimage, fee_paid_msat, .. }
				if self.is_mpp_leg(payment_id) =>
			{
				let combined = self
					.tx_metadata
					.record_mpp_leg(
						*payment_id,
						Some((fee_paid_msat.unwrap_or(0), payment_preimage.0)),
					)
					.await;
				return self.push_combined_mpp(combined).await;
			},
			Event::PaymentFailed { payment_id, .. } if self.is_mpp_leg(payment_id) => {
				let combined = self.tx_metadata.record_mpp_leg(*payment_id, None).await;
				return self.push_combined_mpp(combined).await;
			},
			_ => {},
		}

		if let Some(payment_hash) = terminal_payment_hash(&event) {
			let mut pending_mpp_events = self.pending_mpp_events.lock().await;
			if let Some(events) = pending_mpp_events.get_mut(&payment_hash) {
				events.push(event);
				return Ok(());
			}
		}

		self.push_event(event).await
	}

	/// Whether `id` identifies a leg of a multi-path payment.
	fn is_mpp_leg(&self, id: &PaymentId) -> bool {
		matches!(self.tx_metadata.read().get(id).map(|m| m.ty), Some(TxType::MppPayment { .. }))
	}

	/// Surfaces the single combined event for a multi-path payment, or nothing if the payment is
	/// still waiting on its other leg (or already produced its combined event).
	async fn push_combined_mpp(
		&self, combined: Option<(PaymentId, MppOutcome)>,
	) -> Result<(), ldk_node::lightning::io::Error> {
		match combined {
			Some((surface_id, MppOutcome::Succeeded { payment_hash, preimage, fee_msat })) => {
				self.push_event(Event::PaymentSuccessful {
					payment_id: surface_id,
					payment_hash: PaymentHash(payment_hash),
					payment_preimage: PaymentPreimage(preimage),
					fee_paid_msat: Some(fee_msat),
				})
				.await
			},
			Some((surface_id, MppOutcome::Failed { payment_hash })) => {
				self.push_event(Event::PaymentFailed {
					payment_id: surface_id,
					payment_hash: Some(PaymentHash(payment_hash)),
					reason: None,
				})
				.await
			},
			None => Ok(()),
		}
	}

	/// Appends an event to the queue and persists it, waking any pending consumer.
	async fn push_event(&self, event: Event) -> Result<(), ldk_node::lightning::io::Error> {
		{
			let mut locked_queue = self.queue.lock().await;
			locked_queue.push_back(event);
			self.persist_queue(&locked_queue).await?;
		}

		self.notify.notify_one();
		Ok(())
	}

	pub(crate) async fn next_event(&self) -> Option<Event> {
		let locked_queue = self.queue.lock().await;
		locked_queue.front().cloned()
	}

	/// Waits until the queue has an event and returns it (without removing it).
	///
	/// The wait is registered before the queue is checked, so a push that lands between the
	/// check and the wait is not lost: [`EventQueue::push_event`] and
	/// [`EventQueue::event_handled`] call [`Notify::notify_one`] after releasing the queue lock,
	/// and a `notify_one` with no registered waiter leaves a permit that completes the next wait
	/// at once. A wait that is dropped after being notified (the caller raced it against a
	/// shutdown, say) passes the notification on to the next waiter, so cancelling this future
	/// cannot swallow an event either. Waking spuriously is harmless: the loop checks the queue
	/// again.
	pub(crate) async fn next_event_async(&self) -> Event {
		loop {
			let mut notified = std::pin::pin!(self.notify.notified());
			notified.as_mut().enable();
			if let Some(event) = self.queue.lock().await.front().cloned() {
				return event;
			}
			notified.await;
		}
	}

	pub(crate) async fn event_handled(&self) -> Result<(), ldk_node::lightning::io::Error> {
		{
			let mut locked_queue = self.queue.lock().await;
			locked_queue.pop_front();
			self.persist_queue(&locked_queue).await?;
		}

		self.notify.notify_one();
		Ok(())
	}

	async fn persist_queue(
		&self, locked_queue: &VecDeque<Event>,
	) -> Result<(), ldk_node::lightning::io::Error> {
		let data = EventQueueSerWrapper(locked_queue).encode();
		KVStore::write(
			self.kv_store.as_ref(),
			EVENT_QUEUE_PERSISTENCE_PRIMARY_NAMESPACE,
			EVENT_QUEUE_PERSISTENCE_SECONDARY_NAMESPACE,
			EVENT_QUEUE_PERSISTENCE_KEY,
			data,
		)
		.await
		.map_err(|e| {
			log_error!(
				self.logger.as_ref(),
				"Write for key {}/{}/{} failed due to: {}",
				EVENT_QUEUE_PERSISTENCE_PRIMARY_NAMESPACE,
				EVENT_QUEUE_PERSISTENCE_SECONDARY_NAMESPACE,
				EVENT_QUEUE_PERSISTENCE_KEY,
				e
			);
			e
		})?;
		Ok(())
	}
}

fn terminal_payment_hash(event: &Event) -> Option<PaymentHash> {
	match event {
		Event::PaymentSuccessful { payment_hash, .. } => Some(*payment_hash),
		Event::PaymentFailed { payment_hash, .. } => *payment_hash,
		_ => None,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::logging::LoggerType;
	use crate::store::{PaymentId, PaymentType, TxMetadata, TxMetadataStore, TxType};
	use ldk_node::io::sqlite_store::SqliteStore;
	use ldk_node::lightning::io;
	use ldk_node::lightning::util::persist::{PageToken, PaginatedListResponse};
	use std::future::Future;
	use std::path::PathBuf;
	use std::pin::Pin;
	use std::sync::atomic::{AtomicUsize, Ordering};
	use std::time::{Duration, UNIX_EPOCH};

	fn temp_sqlite_store() -> (PathBuf, Arc<dyn DynStore>) {
		let path = std::env::temp_dir().join(format!(
			"orange-sdk-event-mpp-buffer-test-{}",
			SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
		));
		let store = SqliteStore::new(path.clone(), Some("orange.sqlite".to_string()), None)
			.expect("sqlite store");
		(path, Arc::new(store))
	}

	fn mpp_metadata(surface_id: PaymentId, lightning_leg: [u8; 32]) -> TxMetadata {
		TxMetadata {
			ty: TxType::MppPayment {
				surface_id,
				lightning_leg,
				total_amount_msat: 200_000,
				ty: PaymentType::OutgoingLightningBolt11 { payment_preimage: None },
				trusted_fee_msat: None,
				lightning_fee_msat: None,
				preimage: None,
				failed: false,
				finalized: false,
			},
			time: Duration::from_secs(1),
		}
	}

	#[tokio::test]
	async fn pending_mpp_setup_buffers_terminal_events_until_metadata_exists() {
		let (_path, store) = temp_sqlite_store();
		let tx_metadata = TxMetadataStore::new(Arc::clone(&store)).await;
		let queue = EventQueue::new(
			store,
			tx_metadata.clone(),
			Arc::new(Logger::new(&LoggerType::LogFacade).expect("logger")),
		)
		.await
		.expect("event queue");

		let payment_hash = PaymentHash([3u8; 32]);
		let surface_id = PaymentId::Trusted([7u8; 32]);
		let lightning_id = PaymentId::SelfCustodial(payment_hash.0);
		let preimage = PaymentPreimage([1u8; 32]);

		queue.begin_mpp_setup(payment_hash).await;
		queue
			.add_event(Event::PaymentSuccessful {
				payment_id: surface_id,
				payment_hash,
				payment_preimage: preimage,
				fee_paid_msat: Some(1_000),
			})
			.await
			.expect("buffer event");
		assert_eq!(queue.next_event().await, None);

		tx_metadata.insert(surface_id, mpp_metadata(surface_id, payment_hash.0)).await;
		tx_metadata.upsert(lightning_id, mpp_metadata(surface_id, payment_hash.0)).await;
		queue.finish_mpp_setup(payment_hash).await.expect("replay buffered events");
		assert_eq!(queue.next_event().await, None);

		queue
			.add_event(Event::PaymentSuccessful {
				payment_id: lightning_id,
				payment_hash,
				payment_preimage: preimage,
				fee_paid_msat: Some(2_000),
			})
			.await
			.expect("complete mpp");

		assert_eq!(
			queue.next_event().await,
			Some(Event::PaymentSuccessful {
				payment_id: surface_id,
				payment_hash,
				payment_preimage: preimage,
				fee_paid_msat: Some(3_000),
			})
		);
	}

	fn failed_payment(tag: u8) -> Event {
		Event::PaymentFailed {
			payment_id: PaymentId::SelfCustodial([tag; 32]),
			payment_hash: Some(PaymentHash([tag; 32])),
			reason: None,
		}
	}

	/// The queue is persisted after every push and every acknowledgement; a queue built over the
	/// same store must start from that copy, or every event still unhandled at a shutdown is lost.
	#[tokio::test]
	async fn unhandled_events_survive_a_restart() {
		let (_path, store) = temp_sqlite_store();
		let logger = Arc::new(Logger::new(&LoggerType::LogFacade).expect("logger"));
		let tx_metadata = TxMetadataStore::new(Arc::clone(&store)).await;

		let queue = EventQueue::new(Arc::clone(&store), tx_metadata.clone(), Arc::clone(&logger))
			.await
			.expect("event queue");
		queue.add_event(failed_payment(1)).await.expect("push");
		queue.add_event(failed_payment(2)).await.expect("push");
		drop(queue);

		let queue = EventQueue::new(Arc::clone(&store), tx_metadata.clone(), Arc::clone(&logger))
			.await
			.expect("event queue");
		assert_eq!(queue.next_event().await, Some(failed_payment(1)));
		queue.event_handled().await.expect("ack");
		assert_eq!(queue.next_event().await, Some(failed_payment(2)));
		drop(queue);

		// The acknowledgement was persisted too: only the second event comes back.
		let queue =
			EventQueue::new(Arc::clone(&store), tx_metadata, logger).await.expect("event queue");
		assert_eq!(queue.next_event().await, Some(failed_payment(2)));
		queue.event_handled().await.expect("ack");
		assert_eq!(queue.next_event().await, None);
	}

	/// A stored queue that does not decode fails the build instead of starting empty.
	#[tokio::test]
	async fn an_undecodable_stored_queue_fails_the_build() {
		let (_path, store) = temp_sqlite_store();
		// One event announced, then a variant id no `Event` has.
		KVStore::write(
			store.as_ref(),
			EVENT_QUEUE_PERSISTENCE_PRIMARY_NAMESPACE,
			EVENT_QUEUE_PERSISTENCE_SECONDARY_NAMESPACE,
			EVENT_QUEUE_PERSISTENCE_KEY,
			vec![0x00, 0x01, 0xff],
		)
		.await
		.expect("write");
		let logger = Arc::new(Logger::new(&LoggerType::LogFacade).expect("logger"));
		let tx_metadata = TxMetadataStore::new(Arc::clone(&store)).await;
		let err = EventQueue::new(store, tx_metadata, logger).await.err().expect("must fail");
		assert_eq!(err.kind(), io::ErrorKind::InvalidData);
	}

	/// A store whose writes wait for the test to open a gate, so a push can be held inside
	/// `persist_queue` with the queue lock taken, where a slow remote store (VSS over a mobile
	/// link) holds it for hundreds of milliseconds.
	struct GatedStore {
		inner: Arc<dyn DynStore>,
		gate: watch::Receiver<bool>,
	}

	impl DynStore for GatedStore {
		fn read_async(
			&self, p: &str, s: &str, k: &str,
		) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, io::Error>> + Send + 'static>> {
			self.inner.read_async(p, s, k)
		}

		fn write_async(
			&self, p: &str, s: &str, k: &str, buf: Vec<u8>,
		) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + 'static>> {
			let inner = Arc::clone(&self.inner);
			let mut gate = self.gate.clone();
			let (p, s, k) = (p.to_owned(), s.to_owned(), k.to_owned());
			Box::pin(async move {
				gate.wait_for(|open| *open)
					.await
					.map_err(|_| io::Error::new(io::ErrorKind::Other, "gate dropped"))?;
				inner.write_async(&p, &s, &k, buf).await
			})
		}

		fn remove_async(
			&self, p: &str, s: &str, k: &str, lazy: bool,
		) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + 'static>> {
			self.inner.remove_async(p, s, k, lazy)
		}

		fn list_async(
			&self, p: &str, s: &str,
		) -> Pin<Box<dyn Future<Output = Result<Vec<String>, io::Error>> + Send + 'static>> {
			self.inner.list_async(p, s)
		}

		fn list_paginated_async(
			&self, p: &str, s: &str, page_token: Option<PageToken>,
		) -> Pin<Box<dyn Future<Output = Result<PaginatedListResponse, io::Error>> + Send + 'static>>
		{
			self.inner.list_paginated_async(p, s, page_token)
		}
	}

	/// Stands in for the thread `Wallet::wait_next_event` parks in `block_on`: a wake-up polls
	/// the consumer again at once, so the poll lands wherever the wake-up came from.
	struct PollOnWake {
		consumer: std::sync::Mutex<Option<Pin<Box<dyn Future<Output = Event> + Send>>>>,
		delivered: std::sync::Mutex<Option<Event>>,
		polls: AtomicUsize,
		reentrant_wakes: AtomicUsize,
	}

	impl PollOnWake {
		fn new(consumer: Pin<Box<dyn Future<Output = Event> + Send>>) -> Self {
			Self {
				consumer: std::sync::Mutex::new(Some(consumer)),
				delivered: std::sync::Mutex::new(None),
				polls: AtomicUsize::new(0),
				reentrant_wakes: AtomicUsize::new(0),
			}
		}

		fn poll_consumer(self: &Arc<Self>) {
			let Ok(mut slot) = self.consumer.try_lock() else {
				self.reentrant_wakes.fetch_add(1, Ordering::SeqCst);
				return;
			};
			let Some(consumer) = slot.as_mut() else { return };
			self.polls.fetch_add(1, Ordering::SeqCst);
			let waker = std::task::Waker::from(Arc::clone(self));
			let mut cx = std::task::Context::from_waker(&waker);
			if let std::task::Poll::Ready(event) = consumer.as_mut().poll(&mut cx) {
				*self.delivered.lock().unwrap() = Some(event);
				*slot = None;
			}
		}

		fn delivered(&self) -> Option<Event> {
			self.delivered.lock().unwrap().clone()
		}
	}

	impl std::task::Wake for PollOnWake {
		fn wake(self: Arc<Self>) {
			self.poll_consumer();
		}

		fn wake_by_ref(self: &Arc<Self>) {
			self.poll_consumer();
		}
	}

	/// The consumer is woken while one pusher still holds its post-persist section and a second
	/// pusher holds the queue inside its own persist. Its poll must leave it registered for the
	/// next change. Before the `Notify` rewrite, `EventFuture::poll` read both `try_lock`
	/// failures as "nothing to do" and returned `Pending` without a waker, so the second push,
	/// and every push after it, woke nobody: the wallet kept queueing events that no
	/// `wait_next_event` would ever return.
	#[tokio::test]
	async fn a_poll_that_lands_on_two_busy_pushers_is_still_woken() {
		let (_path, sqlite) = temp_sqlite_store();
		let (open_gate, gate) = watch::channel(false);
		let store: Arc<dyn DynStore> = Arc::new(GatedStore { inner: Arc::clone(&sqlite), gate });
		let logger = Arc::new(Logger::new(&LoggerType::LogFacade).expect("logger"));
		let tx_metadata = TxMetadataStore::new(sqlite).await;
		let queue =
			Arc::new(EventQueue::new(store, tx_metadata, logger).await.expect("event queue"));

		// The consumer waits on an empty queue.
		let consumer = Arc::new(PollOnWake::new({
			let queue = Arc::clone(&queue);
			Box::pin(async move { queue.next_event_async().await })
		}));
		consumer.poll_consumer();
		assert_eq!(consumer.delivered(), None);

		// Pusher A takes the queue lock and parks in its persist; pusher B queues up behind it.
		let a = tokio::spawn({
			let queue = Arc::clone(&queue);
			async move { queue.add_event(failed_payment(1)).await }
		});
		for _ in 0..8 {
			tokio::task::yield_now().await;
		}
		let b = tokio::spawn({
			let queue = Arc::clone(&queue);
			async move { queue.add_event(failed_payment(2)).await }
		});
		for _ in 0..8 {
			tokio::task::yield_now().await;
		}
		assert!(!a.is_finished() && !b.is_finished());

		// A's persist completes: the queue lock passes to B, and A wakes the consumer, whose poll
		// lands while B holds the queue. Then B's persist completes.
		open_gate.send(true).expect("gate");
		a.await.expect("join").expect("push A");
		b.await.expect("join").expect("push B");

		assert_eq!(consumer.reentrant_wakes.load(Ordering::SeqCst), 0);
		assert_eq!(
			consumer.delivered(),
			Some(failed_payment(1)),
			"polled {} time(s), never handed the event",
			consumer.polls.load(Ordering::SeqCst)
		);
	}

	/// An event handler around an ldk-node that is never started (so no bitcoind is needed) and a
	/// dummy trusted wallet that holds no payments. Keep the returned sender alive.
	#[cfg(feature = "_test-utils")]
	async fn claimable_test_handler() -> (PathBuf, LdkEventHandler, TrustedWalletSender) {
		use crate::lightning_wallet::{InboundPaymentIds, SplicePendingInbox};
		use crate::trusted_wallet::dummy::DummyTrustedWallet;
		use std::sync::Mutex as StdMutex;
		use tokio::sync::Notify;

		let (path, store) = temp_sqlite_store();
		let tx_metadata = TxMetadataStore::new(Arc::clone(&store)).await;
		let logger = Arc::new(Logger::new(&LoggerType::LogFacade).expect("logger"));
		let event_queue = Arc::new(
			EventQueue::new(Arc::clone(&store), tx_metadata.clone(), Arc::clone(&logger))
				.await
				.expect("event queue"),
		);

		let mut builder = ldk_node::Builder::new();
		builder.set_network(ldk_node::bitcoin::Network::Regtest);
		builder.set_storage_dir_path(path.join("ldk").to_str().unwrap().to_string());
		let node_entropy = ldk_node::entropy::NodeEntropy::from_seed_bytes([7; 64]);
		let ldk_node = Arc::new(builder.build(node_entropy).expect("build ldk-node"));

		let trusted: Box<DynTrustedWalletInterface> =
			Box::new(DummyTrustedWallet::unstarted(Arc::clone(&ldk_node)));
		let (trusted_sender, trusted_handle) = watch::channel(Some(Arc::new(trusted)));

		let handler = LdkEventHandler {
			event_queue,
			ldk_node,
			tx_metadata,
			store,
			trusted: trusted_handle,
			payment_receipt_sender: watch::channel(()).0,
			channel_pending_sender: watch::channel(0).0,
			splice_pending_inbox: Arc::new(SplicePendingInbox {
				pending: StdMutex::new(HashMap::new()),
				notify: Notify::new(),
			}),
			inbound_payment_ids: Arc::new(InboundPaymentIds::default()),
			logger,
		};
		(path, handler, trusted_sender)
	}

	#[cfg(feature = "_test-utils")]
	type TrustedWalletSender = watch::Sender<Option<Arc<Box<DynTrustedWalletInterface>>>>;

	/// `claim_for_id` no longer checks the amount (ldk-node #1170), so the check against the
	/// wrapped receive's requested amount is the only thing standing between an underpaid HTLC
	/// and a claim that releases the preimage.
	#[cfg(feature = "_test-utils")]
	#[tokio::test(flavor = "multi_thread")]
	async fn underpaid_wrapped_receive_is_failed_back_and_kept() {
		let (_path, handler, _trusted_sender) = claimable_test_handler().await;
		let payment_hash = PaymentHash([0x5a; 32]);
		// Test data only. The decision does not check it against the hash.
		let preimage = [0x42; 32];
		let entry = store::WrappedReceiveEntry {
			preimage,
			created_at_secs: 1_700_000_000,
			amount_msat: 21_000,
		};
		store::write_wrapped_receive(&*handler.store, &payment_hash, &entry).await.unwrap();

		for underpaid in [0, 1, 20_999] {
			assert!(matches!(
				handler.decide_payment_claimable(payment_hash, underpaid).await,
				ClaimableDecision::FailBack
			));
		}
		// The entry stays, so a payment of the full amount can still be claimed.
		assert!(
			store::read_wrapped_receive(&*handler.store, &payment_hash).await.unwrap().is_some()
		);

		for paid in [21_000, 21_001, u64::MAX] {
			assert!(matches!(
				handler.decide_payment_claimable(payment_hash, paid).await,
				ClaimableDecision::Claim(p) if p == PaymentPreimage(preimage)
			));
		}
	}

	#[cfg(feature = "_test-utils")]
	#[tokio::test(flavor = "multi_thread")]
	async fn claimable_payment_without_a_wrapped_receive_is_failed_back() {
		let (_path, handler, _trusted_sender) = claimable_test_handler().await;
		assert!(matches!(
			handler.decide_payment_claimable(PaymentHash([0x6b; 32]), u64::MAX).await,
			ClaimableDecision::FailBack
		));
	}
}

struct EventQueueSerWrapper<'a>(&'a VecDeque<Event>);

impl Writeable for EventQueueSerWrapper<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ldk_node::lightning::io::Error> {
		(self.0.len() as u16).write(writer)?;
		for e in self.0.iter() {
			e.write(writer)?;
		}
		Ok(())
	}
}

struct EventQueueDeserWrapper(VecDeque<Event>);

impl Readable for EventQueueDeserWrapper {
	fn read<R: ldk_node::lightning::io::Read>(
		reader: &mut R,
	) -> Result<Self, ldk_node::lightning::ln::msgs::DecodeError> {
		let len: u16 = Readable::read(reader)?;
		let mut queue = VecDeque::with_capacity(len as usize);
		for _ in 0..len {
			queue.push_back(Readable::read(reader)?);
		}
		Ok(Self(queue))
	}
}

/// What [`LdkEventHandler`] does with a payment waiting to be claimed (`PaymentClaimable`).
///
/// Deliberately not `Debug`: `Claim` holds a preimage, which must never be printed.
enum ClaimableDecision {
	/// Claim the payment with this preimage.
	Claim(PaymentPreimage),
	/// Fail the payment back.
	FailBack,
}

/// The trusted wallet as seen by [`LdkEventHandler`], which starts before the trusted wallet has
/// finished initializing. Holds `None` until [`crate::Wallet::new`] has built both wallets; if
/// initialization fails the sender is dropped while still holding `None`.
pub(crate) type TrustedWalletHandle = watch::Receiver<Option<Arc<Box<DynTrustedWalletInterface>>>>;

#[derive(Clone)]
pub(crate) struct LdkEventHandler {
	pub(crate) event_queue: Arc<EventQueue>,
	pub(crate) ldk_node: Arc<ldk_node::Node>,
	pub(crate) tx_metadata: store::TxMetadataStore,
	pub(crate) store: Arc<dyn DynStore>,
	pub(crate) trusted: TrustedWalletHandle,
	pub(crate) payment_receipt_sender: watch::Sender<()>,
	pub(crate) channel_pending_sender: watch::Sender<u128>,
	pub(crate) splice_pending_inbox: Arc<crate::lightning_wallet::SplicePendingInbox>,
	pub(crate) inbound_payment_ids: Arc<crate::lightning_wallet::InboundPaymentIds>,
	pub(crate) logger: Arc<Logger>,
}

impl LdkEventHandler {
	pub(crate) async fn handle_ldk_node_event(&self, event: ldk_node::Event) {
		match event {
			ldk_node::Event::PaymentSuccessful {
				payment_id,
				payment_hash,
				payment_preimage,
				fee_paid_msat,
				bolt12_invoice: _,
			} => {
				let preimage = payment_preimage.unwrap(); // safe
				let payment_id = PaymentId::SelfCustodial(payment_id.0);

				if self.tx_metadata.set_preimage(payment_id, preimage.0).await.is_err() {
					log_error!(self.logger, "Failed to set preimage for payment {payment_id:?}");
				}

				if let Err(e) = self
					.event_queue
					.add_event(Event::PaymentSuccessful {
						payment_id,
						payment_hash,
						payment_preimage: preimage,
						fee_paid_msat,
					})
					.await
				{
					log_error!(self.logger, "Failed to add PaymentSuccessful event: {e:?}");
					return;
				}
			},
			ldk_node::Event::PaymentFailed { payment_id, payment_hash, reason } => {
				if let Err(e) = self
					.event_queue
					.add_event(Event::PaymentFailed {
						payment_id: PaymentId::SelfCustodial(payment_id.0),
						payment_hash,
						reason,
					})
					.await
				{
					log_error!(self.logger, "Failed to add PaymentFailed event: {e:?}");
					return;
				}
			},
			ldk_node::Event::PaymentReceived {
				payment_id,
				payment_hash,
				amount_msat,
				custom_records,
			} => {
				// Inbound ids are derived by LDK from the HTLCs, not the payment hash: remember
				// this one so `await_payment_receipt` can find the payment by its hash.
				self.inbound_payment_ids.record_received(payment_hash, payment_id);

				// The fee is informational, so a failed store read must not hold back the event:
				// it is logged and the event carries no fee.
				let lsp_fee_msats = match self.ldk_node.payment(&payment_id) {
					Ok(Some(p)) => {
						if let PaymentKind::Bolt11 { counterparty_skimmed_fee_msat, .. } = p.kind {
							counterparty_skimmed_fee_msat
						} else {
							None
						}
					},
					Ok(None) => None,
					Err(e) => {
						log_error!(
							self.logger,
							"Failed to read received payment {payment_id} for its LSP fee: {e}"
						);
						None
					},
				};

				if let Err(e) = self
					.event_queue
					.add_event(Event::PaymentReceived {
						payment_id: PaymentId::SelfCustodial(payment_id.0),
						payment_hash,
						amount_msat,
						custom_records,
						lsp_fee_msats,
					})
					.await
				{
					log_error!(self.logger, "Failed to add PaymentReceived event: {e:?}");
				}
				// If this was the lightning leg of a wrapped receive, its preimage is no longer needed.
				if let Err(e) = store::remove_wrapped_receive(&*self.store, &payment_hash).await {
					log_error!(self.logger, "Failed to remove wrapped receive {payment_hash}: {e}");
				}
				let _ = self.payment_receipt_sender.send(());
			},
			ldk_node::Event::PaymentForwarded { .. } => {},
			ldk_node::Event::PaymentClaimable {
				payment_id,
				payment_hash,
				claimable_amount_msat,
				..
			} => {
				self.inbound_payment_ids.record_claimable(payment_hash, payment_id);
				self.handle_payment_claimable(payment_id, payment_hash, claimable_amount_msat)
					.await;
			},
			ldk_node::Event::ChannelPending { funding_txo, .. } => {
				log_debug!(self.logger, "Received ChannelPending event");
				// The funding tx is already in `ldk_node.list_payments()`; populate our
				// metadata before any concurrent `list_transactions` call observes the
				// outbound payment.
				self.reserve_rebalance_slot_for_funding_tx(funding_txo.txid).await;
			},
			ldk_node::Event::ChannelReady {
				channel_id,
				user_channel_id,
				counterparty_node_id,
				funding_txo,
			} => {
				let funding_txo = funding_txo.unwrap(); // safe

				if let Err(e) = self
					.event_queue
					.add_event(Event::ChannelOpened {
						channel_id,
						user_channel_id,
						counterparty_node_id: counterparty_node_id.unwrap(), // safe
						funding_txo,
					})
					.await
				{
					log_error!(self.logger, "Failed to add ChannelOpened event: {e:?}");
					return;
				}
				let _ = self.channel_pending_sender.send(user_channel_id.0);
			},
			ldk_node::Event::ChannelClosed {
				channel_id,
				user_channel_id,
				counterparty_node_id,
				reason,
			} => {
				// We experienced a channel close, we disable rebalancing so we don't automatically
				// try to reopen the channel.
				self.event_queue.set_rebalance_enabled(false).await;

				if let Err(e) = self
					.event_queue
					.add_event(Event::ChannelClosed {
						channel_id,
						user_channel_id,
						counterparty_node_id,
						reason,
					})
					.await
				{
					log_error!(self.logger, "Failed to add ChannelClosed event: {e:?}");
					return;
				}
			},
			ldk_node::Event::SpliceNegotiated {
				channel_id,
				user_channel_id,
				counterparty_node_id,
				new_funding_txo,
			} => {
				log_debug!(self.logger, "Received SpliceNegotiated event {event:?}");
				// Reserve the metadata slot before delivering so any task waking on the
				// inbox (the rebalancer's `OnChainRebalanceInitiated` for splice-in,
				// `pay_lightning` for splice-out) sees an entry to upsert.
				self.reserve_rebalance_slot_for_funding_tx(new_funding_txo.txid).await;
				self.splice_pending_inbox.deliver(user_channel_id.0, new_funding_txo);

				if let Err(e) = self
					.event_queue
					.add_event(Event::SplicePending {
						channel_id,
						user_channel_id,
						counterparty_node_id,
						new_funding_txo,
					})
					.await
				{
					log_error!(self.logger, "Failed to add SplicePending event: {e:?}");
					return;
				}
			},
			ldk_node::Event::SpliceNegotiationFailed { .. } => {
				log_warn!(self.logger, "Received SpliceNegotiationFailed event: {event:?}");
			},
		}

		if let Err(e) = self.ldk_node.event_handled() {
			log_error!(self.logger, "Failed to handle event: {e:?}");
		}
	}

	/// Claims or fails a payment to an invoice from
	/// [`crate::lightning_wallet::LightningWallet::get_bolt11_invoice_for_hash`], the only kind of
	/// payment ldk-node leaves for us to claim. ldk-node requires that every such payment is
	/// promptly claimed or failed back.
	///
	/// We claim only a payment for a wrapped receive we still hold the preimage for, of at least
	/// the amount requested, whose trusted leg has not been paid. Failing back is always safe: the
	/// payer can still pay the trusted leg.
	async fn handle_payment_claimable(
		&self, payment_id: LdkPaymentId, payment_hash: PaymentHash, claimable_amount_msat: u64,
	) {
		match self.decide_payment_claimable(payment_hash, claimable_amount_msat).await {
			ClaimableDecision::Claim(preimage) => {
				// `claim_for_id` checks only that the preimage matches the payment's hash, not the
				// amount: the check in `decide_payment_claimable` is the only one.
				if let Err(e) = self.ldk_node.bolt11_payment().claim_for_id(payment_id, preimage) {
					log_error!(self.logger, "Failed to claim wrapped receive {payment_hash}: {e}");
					self.fail_claimable_payment(payment_id, payment_hash);
				}
			},
			ClaimableDecision::FailBack => self.fail_claimable_payment(payment_id, payment_hash),
		}
	}

	/// Decides whether to claim a payment of `claimable_amount_msat` to `payment_hash`, as
	/// described on [`Self::handle_payment_claimable`], logging why one is failed back. Retires
	/// the wrapped receive if its trusted leg was already paid.
	async fn decide_payment_claimable(
		&self, payment_hash: PaymentHash, claimable_amount_msat: u64,
	) -> ClaimableDecision {
		let entry = match store::read_wrapped_receive(&*self.store, &payment_hash).await {
			Ok(Some(entry)) => entry,
			Ok(None) => {
				log_warn!(
					self.logger,
					"Failing back claimable payment {payment_hash}: not a pending wrapped receive"
				);
				return ClaimableDecision::FailBack;
			},
			Err(e) => {
				log_error!(
					self.logger,
					"Failing back claimable payment {payment_hash}: failed to read wrapped receive: {e}"
				);
				return ClaimableDecision::FailBack;
			},
		};

		if claimable_amount_msat < entry.amount_msat {
			log_warn!(
				self.logger,
				"Failing back wrapped receive {payment_hash}: claimable {claimable_amount_msat} msat is below the requested {} msat",
				entry.amount_msat
			);
			return ClaimableDecision::FailBack;
		}

		match self.trusted_leg_paid(payment_hash).await {
			Ok(false) => {},
			Ok(true) => {
				log_warn!(
					self.logger,
					"Failing back wrapped receive {payment_hash}: its trusted leg was already paid"
				);
				if let Err(e) = store::remove_wrapped_receive(&*self.store, &payment_hash).await {
					log_error!(self.logger, "Failed to remove wrapped receive {payment_hash}: {e}");
				}
				return ClaimableDecision::FailBack;
			},
			Err(e) => {
				log_error!(
					self.logger,
					"Failing back wrapped receive {payment_hash}: failed to check its trusted leg: {e}"
				);
				return ClaimableDecision::FailBack;
			},
		}

		ClaimableDecision::Claim(PaymentPreimage(entry.preimage))
	}

	/// Whether the trusted wallet already holds a payment for the trusted leg of a wrapped receive,
	/// waiting for the trusted wallet to finish initializing if needed.
	async fn trusted_leg_paid(&self, payment_hash: PaymentHash) -> Result<bool, TrustedError> {
		let trusted = {
			let mut handle = self.trusted.clone();
			match handle.wait_for(Option::is_some).await {
				Ok(trusted) => trusted.as_ref().map(Arc::clone),
				Err(_) => None,
			}
		};
		match trusted {
			Some(trusted) => trusted.has_lightning_receive_for_hash(payment_hash.0).await,
			None => Err(TrustedError::Other("Trusted wallet failed to initialize".to_owned())),
		}
	}

	fn fail_claimable_payment(&self, payment_id: LdkPaymentId, payment_hash: PaymentHash) {
		fail_back_claimable(&self.ldk_node, payment_id, payment_hash, &self.logger);
	}

	/// Reserve a `PendingRebalance` metadata slot for a freshly broadcast channel or splice
	/// funding tx. The matching outbound on-chain payment is already visible in
	/// `ldk_node.list_payments()` by the time we're called, so without this entry
	/// `list_transactions` would trip its `debug_assert_ne!`. `PendingRebalance` is used as the
	/// placeholder because `list_transactions` already skips it.
	async fn reserve_rebalance_slot_for_funding_tx(&self, txid: Txid) {
		let payment_id = PaymentId::SelfCustodial(txid.to_byte_array());
		if self.tx_metadata.read().get(&payment_id).is_some() {
			return;
		}
		self.tx_metadata
			.upsert(
				payment_id,
				store::TxMetadata {
					ty: store::TxType::PendingRebalance {},
					time: SystemTime::now()
						.duration_since(SystemTime::UNIX_EPOCH)
						.unwrap_or_default(),
				},
			)
			.await;
	}
}

/// Fails a claimable payment back, then removes the record ldk-node made for it.
///
/// ldk-node creates that record when the HTLCs arrive (we enable
/// `manually_handle_unknown_bolt11_payments`) and `fail_for_id` only marks it failed, so
/// without the removal every payment we refuse, including any number of payments to an
/// invoice we do not hold the preimage for, would stay in the payment store for good and be
/// read back on every full listing. Nothing else refers to it: `fail_for_id` has already failed
/// the HTLCs back (ldk-node's `HTLCHandlingFailed` handling does not look payments up), and the
/// payment never appears in our history. If LDK offers the same HTLCs again, ldk-node records
/// them afresh under the same id. If instead only our handling of this event is replayed after
/// a restart, `fail_for_id` no longer finds the record and logs an error; should the failure
/// not have been persisted by then, LDK still fails the HTLCs back itself before they expire.
///
/// A payment already recorded as received is left alone. `fail_for_id` and `remove_payment` check
/// no status, and a `PaymentClaimable` replayed after a restart for a payment we did claim can
/// still be decided against (the trusted wallet not initialized, a store error), which would
/// otherwise mark the received payment failed and delete it.
pub(crate) fn fail_back_claimable(
	node: &ldk_node::Node, payment_id: LdkPaymentId, payment_hash: PaymentHash, logger: &Logger,
) {
	match node.payment(&payment_id) {
		Ok(Some(payment)) if payment.status == PaymentStatus::Succeeded => {
			log_info!(
				logger,
				"Not failing back payment {payment_id} for {payment_hash}: it was already received"
			);
			return;
		},
		Ok(_) => {},
		Err(e) => {
			// We cannot tell whether it was received: fail it back, as before the record
			// removal, but keep its record.
			log_error!(
				logger,
				"Failed to read claimable payment {payment_id} for {payment_hash}, failing it back without removing its record: {e}"
			);
			if let Err(e) = node.bolt11_payment().fail_for_id(payment_id) {
				log_error!(logger, "Failed to fail back claimable payment {payment_hash}: {e}");
			}
			return;
		},
	}
	if let Err(e) = node.bolt11_payment().fail_for_id(payment_id) {
		log_error!(logger, "Failed to fail back claimable payment {payment_hash}: {e}");
		return;
	}
	if let Err(e) = node.remove_payment(&payment_id) {
		log_error!(
			logger,
			"Failed to remove the record of failed-back payment {payment_id} for {payment_hash}: {e}"
		);
	}
}
