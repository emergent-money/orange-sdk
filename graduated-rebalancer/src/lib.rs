#![deny(missing_docs)]
#![allow(clippy::type_complexity)]

//! A library for managing graduated rebalancing between trusted and lightning wallets.
//!
//! This crate provides a `GraduatedRebalancer` that automatically manages the balance
//! between trusted wallets (for small amounts) and lightning wallets (for larger amounts)
//! based on configurable thresholds.

use bitcoin_payment_instructions::amount::Amount;
use bitcoin_payment_instructions::PaymentMethod;
use lightning::bitcoin::hex::DisplayHex;
use lightning::bitcoin::OutPoint;
use lightning::util::logger::Logger;
use lightning::{log_debug, log_error, log_info, log_warn};
use lightning_invoice::Bolt11Invoice;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn duration_to_millis(duration: Duration) -> u64 {
	u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// How long after the expiry of a rebalance invoice the rebalancer still waits for the payment to
/// it to be received.
///
/// LDK accepts a payment to one of its invoices until two hours after the invoice's expiry, as a
/// buffer against block timestamps running ahead of real time (rust-lightning
/// `inbound_payment.rs:271-280`, `calculate_absolute_expiry`), and the wait covers that window.
/// LDK counts it from the highest block-header time it has seen, which may lead the wall clock by
/// up to two hours, so a payment could still be accepted that long after the wait has ended.
///
/// With orange-sdk's 24 h rebalance invoices, a rebalance whose failure goes undetected holds the
/// rebalancer for at most 26 h. One the trusted wallet reports failed holds it for seconds plus
/// [`RebalanceTunables::trusted_failure_receipt_grace`], whether or not a receipt then lands and
/// whether or not the trusted wallet ever reports an outcome (Cashu does not, for a failed melt).
/// Once the receipt is in hand with no failure reported, at most another 10 min
/// (`TRUSTED_VERDICT_WAIT`) for the trusted wallet's verdict.
pub const RECEIPT_DEADLINE_GRACE: Duration = Duration::from_secs(7_200);

/// With a rebalance's Lightning receipt in hand and no trusted failure reported, how long the
/// rebalancer still waits for the trusted wallet's verdict. The verdict then only supplies the
/// trusted fee, which is informational, so it must not hold the rebalancer for long: a Cashu
/// melt whose confirm failed without a definite verdict, or a slow Spark listing, could otherwise
/// keep it until the receipt deadline.
const TRUSTED_VERDICT_WAIT: Duration = Duration::from_secs(600);

/// When the rebalancer stops waiting for the payment to `invoice` to be received: the invoice's
/// expiry plus [`RECEIPT_DEADLINE_GRACE`], as a time since the Unix epoch. Without an expiry that
/// fits a `Duration`, it waits as long as it takes.
fn receipt_deadline(invoice: &Bolt11Invoice) -> Duration {
	invoice
		.expires_at()
		.map_or(Duration::MAX, |expiry| expiry.saturating_add(RECEIPT_DEADLINE_GRACE))
}

/// The tokio [`Instant`](tokio::time::Instant) at `deadline`, a time since the Unix epoch. One
/// beyond what an `Instant` can hold is as good as a century away.
fn instant_at(deadline: Duration) -> tokio::time::Instant {
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
	let remaining = deadline.saturating_sub(now);
	let now = tokio::time::Instant::now();
	now.checked_add(remaining)
		.unwrap_or_else(|| now + Duration::from_secs(100 * 365 * 24 * 60 * 60))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Parameters for doing a rebalance
pub struct TriggerParams {
	/// ID for the rebalance operation, useful for tracking
	/// and logging purposes.
	pub id: [u8; 32],
	/// The amount to transfer in millisatoshis
	pub amount: Amount,
}

/// Create separate triggers for trusted -> LN and onchain -> LN on when to do a rebalance.
pub trait RebalanceTrigger: Send + Sync {
	/// If we need to do a Trusted -> LN rebalance, if the amount is None, no rebalance will be triggered.
	fn needs_trusted_rebalance(&self) -> impl Future<Output = Option<TriggerParams>> + Send;

	/// If we need to do an Onchain -> LN rebalance, if the amount is None, no rebalance will be triggered.
	fn needs_onchain_rebalance(&self) -> impl Future<Output = Option<TriggerParams>> + Send;
}

/// Configuration parameters for rebalancing decisions
#[derive(Debug, Clone, Copy)]
pub struct RebalanceTunables {
	/// The maximum balance that can be held in the trusted wallet.
	pub trusted_balance_limit: Amount,
	/// Trusted balances below this threshold will not be transferred to non-trusted balance
	/// even if we have capacity to do so without paying for a new channel.
	///
	/// This avoids unnecessary transfers and fees.
	pub rebalance_min: Amount,
	/// How long the rebalancer still waits for the Lightning receipt of a rebalance payment after
	/// the trusted wallet reported that payment failed.
	///
	/// A trusted wallet can report a failure after our node already received the payment (Breez
	/// reports a Spark send as failed when the operator gets no preimage back, which happens after
	/// our node released it), and our event handling may not have recorded the receipt yet.
	pub trusted_failure_receipt_grace: Duration,
}

impl Default for RebalanceTunables {
	fn default() -> Self {
		Self {
			trusted_balance_limit: Amount::from_sats(100_000).expect("valid amount"),
			rebalance_min: Amount::from_sats(5_000).expect("valid amount"),
			trusted_failure_receipt_grace: Duration::from_secs(60),
		}
	}
}

/// Trait representing a trusted wallet backend
pub trait TrustedWallet: Send + Sync {
	/// Error type for trusted wallet operations
	type Error: Debug + Send + Sync + 'static;

	/// Get the current balance of the trusted wallet
	fn get_balance(&self)
		-> Pin<Box<dyn Future<Output = Result<Amount, Self::Error>> + Send + '_>>;

	/// Generate a BOLT11 invoice for the specified amount
	fn get_bolt11_invoice(
		&self, amount: Option<Amount>,
	) -> Pin<Box<dyn Future<Output = Result<Bolt11Invoice, Self::Error>> + Send + '_>>;

	/// Make a payment using the trusted wallet
	fn pay(
		&self, method: PaymentMethod, amount: Amount,
	) -> Pin<Box<dyn Future<Output = Result<[u8; 32], Self::Error>> + Send + '_>>;

	/// Estimate the fee for making a payment using the trusted wallet
	fn estimate_fee(
		&self, method: PaymentMethod, amount: Amount,
	) -> Pin<Box<dyn Future<Output = Result<Amount, Self::Error>> + Send + '_>>;

	/// Wait for a payment success notification
	fn await_payment_success(
		&self, payment_hash: [u8; 32],
	) -> Pin<Box<dyn Future<Output = Option<ReceivedLightningPayment>> + Send + '_>>;

	/// Resolves once the payment to `payment_hash` is known to have failed, and never if it is
	/// not.
	///
	/// The rebalancer races this against the Lightning wallet's receipt of the payment, which
	/// never comes for a payment that failed before reaching it, so it must resolve only on a
	/// definite failure: never on an unknown status, a failed lookup, or an error from a send call
	/// the wallet may still resume. The default never resolves, leaving the receipt's deadline to
	/// end the wait.
	fn await_payment_failure(
		&self, _payment_hash: [u8; 32],
	) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
		Box::pin(std::future::pending())
	}
}

/// Trait representing a lightning wallet backend
pub trait LightningWallet: Send + Sync {
	/// Error type for lightning wallet operations
	type Error: Debug + Send + Sync + 'static;

	/// Get the current balance of the lightning wallet
	fn get_balance(&self) -> LightningBalance;

	/// Generate a BOLT11 invoice for the specified amount
	fn get_bolt11_invoice(
		&self, amount: Option<Amount>,
	) -> Pin<Box<dyn Future<Output = Result<Bolt11Invoice, Self::Error>> + Send + '_>>;

	/// Make a payment using the lightning wallet
	fn pay(
		&self, method: PaymentMethod, amount: Amount,
	) -> Pin<Box<dyn Future<Output = Result<[u8; 32], Self::Error>> + Send + '_>>;

	/// Wait for a payment receipt notification
	///
	/// Stops waiting at `deadline`, a time since the Unix epoch, and returns `None` if the payment
	/// has not been received by then. The rebalancer passes the expiry of the invoice it paid plus
	/// [`RECEIPT_DEADLINE_GRACE`]: a payment that has not arrived by then never will, and the
	/// implementation may not learn of a refused payment any other way.
	fn await_payment_receipt(
		&self, payment_hash: [u8; 32], deadline: Duration,
	) -> Pin<Box<dyn Future<Output = Option<ReceivedLightningPayment>> + Send + '_>>;

	/// Check if we already have a channel with the LSP
	fn has_channel_with_lsp(&self) -> bool;

	/// Open a channel with the LSP using all available on-chain funds
	/// (minus fees and anchor reserves).
	fn open_channel_with_lsp(
		&self,
	) -> Pin<Box<dyn Future<Output = Result<u128, Self::Error>> + Send + '_>>;

	/// Wait for a channel pending notification, returns the new channel's outpoint
	fn await_channel_pending(
		&self, channel_id: u128,
	) -> Pin<Box<dyn Future<Output = OutPoint> + Send + '_>>;

	/// Splice all available on-chain funds (minus fees and anchor reserves) into
	/// an existing channel with the LSP.
	fn splice_to_lsp_channel(
		&self,
	) -> Pin<Box<dyn Future<Output = Result<u128, Self::Error>> + Send + '_>>;

	/// Wait for a splice pending notification, returns the splice outpoint
	fn await_splice_pending(
		&self, channel_id: u128,
	) -> Pin<Box<dyn Future<Output = OutPoint> + Send + '_>>;
}

/// Represents a payment from the lightning wallet
#[derive(Debug, Clone)]
pub struct ReceivedLightningPayment {
	/// Unique payment ID
	pub id: [u8; 32],
	/// Fee paid in millisatoshis
	pub fee_paid_msat: Option<u64>,
}

/// Lightning wallet balance information
#[derive(Debug, Clone, Copy)]
pub struct LightningBalance {
	/// Available lightning balance
	pub lightning: Amount,
	/// Available on-chain balance
	pub onchain: Amount,
}

/// Events that can be emitted by the rebalancer
#[derive(Debug, Clone)]
pub enum RebalancerEvent {
	/// Rebalance was initiated
	RebalanceInitiated {
		/// Optional trigger id given by the rebalance trigger
		trigger_id: [u8; 32],
		/// Trusted wallet payment ID for the rebalance
		trusted_rebalance_payment_id: [u8; 32],
		/// Amount being rebalanced in millisatoshis
		amount_msat: u64,
	},
	/// Rebalance completed successfully
	RebalanceSuccessful {
		/// Trigger id given by the rebalance trigger
		trigger_id: [u8; 32],
		/// Trusted wallet payment ID for the rebalance
		trusted_rebalance_payment_id: [u8; 32],
		/// Lightning payment ID for the rebalance
		ln_rebalance_payment_id: [u8; 32],
		/// Amount rebalanced in millisatoshis
		amount_msat: u64,
		/// Total fee paid in millisatoshis
		fee_msat: u64,
	},
	/// We have initiated a lightning channel open
	OnChainRebalanceInitiated {
		/// Trigger id given by the rebalance trigger
		trigger_id: [u8; 32],
		/// User channel id set by the LN wallet
		user_channel_id: u128,
		/// New channel Outpoint
		channel_outpoint: OutPoint,
	},
}

/// Trait for handling rebalancer events
pub trait EventHandler: Send + Sync {
	/// Handle a rebalancer event
	fn handle_event(&self, event: RebalancerEvent)
		-> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// A no-op event handler that discards all events
#[derive(Debug, Copy, Clone, Default)]
pub struct IgnoringEventHandler;

impl EventHandler for IgnoringEventHandler {
	fn handle_event(
		&self, _event: RebalancerEvent,
	) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
		Box::pin(async move {})
		// Do nothing
	}
}

/// The main graduated rebalancer that manages balance between trusted and lightning wallets
pub struct GraduatedRebalancer<
	T: TrustedWallet,
	L: LightningWallet,
	R: RebalanceTrigger,
	E: EventHandler,
	O: Logger,
> {
	trusted: Arc<T>,
	ln_wallet: Arc<L>,
	trigger: Arc<R>,
	event_handler: Arc<E>,
	logger: Arc<O>,

	/// [`RebalanceTunables::trusted_failure_receipt_grace`], in milliseconds.
	trusted_failure_receipt_grace_ms: AtomicU64,

	/// Mutex to ensure thread-safe balance operations.
	balance_mutex: tokio::sync::Mutex<()>,
}

impl<T, LN, R, E, L> GraduatedRebalancer<T, LN, R, E, L>
where
	T: TrustedWallet,
	LN: LightningWallet,
	R: RebalanceTrigger,
	E: EventHandler,
	L: Logger,
{
	/// Create a new graduated rebalancer
	///
	/// Of `tunables` the rebalancer itself uses only
	/// [`RebalanceTunables::trusted_failure_receipt_grace`]; the balance thresholds are the
	/// trigger's to apply.
	pub fn new(
		trusted: Arc<T>, ln_wallet: Arc<LN>, trigger: Arc<R>, event_handler: Arc<E>,
		logger: Arc<L>, tunables: RebalanceTunables,
	) -> Self {
		Self {
			trusted,
			ln_wallet,
			trigger,
			event_handler,
			logger,
			trusted_failure_receipt_grace_ms: AtomicU64::new(duration_to_millis(
				tunables.trusted_failure_receipt_grace,
			)),
			balance_mutex: tokio::sync::Mutex::new(()),
		}
	}

	/// Changes [`RebalanceTunables::trusted_failure_receipt_grace`]. The grace is read when a
	/// trusted failure is reported, so this also applies to a rebalance already waiting for its
	/// receipt.
	pub fn set_trusted_failure_receipt_grace(&self, grace: Duration) {
		self.trusted_failure_receipt_grace_ms.store(duration_to_millis(grace), Ordering::Relaxed);
	}

	/// Does any rebalance if it meets the conditions of the tunables
	pub async fn do_rebalance_if_needed(&self) {
		self.do_trusted_rebalance_if_needed().await;

		self.do_onchain_rebalance_if_needed().await;
	}

	/// Does a trusted to lightning rebalance if needed
	pub async fn do_trusted_rebalance_if_needed(&self) {
		let _lock = self.balance_mutex.lock().await;
		if let Some(params) = self.trigger.needs_trusted_rebalance().await {
			self.do_trusted_rebalance_locked(params).await;
		}
	}

	/// Does an on-chain to lightning rebalance if needed
	pub async fn do_onchain_rebalance_if_needed(&self) {
		let _lock = self.balance_mutex.lock().await;
		if let Some(params) = self.trigger.needs_onchain_rebalance().await {
			self.do_onchain_rebalance_locked(params).await;
		}
	}

	/// Perform a rebalance from trusted to lightning wallet
	async fn do_trusted_rebalance_locked(&self, params: TriggerParams) {
		let mut transfer_amt = params.amount;
		log_info!(self.logger, "Initiating rebalance");

		if let Ok(mut inv) = self.ln_wallet.get_bolt11_invoice(Some(transfer_amt)).await {
			if let Ok(fee) = self
				.trusted
				.estimate_fee(PaymentMethod::LightningBolt11(inv.clone()), transfer_amt)
				.await
			{
				if fee >= transfer_amt {
					log_error!(
						self.logger,
						"Rebalance trusted transaction fee {fee:?} exceeds amount {transfer_amt:?}",
					);
					return;
				}

				if transfer_amt.saturating_add(fee) > params.amount {
					transfer_amt = params.amount.saturating_sub(fee);
					match self.ln_wallet.get_bolt11_invoice(Some(transfer_amt)).await {
						Ok(reduced_inv) => inv = reduced_inv,
						Err(e) => {
							log_error!(
								self.logger,
								"Failed to create fee-adjusted rebalance invoice: {e:?}",
							);
							return;
						},
					}
				}
			}

			log_debug!(
				self.logger,
				"Attempting to pay invoice {inv} to rebalance for {transfer_amt:?}",
			);
			let expected_hash = inv.payment_hash();
			let receipt_deadline = receipt_deadline(&inv);
			let deadline = instant_at(receipt_deadline);
			match self.trusted.pay(PaymentMethod::LightningBolt11(inv), transfer_amt).await {
				Ok(rebalance_id) => {
					log_debug!(
						self.logger,
						"Rebalance trusted transaction initiated, id {}. Waiting for LN payment.",
						rebalance_id.as_hex()
					);

					self.event_handler
						.handle_event(RebalancerEvent::RebalanceInitiated {
							trigger_id: params.id,
							trusted_rebalance_payment_id: rebalance_id,
							amount_msat: transfer_amt.milli_sats(),
						})
						.await;

					// Wait for the Lightning receipt, but stop as soon as the trusted wallet
					// reports the payment failed: then no receipt is coming, and waiting until
					// the receipt's deadline would hold `balance_mutex`, blocking every other
					// rebalance, for as long as the invoice is valid.
					let mut receipt =
						self.ln_wallet.await_payment_receipt(expected_hash.0, receipt_deadline);
					let trusted_failure = self.trusted.await_payment_failure(expected_hash.0);
					// When to stop waiting for the trusted side's verdict once the receipt is in
					// hand, if the trusted side already reported a failure: the end of the grace.
					let mut verdict_deadline = None;
					let receipt = tokio::select! {
						biased;
						receipt = &mut receipt => receipt,
						() = trusted_failure => {
							// The failure may have been reported after our node received the
							// payment, before the receipt was recorded: allow the receipt a grace.
							let grace = Duration::from_millis(
								self.trusted_failure_receipt_grace_ms.load(Ordering::Relaxed),
							);
							log_warn!(
								self.logger,
								"Rebalance payment failed on the trusted side; waiting up to {grace:?} for a Lightning receipt in case it was received anyway"
							);
							let grace_end = tokio::time::Instant::now() + grace;
							verdict_deadline = Some(grace_end.min(deadline));
							match tokio::time::timeout_at(grace_end, &mut receipt).await {
								Ok(Some(receipt)) => {
									log_warn!(
										self.logger,
										"Rebalance payment was received although the trusted side reported it failed"
									);
									Some(receipt)
								},
								Ok(None) | Err(_) => {
									log_error!(
										self.logger,
										"Rebalance payment failed on the trusted side; no Lightning receipt expected"
									);
									return;
								},
							}
						},
					};
					let ln_payment = match receipt {
						Some(receipt) => receipt,
						None => {
							log_error!(self.logger, "Failed to receive rebalance payment!");
							return;
						},
					};

					// The receipt is in hand: our node was paid, so we record the rebalance, and the
					// trusted side's verdict only supplies its fee. That verdict can be wrong or
					// never come: Breez can list a Spark send as failed after our node released
					// the preimage (and never turns a failed payment into a completed one), and a
					// Cashu wallet waits for an outgoing transaction that a failed melt never
					// creates. Where a reported failure is accurate (Breez returned the leaves to
					// us), history then shows a transfer without a trusted debit; the next listing
					// of the trusted balance still gets balances right. That beats waiting on the
					// verdict for good, as before. So the wait is bounded, by the rest of the grace
					// once a failure was reported and by `TRUSTED_VERDICT_WAIT` otherwise (never
					// past the receipt's deadline), and without a verdict the rebalance is
					// recorded with the trusted fee unknown.
					let verdict_deadline = verdict_deadline.unwrap_or_else(|| {
						(tokio::time::Instant::now() + TRUSTED_VERDICT_WAIT).min(deadline)
					});
					let trusted_fee_msat = match tokio::time::timeout_at(
						verdict_deadline,
						self.trusted.await_payment_success(expected_hash.0),
					)
					.await
					{
						Ok(Some(success)) => success.fee_paid_msat,
						Ok(None) => {
							log_warn!(
								self.logger,
								"Rebalance payment was received by our node, but the trusted side reports it failed or unknown; recording the rebalance with the trusted fee unknown"
							);
							None
						},
						Err(_) => {
							log_warn!(
								self.logger,
								"Rebalance payment was received by our node, but the trusted side reported no outcome in time; recording the rebalance with the trusted fee unknown"
							);
							None
						},
					};

					log_info!(
						self.logger,
						"Rebalance succeeded. Sent trusted tx {} to lightning tx {}",
						rebalance_id.as_hex(),
						ln_payment.id.as_hex(),
					);

					self.event_handler
						.handle_event(RebalancerEvent::RebalanceSuccessful {
							trigger_id: params.id,
							trusted_rebalance_payment_id: rebalance_id,
							ln_rebalance_payment_id: ln_payment.id,
							amount_msat: transfer_amt.milli_sats(),
							fee_msat: ln_payment.fee_paid_msat.unwrap_or_default()
								+ trusted_fee_msat.unwrap_or_default(),
						})
						.await;
				},
				Err(e) => {
					log_info!(self.logger, "Rebalance trusted transaction failed with {e:?}",);
				},
			}
		}
	}

	/// Perform on-chain to lightning rebalance by opening a channel or splicing into an existing one
	async fn do_onchain_rebalance_locked(&self, params: TriggerParams) {
		let (channel_outpoint, user_channel_id) = if self.ln_wallet.has_channel_with_lsp() {
			log_info!(self.logger, "Splicing into channel with LSP with on-chain funds");

			let user_chan_id = match self.ln_wallet.splice_to_lsp_channel().await {
				Ok(chan_id) => chan_id,
				Err(e) => {
					log_error!(self.logger, "Failed to open channel with LSP: {e:?}");
					return;
				},
			};

			log_info!(self.logger, "Initiated splice opened with LSP");

			let channel_outpoint = self.ln_wallet.await_splice_pending(user_chan_id).await;

			log_info!(self.logger, "Splice initiated at: {channel_outpoint}");

			(channel_outpoint, user_chan_id)
		} else {
			log_info!(self.logger, "Opening channel with LSP with on-chain funds");

			let user_chan_id = match self.ln_wallet.open_channel_with_lsp().await {
				Ok(chan_id) => chan_id,
				Err(e) => {
					log_error!(self.logger, "Failed to open channel with LSP: {e:?}");
					return;
				},
			};

			log_info!(self.logger, "Initiated channel opened with LSP");

			let channel_outpoint = self.ln_wallet.await_channel_pending(user_chan_id).await;

			log_info!(self.logger, "Channel open succeeded at: {channel_outpoint}");

			(channel_outpoint, user_chan_id)
		};

		self.event_handler
			.handle_event(RebalancerEvent::OnChainRebalanceInitiated {
				trigger_id: params.id,
				user_channel_id,
				channel_outpoint,
			})
			.await;
	}

	/// Stops the rebalancer, waits for any active rebalances to complete
	pub async fn stop(&self) {
		log_debug!(self.logger, "Waiting for balance mutex...");
		let _ = self.balance_mutex.lock().await;
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use lightning::bitcoin::hashes::{sha256, Hash};
	use lightning::bitcoin::secp256k1::{Secp256k1, SecretKey};
	use lightning::types::payment::{PaymentHash, PaymentSecret};
	use lightning_invoice::{Currency, InvoiceBuilder};

	fn invoice_at(timestamp: Duration, expiry: Duration) -> Bolt11Invoice {
		let secp = Secp256k1::new();
		let key = SecretKey::from_slice(&[42; 32]).unwrap();
		InvoiceBuilder::new(Currency::Regtest)
			.description(String::new())
			.amount_milli_satoshis(1_000_000)
			.payment_hash(PaymentHash(sha256::Hash::hash(&[1; 32]).to_byte_array()))
			.payment_secret(PaymentSecret([0; 32]))
			.duration_since_epoch(timestamp)
			.expiry_time(expiry)
			.min_final_cltv_expiry_delta(144)
			.build_signed(|msg| secp.sign_ecdsa_recoverable(msg, &key))
			.unwrap()
	}

	fn invoice(expiry: Duration) -> Bolt11Invoice {
		invoice_at(Duration::from_secs(1_700_000_000), expiry)
	}

	fn invoice_from_now(expiry: Duration) -> Bolt11Invoice {
		invoice_at(SystemTime::now().duration_since(UNIX_EPOCH).unwrap(), expiry)
	}

	struct NoLogger;
	impl Logger for NoLogger {
		fn log(&self, _record: lightning::util::logger::Record) {}
	}

	/// What a mock trusted wallet's `await_payment_success` says about the rebalance payment.
	#[derive(Clone, Copy)]
	enum Verdict {
		/// It succeeded, with a 500 msat fee.
		Succeeded,
		/// It failed (as Spark lists a send whose operator got no preimage back).
		Failed,
		/// Nothing, ever (as Cashu waiting for the transaction of a melt that failed).
		Never,
	}

	/// A trusted wallet whose rebalance payment reports failure after `fail_after`, if set, and
	/// whose `await_payment_success` gives `verdict`.
	struct MockTrusted {
		fail_after: Option<Duration>,
		verdict: Verdict,
	}

	impl TrustedWallet for MockTrusted {
		type Error = ();
		fn get_balance(&self) -> Pin<Box<dyn Future<Output = Result<Amount, ()>> + Send + '_>> {
			Box::pin(async { Ok(Amount::from_sats(200_000).unwrap()) })
		}
		fn get_bolt11_invoice(
			&self, _amount: Option<Amount>,
		) -> Pin<Box<dyn Future<Output = Result<Bolt11Invoice, ()>> + Send + '_>> {
			unimplemented!()
		}
		fn pay(
			&self, _method: PaymentMethod, _amount: Amount,
		) -> Pin<Box<dyn Future<Output = Result<[u8; 32], ()>> + Send + '_>> {
			Box::pin(async { Ok([1; 32]) })
		}
		fn estimate_fee(
			&self, _method: PaymentMethod, _amount: Amount,
		) -> Pin<Box<dyn Future<Output = Result<Amount, ()>> + Send + '_>> {
			Box::pin(async { Ok(Amount::ZERO) })
		}
		fn await_payment_success(
			&self, _payment_hash: [u8; 32],
		) -> Pin<Box<dyn Future<Output = Option<ReceivedLightningPayment>> + Send + '_>> {
			let verdict = self.verdict;
			Box::pin(async move {
				match verdict {
					Verdict::Succeeded => {
						Some(ReceivedLightningPayment { id: [1; 32], fee_paid_msat: Some(500) })
					},
					Verdict::Failed => None,
					Verdict::Never => std::future::pending().await,
				}
			})
		}
		fn await_payment_failure(
			&self, _payment_hash: [u8; 32],
		) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
			let fail_after = self.fail_after;
			Box::pin(async move {
				match fail_after {
					Some(after) => tokio::time::sleep(after).await,
					None => std::future::pending().await,
				}
			})
		}
	}

	/// A Lightning wallet whose rebalance payment is received after `receipt_after`, if set.
	struct MockLightning {
		receipt_after: Option<Duration>,
	}

	impl LightningWallet for MockLightning {
		type Error = ();
		fn get_balance(&self) -> LightningBalance {
			unimplemented!()
		}
		fn get_bolt11_invoice(
			&self, _amount: Option<Amount>,
		) -> Pin<Box<dyn Future<Output = Result<Bolt11Invoice, ()>> + Send + '_>> {
			Box::pin(async { Ok(invoice_from_now(INVOICE_EXPIRY)) })
		}
		fn pay(
			&self, _method: PaymentMethod, _amount: Amount,
		) -> Pin<Box<dyn Future<Output = Result<[u8; 32], ()>> + Send + '_>> {
			unimplemented!()
		}
		fn await_payment_receipt(
			&self, _payment_hash: [u8; 32], _deadline: Duration,
		) -> Pin<Box<dyn Future<Output = Option<ReceivedLightningPayment>> + Send + '_>> {
			let receipt_after = self.receipt_after;
			Box::pin(async move {
				match receipt_after {
					Some(after) => {
						tokio::time::sleep(after).await;
						Some(ReceivedLightningPayment { id: [2; 32], fee_paid_msat: Some(1_000) })
					},
					None => std::future::pending().await,
				}
			})
		}
		fn has_channel_with_lsp(&self) -> bool {
			unimplemented!()
		}
		fn open_channel_with_lsp(
			&self,
		) -> Pin<Box<dyn Future<Output = Result<u128, ()>> + Send + '_>> {
			unimplemented!()
		}
		fn await_channel_pending(
			&self, _channel_id: u128,
		) -> Pin<Box<dyn Future<Output = OutPoint> + Send + '_>> {
			unimplemented!()
		}
		fn splice_to_lsp_channel(
			&self,
		) -> Pin<Box<dyn Future<Output = Result<u128, ()>> + Send + '_>> {
			unimplemented!()
		}
		fn await_splice_pending(
			&self, _channel_id: u128,
		) -> Pin<Box<dyn Future<Output = OutPoint> + Send + '_>> {
			unimplemented!()
		}
	}

	struct AlwaysTrusted;
	impl RebalanceTrigger for AlwaysTrusted {
		async fn needs_trusted_rebalance(&self) -> Option<TriggerParams> {
			Some(TriggerParams { id: [3; 32], amount: Amount::from_sats(150_000).unwrap() })
		}
		async fn needs_onchain_rebalance(&self) -> Option<TriggerParams> {
			None
		}
	}

	#[derive(Default)]
	struct Events(std::sync::Mutex<Vec<RebalancerEvent>>);
	impl EventHandler for Events {
		fn handle_event(
			&self, event: RebalancerEvent,
		) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
			self.0.lock().unwrap().push(event);
			Box::pin(async {})
		}
	}

	/// The expiry of the mock Lightning wallet's invoices, which are dated now.
	const INVOICE_EXPIRY: Duration = Duration::from_secs(24 * 60 * 60);

	/// Runs one trusted rebalance; returns how long it took and, if it was recorded as
	/// successful, the total fee it was recorded with.
	async fn rebalance(
		fail_after: Option<Duration>, receipt_after: Option<Duration>, verdict: Verdict,
	) -> (Duration, Option<u64>) {
		let events = Arc::new(Events::default());
		let rebalancer = GraduatedRebalancer::new(
			Arc::new(MockTrusted { fail_after, verdict }),
			Arc::new(MockLightning { receipt_after }),
			Arc::new(AlwaysTrusted),
			Arc::clone(&events),
			Arc::new(NoLogger),
			RebalanceTunables::default(),
		);
		let start = tokio::time::Instant::now();
		rebalancer.do_trusted_rebalance_if_needed().await;
		let events = events.0.lock().unwrap();
		assert!(matches!(events.first(), Some(RebalancerEvent::RebalanceInitiated { .. })));
		let fee = match events.get(1) {
			Some(RebalancerEvent::RebalanceSuccessful {
				trusted_rebalance_payment_id,
				ln_rebalance_payment_id,
				fee_msat,
				..
			}) => {
				assert_eq!(*trusted_rebalance_payment_id, [1; 32]);
				assert_eq!(*ln_rebalance_payment_id, [2; 32]);
				Some(*fee_msat)
			},
			None => None,
			Some(e) => panic!("unexpected {e:?}"),
		};
		assert_eq!(events.len(), if fee.is_some() { 2 } else { 1 });
		(start.elapsed(), fee)
	}

	/// The receipt deadline for an invoice dated now: its expiry plus `RECEIPT_DEADLINE_GRACE`,
	/// less the sub-second part of now that the invoice timestamp drops.
	fn assert_ended_at_the_deadline(elapsed: Duration) {
		let deadline = INVOICE_EXPIRY + RECEIPT_DEADLINE_GRACE;
		assert!(
			elapsed <= deadline && elapsed > deadline - Duration::from_secs(2),
			"ended after {elapsed:?}, deadline {deadline:?}"
		);
	}

	/// A trusted failure with no receipt ends the rebalance once the grace is over.
	#[tokio::test(start_paused = true)]
	async fn trusted_failure_ends_the_rebalance_after_the_grace() {
		let secs = Duration::from_secs;
		assert_eq!(rebalance(Some(secs(1)), None, Verdict::Failed).await, (secs(61), None));
	}

	/// A receipt within the grace after a trusted failure completes the rebalance: it is
	/// recorded, with the trusted fee unknown when the trusted side keeps saying the payment
	/// failed (Spark: Breez never turns a failed send into a completed one), rather than shown as
	/// fresh income. Past the grace it is too late.
	#[tokio::test(start_paused = true)]
	async fn a_receipt_within_the_grace_after_a_trusted_failure_completes_the_rebalance() {
		let secs = Duration::from_secs;
		let (failure, receipt) = (Some(secs(1)), Some(secs(30)));
		assert_eq!(rebalance(failure, receipt, Verdict::Failed).await, (secs(30), Some(1_000)));
		assert_eq!(rebalance(failure, receipt, Verdict::Succeeded).await, (secs(30), Some(1_500)));
		assert_eq!(rebalance(failure, Some(secs(62)), Verdict::Failed).await, (secs(61), None));
	}

	/// Cashu: the failed-melt signal fires at 1 s, the receipt lands within the grace, and the
	/// trusted side never reports an outcome (it waits for a transaction the failed melt never
	/// created). The rebalance is recorded, with the trusted fee unknown, once the grace is over,
	/// not at the receipt deadline 26 h on.
	#[tokio::test(start_paused = true)]
	async fn a_receipt_after_a_failed_melt_is_recorded_once_the_grace_is_over() {
		let secs = Duration::from_secs;
		assert_eq!(
			rebalance(Some(secs(1)), Some(secs(30)), Verdict::Never).await,
			(secs(61), Some(1_000))
		);
		// The same with the receipt in the grace's last second.
		assert_eq!(
			rebalance(Some(secs(1)), Some(secs(60)), Verdict::Never).await,
			(secs(61), Some(1_000))
		);
	}

	/// Without a trusted failure the receipt completes the rebalance, however long it takes, and
	/// a trusted side that reports failure or nothing afterwards does not undo it. Its verdict,
	/// which only supplies the trusted fee, is waited for at most 10 minutes.
	#[tokio::test(start_paused = true)]
	async fn a_receipt_without_a_trusted_failure_completes_the_rebalance() {
		let secs = Duration::from_secs;
		let receipt = Some(secs(600));
		assert_eq!(rebalance(None, receipt, Verdict::Succeeded).await, (secs(600), Some(1_500)));
		assert_eq!(rebalance(None, receipt, Verdict::Failed).await, (secs(600), Some(1_000)));
		assert_eq!(rebalance(None, receipt, Verdict::Never).await, (secs(1_200), Some(1_000)));
		// Nor past the receipt deadline, for a receipt that lands a minute before it.
		let late_receipt = INVOICE_EXPIRY + RECEIPT_DEADLINE_GRACE - secs(60);
		let (elapsed, fee) = rebalance(None, Some(late_receipt), Verdict::Never).await;
		assert_eq!(fee, Some(1_000));
		assert_ended_at_the_deadline(elapsed);
	}

	/// The wait for a rebalance payment ends two hours after its invoice expires, when LDK stops
	/// accepting payments to it: 26 h after a 24 h rebalance invoice is created.
	#[test]
	fn receipt_deadline_is_the_invoice_expiry_plus_ldks_acceptance_window() {
		let one_day = invoice(Duration::from_secs(86_400));
		assert_eq!(receipt_deadline(&one_day), Duration::from_secs(1_700_000_000 + 86_400 + 7_200));
	}
}
