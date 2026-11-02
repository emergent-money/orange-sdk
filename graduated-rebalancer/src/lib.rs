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
use lightning::{log_debug, log_error, log_info};
use lightning_invoice::Bolt11Invoice;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

/// How long after the expiry of a rebalance invoice the rebalancer still waits for the payment to
/// it to be received.
///
/// LDK accepts a payment to one of its invoices until two hours after the invoice's expiry, as a
/// buffer against block timestamps running ahead of real time (rust-lightning
/// `inbound_payment.rs:271-280`, `calculate_absolute_expiry`), so the wait covers that window:
/// no payment it could still accept arrives after the wait has ended.
pub const RECEIPT_DEADLINE_GRACE: Duration = Duration::from_secs(7_200);

/// When the rebalancer stops waiting for the payment to `invoice` to be received: the invoice's
/// expiry plus [`RECEIPT_DEADLINE_GRACE`], as a time since the Unix epoch. Without an expiry that
/// fits a `Duration`, it waits as long as it takes.
fn receipt_deadline(invoice: &Bolt11Invoice) -> Duration {
	invoice
		.expires_at()
		.map_or(Duration::MAX, |expiry| expiry.saturating_add(RECEIPT_DEADLINE_GRACE))
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
}

impl Default for RebalanceTunables {
	fn default() -> Self {
		Self {
			trusted_balance_limit: Amount::from_sats(100_000).expect("valid amount"),
			rebalance_min: Amount::from_sats(5_000).expect("valid amount"),
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
	/// definite failure: never on an unknown status or a failed lookup. The default never
	/// resolves, leaving the receipt's deadline to end the wait.
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
	pub fn new(
		trusted: Arc<T>, ln_wallet: Arc<LN>, trigger: Arc<R>, event_handler: Arc<E>, logger: Arc<L>,
	) -> Self {
		Self {
			trusted,
			ln_wallet,
			trigger,
			event_handler,
			logger,
			balance_mutex: tokio::sync::Mutex::new(()),
		}
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
					let receipt =
						self.ln_wallet.await_payment_receipt(expected_hash.0, receipt_deadline);
					let trusted_failure = self.trusted.await_payment_failure(expected_hash.0);
					let ln_payment = tokio::select! {
						biased;
						receipt = receipt => match receipt {
							Some(receipt) => receipt,
							None => {
								log_error!(self.logger, "Failed to receive rebalance payment!");
								return;
							},
						},
						() = trusted_failure => {
							log_error!(
								self.logger,
								"Rebalance payment failed on the trusted side; no Lightning receipt expected"
							);
							return;
						},
					};

					let trusted_payment =
						match self.trusted.await_payment_success(expected_hash.0).await {
							Some(success) => success,
							None => {
								log_error!(self.logger, "Failed to send rebalance payment!");
								return;
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
								+ trusted_payment.fee_paid_msat.unwrap_or_default(),
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

	pub(crate) fn invoice(expiry: Duration) -> Bolt11Invoice {
		let secp = Secp256k1::new();
		let key = SecretKey::from_slice(&[42; 32]).unwrap();
		InvoiceBuilder::new(Currency::Regtest)
			.description(String::new())
			.amount_milli_satoshis(1_000_000)
			.payment_hash(PaymentHash(sha256::Hash::hash(&[1; 32]).to_byte_array()))
			.payment_secret(PaymentSecret([0; 32]))
			.duration_since_epoch(Duration::from_secs(1_700_000_000))
			.expiry_time(expiry)
			.min_final_cltv_expiry_delta(144)
			.build_signed(|msg| secp.sign_ecdsa_recoverable(msg, &key))
			.unwrap()
	}

	/// The wait for a rebalance payment ends two hours after its invoice expires, when LDK stops
	/// accepting payments to it.
	#[test]
	fn receipt_deadline_is_the_invoice_expiry_plus_ldks_acceptance_window() {
		let one_hour = invoice(Duration::from_secs(3_600));
		assert_eq!(receipt_deadline(&one_hour), Duration::from_secs(1_700_000_000 + 3_600 + 7_200));
	}
}
