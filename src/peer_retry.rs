//! Elapsed-time reconnection deadlines, independent of the polling interval.
use std::time::{Duration, Instant};

const MIN_RETRY: Duration = Duration::from_secs(30);
const MAX_RETRY: Duration = Duration::from_secs(240);

pub(crate) struct PeerRetry {
	delay: Duration,
	next_attempt: Instant,
}

impl PeerRetry {
	pub(crate) fn ready(&self, now: Instant) -> bool {
		now >= self.next_attempt
	}
	pub(crate) fn after_failure(previous: Option<&Self>, now: Instant) -> Self {
		let delay = previous.map_or(MIN_RETRY, |p| (p.delay * 2).min(MAX_RETRY));
		Self { delay, next_attempt: now + delay }
	}
	pub(crate) fn delay_seconds(&self) -> u64 {
		self.delay.as_secs()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn retries_are_deadline_based_and_bounded() {
		let now = Instant::now();
		let mut retry = PeerRetry::after_failure(None, now);
		for expected in [30, 60, 120, 240, 240, 240] {
			assert_eq!(retry.delay_seconds(), expected);
			assert!(!retry.ready(now + Duration::from_secs(expected - 1)));
			assert!(retry.ready(now + Duration::from_secs(expected)));
			retry = PeerRetry::after_failure(Some(&retry), now);
		}
		// A successful connection removes the state; a later outage starts promptly again.
		assert_eq!(PeerRetry::after_failure(None, now).delay_seconds(), 30);
	}
}
