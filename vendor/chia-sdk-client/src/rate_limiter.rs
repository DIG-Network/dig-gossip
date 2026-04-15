use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use chia_protocol::{Message, ProtocolMessageTypes};

use crate::RateLimits;

#[derive(Debug, Clone)]
pub struct RateLimiter {
    incoming: bool,
    reset_seconds: u64,
    period: u64,
    message_counts: HashMap<ProtocolMessageTypes, f64>,
    message_cumulative_sizes: HashMap<ProtocolMessageTypes, f64>,
    dig_message_counts: HashMap<u8, f64>,
    dig_message_sizes: HashMap<u8, f64>,
    limit_factor: f64,
    non_tx_count: f64,
    non_tx_size: f64,
    rate_limits: RateLimits,
}

impl RateLimiter {
    pub fn new(
        incoming: bool,
        reset_seconds: u64,
        limit_factor: f64,
        rate_limits: RateLimits,
    ) -> Self {
        Self {
            incoming,
            reset_seconds,
            period: time() / reset_seconds,
            message_counts: HashMap::new(),
            message_cumulative_sizes: HashMap::new(),
            dig_message_counts: HashMap::new(),
            dig_message_sizes: HashMap::new(),
            limit_factor,
            non_tx_count: 0.0,
            non_tx_size: 0.0,
            rate_limits,
        }
    }

    fn sync_period(&mut self) {
        let period = time() / self.reset_seconds;
        if self.period != period {
            self.period = period;
            self.message_counts.clear();
            self.message_cumulative_sizes.clear();
            self.dig_message_counts.clear();
            self.dig_message_sizes.clear();
            self.non_tx_count = 0.0;
            self.non_tx_size = 0.0;
        }
    }

    /// Rate-check a DIG L2 wire discriminant (`DigMessageType as u8`, **200+**) that is not a
    /// [`ProtocolMessageTypes`] variant on the Chia enum (dig-gossip CON-005).
    ///
    /// Uses the same 60-second rolling window and [`RateLimits::dig_wire`] entries as Chia
    /// messages use for [`Self::handle_message`]. Unknown `wire_type` keys (no row in `dig_wire`)
    /// return **`true`** (fail-open) until DIG assigns a limit for that opcode.
    pub fn check_dig_extension(&mut self, wire_type: u8, data_len: u32) -> bool {
        self.sync_period();
        let size = f64::from(data_len);
        let Some(limits) = self.rate_limits.dig_wire.get(&wire_type).copied() else {
            return true;
        };

        let new_message_count = self.dig_message_counts.get(&wire_type).unwrap_or(&0.0) + 1.0;
        let new_cumulative_size = self.dig_message_sizes.get(&wire_type).unwrap_or(&0.0) + size;
        let max_total_size = limits
            .max_total_size
            .unwrap_or(limits.frequency * limits.max_size);

        let passed = new_message_count <= limits.frequency * self.limit_factor
            && size <= limits.max_size
            && new_cumulative_size <= max_total_size * self.limit_factor;

        if self.incoming || passed {
            *self.dig_message_counts.entry(wire_type).or_default() = new_message_count;
            *self.dig_message_sizes.entry(wire_type).or_default() = new_cumulative_size;
        }

        passed
    }

    pub fn handle_message(&mut self, message: &Message) -> bool {
        self.sync_period();

        let size: u32 = message.data.len().try_into().expect("Message too large");
        let size = f64::from(size);

        let new_message_count = self.message_counts.get(&message.msg_type).unwrap_or(&0.0) + 1.0;
        let new_cumulative_size = self
            .message_cumulative_sizes
            .get(&message.msg_type)
            .unwrap_or(&0.0)
            + size;
        let mut new_non_tx_count = self.non_tx_count;
        let mut new_non_tx_size = self.non_tx_size;

        let passed = 'checker: {
            let mut limits = self.rate_limits.default_settings;

            if let Some(tx_limits) = self.rate_limits.tx.get(&message.msg_type) {
                limits = *tx_limits;
            } else if let Some(other_limits) = self.rate_limits.other.get(&message.msg_type) {
                limits = *other_limits;

                new_non_tx_count += 1.0;
                new_non_tx_size += size;

                if new_non_tx_count > self.rate_limits.non_tx_frequency * self.limit_factor {
                    break 'checker false;
                }

                if new_non_tx_size > self.rate_limits.non_tx_max_total_size * self.limit_factor {
                    break 'checker false;
                }
            }

            let max_total_size = limits
                .max_total_size
                .unwrap_or(limits.frequency * limits.max_size);

            if new_message_count > limits.frequency * self.limit_factor {
                break 'checker false;
            }

            if size > limits.max_size {
                break 'checker false;
            }

            if new_cumulative_size > max_total_size * self.limit_factor {
                break 'checker false;
            }

            true
        };

        if self.incoming || passed {
            *self.message_counts.entry(message.msg_type).or_default() = new_message_count;
            *self
                .message_cumulative_sizes
                .entry(message.msg_type)
                .or_default() = new_cumulative_size;
            self.non_tx_count = new_non_tx_count;
            self.non_tx_size = new_non_tx_size;
        }

        passed
    }
}

fn time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}
