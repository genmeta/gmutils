use std::time::Instant;

/// Timing checkpoints collected during a single request-response cycle.
pub(crate) struct Timing {
    start: Instant,
    connected: Option<Instant>,
    first_byte: Option<Instant>,
}

impl Timing {
    pub(crate) fn new() -> Self {
        Self {
            start: Instant::now(),
            connected: None,
            first_byte: None,
        }
    }

    pub(crate) fn mark_connected(&mut self) {
        self.connected = Some(Instant::now());
    }

    pub(crate) fn mark_first_byte(&mut self) {
        self.first_byte = Some(Instant::now());
    }

    pub(crate) fn time_connect(&self) -> f64 {
        self.connected
            .map(|t| t.duration_since(self.start).as_secs_f64())
            .unwrap_or(0.0)
    }

    pub(crate) fn time_starttransfer(&self) -> f64 {
        self.first_byte
            .map(|t| t.duration_since(self.start).as_secs_f64())
            .unwrap_or(0.0)
    }

    pub(crate) fn time_total(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }
}
