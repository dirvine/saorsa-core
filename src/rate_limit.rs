use parking_lot::RwLock;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub window: Duration,
    pub max_requests: u32,
    pub burst_size: u32,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_update: Instant,
    requests_in_window: u32,
    window_start: Instant,
}

impl Bucket {
    fn new(initial_tokens: f64) -> Self {
        let now = Instant::now();
        Self {
            tokens: initial_tokens,
            last_update: now,
            requests_in_window: 0,
            window_start: now,
        }
    }

    fn try_consume(&mut self, cfg: &EngineConfig) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) > cfg.window {
            self.window_start = now;
            self.requests_in_window = 0;
        }
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        let refill_rate = cfg.max_requests as f64 / cfg.window.as_secs_f64();
        self.tokens += elapsed * refill_rate;
        self.tokens = self.tokens.min(cfg.burst_size as f64);
        self.last_update = now;
        if self.tokens >= 1.0 && self.requests_in_window < cfg.max_requests {
            self.tokens -= 1.0;
            self.requests_in_window += 1;
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct Engine<K: Eq + Hash + Clone + ToString> {
    cfg: EngineConfig,
    global: Mutex<Bucket>,
    keyed: RwLock<HashMap<K, Bucket>>,
}

impl<K: Eq + Hash + Clone + ToString> Engine<K> {
    pub fn new(cfg: EngineConfig) -> Self {
        let burst_size = cfg.burst_size as f64;
        Self {
            cfg,
            global: Mutex::new(Bucket::new(burst_size)),
            keyed: RwLock::new(HashMap::new()),
        }
    }

    #[allow(clippy::panic)]
    pub fn try_consume_global(&self) -> bool {
        let mut g = self.global.lock().unwrap_or_else(|e| {
            // Mutex poisoning indicates a serious bug, panic is appropriate
            panic!("Global rate limit mutex poisoned: {}", e)
        });
        g.try_consume(&self.cfg)
    }

    pub fn try_consume_key(&self, key: &K) -> bool {
        let mut map = self.keyed.write();
        let bucket = map.entry(key.clone()).or_insert_with(|| Bucket::new(self.cfg.burst_size as f64));
        bucket.try_consume(&self.cfg)
    }
}

pub type SharedEngine<K> = Arc<Engine<K>>;
