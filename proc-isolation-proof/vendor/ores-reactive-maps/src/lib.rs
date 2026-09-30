use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

pub const DEFAULT_PUBLIC_PREFIX: &str = "ORES_PUBLIC_";

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawEntry {
    value: String,
}

#[derive(Debug, Clone)]
struct Layer {
    priority: i64,
    order: u64,
    entries: BTreeMap<String, RawEntry>,
}

struct State {
    layers: BTreeMap<String, Layer>,
    public_prefix: String,
    next_layer_order: u64,
}

impl State {
    fn new(public_prefix: impl Into<String>) -> Self {
        Self {
            layers: BTreeMap::new(),
            public_prefix: public_prefix.into(),
            next_layer_order: 0,
        }
    }

    fn resolve(&self, key: &str) -> Option<String> {
        let mut winner: Option<(&Layer, &RawEntry)> = None;
        for layer in self.layers.values() {
            let Some(candidate) = layer.entries.get(key) else {
                continue;
            };
            let replace = match winner {
                None => true,
                Some((current, _)) => {
                    layer.priority > current.priority
                        || (layer.priority == current.priority && layer.order > current.order)
                }
            };
            if replace {
                winner = Some((layer, candidate));
            }
        }
        winner.map(|(_, raw)| raw.value.clone())
    }
}

#[derive(Clone)]
pub struct ReactiveMap {
    state: Arc<Mutex<State>>,
}

impl Default for ReactiveMap {
    fn default() -> Self {
        Self::new()
    }
}

impl ReactiveMap {
    #[must_use]
    pub fn new() -> Self {
        Self::with_public_prefix(DEFAULT_PUBLIC_PREFIX)
    }

    #[must_use]
    pub fn with_public_prefix(prefix: impl Into<String>) -> Self {
        Self {
            state: Arc::new(Mutex::new(State::new(prefix))),
        }
    }

    #[must_use]
    pub fn public_prefix(&self) -> String {
        self.lock().public_prefix.clone()
    }

    #[must_use]
    pub fn get_val(&self, key: &str) -> Option<String> {
        self.lock().resolve(key)
    }

    pub fn replace_string_layer(
        &self,
        name: impl Into<String>,
        _source: impl Into<String>,
        priority: i64,
        values: BTreeMap<String, String>,
    ) {
        let name = name.into();
        let mut state = self.lock();
        let order = match state.layers.get(&name) {
            Some(layer) => layer.order,
            None => {
                let order = state.next_layer_order;
                state.next_layer_order += 1;
                order
            }
        };
        let entries = values
            .into_iter()
            .map(|(key, value)| (key, RawEntry { value }))
            .collect();
        state.layers.insert(
            name,
            Layer {
                priority,
                order,
                entries,
            },
        );
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
