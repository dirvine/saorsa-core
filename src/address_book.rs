// Copyright 2025 Saorsa Labs Limited
//
// Dual-licensed under AGPL-3.0-or-later and a commercial license.

//! AddressBook: maps UserId <-> FourWordAddress for messaging and chat.
//!
//! - Panic-free; uses DHT for persistence when available, else in-memory fallback.
//! - Public helpers are async and safe to call from other modules/apps.

use crate::identity::four_words::FourWordAddress;
use crate::{
    Result,
    error::{IdentityError, P2PError},
    fwid,
};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserToWordsEntry {
    user_id: String,
    four_words: String,
}

#[derive(Clone)]
pub struct AddressBook {
    user_to_words: Arc<RwLock<HashMap<String, String>>>,
    words_to_user: Arc<RwLock<HashMap<String, String>>>,
}

impl Default for AddressBook {
    fn default() -> Self {
        Self {
            user_to_words: Arc::new(RwLock::new(HashMap::new())),
            words_to_user: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

static GLOBAL_BOOK: OnceCell<AddressBook> = OnceCell::new();

pub fn address_book() -> &'static AddressBook {
    GLOBAL_BOOK.get_or_init(AddressBook::default)
}

fn key_user_to_words(user_id: &str) -> String {
    let k = fwid::compute_key("abw:user", user_id.as_bytes());
    hex::encode(k.as_bytes())
}

fn key_words_to_user(words: &str) -> String {
    let k = fwid::compute_key("abw:words", words.as_bytes());
    hex::encode(k.as_bytes())
}

impl AddressBook {
    /// Register mapping (overwrites existing).
    pub async fn register(&self, user_id: String, four_words: String) -> Result<()> {
        // Validate format (4 hyphen-separated words)
        let parts: Vec<String> = four_words.split('-').map(|s| s.to_string()).collect();
        if parts.len() != 4
            || !fwid::fw_check([
                parts[0].clone(),
                parts[1].clone(),
                parts[2].clone(),
                parts[3].clone(),
            ])
        {
            return Err(P2PError::Identity(IdentityError::InvalidFourWordAddress(
                "invalid four-word address format".into(),
            )));
        }

        {
            let mut u2w = self.user_to_words.write().await;
            u2w.insert(user_id.clone(), four_words.clone());
        }
        {
            let mut w2u = self.words_to_user.write().await;
            w2u.insert(four_words.clone(), user_id.clone());
        }

        // Try to persist to DHT (best-effort)
        if let Ok(client) = crate::dht::client::DhtClient::new() {
            let entry = UserToWordsEntry {
                user_id: user_id.clone(),
                four_words: four_words.clone(),
            };
            let _ = client.put_object(key_user_to_words(&user_id), &entry).await;
            let _ = client
                .put_object(key_words_to_user(&four_words), &entry)
                .await;
        }
        Ok(())
    }

    /// Lookup FourWordAddress by user_id.
    pub async fn get_words(&self, user_id: &str) -> Result<Option<FourWordAddress>> {
        if let Some(w) = self.user_to_words.read().await.get(user_id).cloned() {
            return Ok(Some(FourWordAddress(w)));
        }
        // Try DHT
        if let Ok(client) = crate::dht::client::DhtClient::new()
            && let Ok(Some(entry)) = client
                .get_object::<UserToWordsEntry>(key_user_to_words(user_id))
                .await
        {
            // cache
            {
                let mut u2w = self.user_to_words.write().await;
                u2w.insert(entry.user_id.clone(), entry.four_words.clone());
            }
            {
                let mut w2u = self.words_to_user.write().await;
                w2u.insert(entry.four_words.clone(), entry.user_id.clone());
            }
            return Ok(Some(FourWordAddress(entry.four_words)));
        }
        Ok(None)
    }

    /// Lookup user_id by FourWordAddress string.
    pub async fn get_user(&self, words: &str) -> Result<Option<String>> {
        if let Some(u) = self.words_to_user.read().await.get(words).cloned() {
            return Ok(Some(u));
        }
        if let Ok(client) = crate::dht::client::DhtClient::new()
            && let Ok(Some(entry)) = client
                .get_object::<UserToWordsEntry>(key_words_to_user(words))
                .await
        {
            // cache
            {
                let mut u2w = self.user_to_words.write().await;
                u2w.insert(entry.user_id.clone(), entry.four_words.clone());
            }
            {
                let mut w2u = self.words_to_user.write().await;
                w2u.insert(entry.four_words.clone(), entry.user_id.clone());
            }
            return Ok(Some(entry.user_id));
        }

        // Backfill from identity packet if publicly retrievable via identity key
        // This path allows discovering user_id from four-words when directory entries are missing.
        let parts: Vec<String> = words.split('-').map(|s| s.to_string()).collect();
        if parts.len() == 4
            && crate::fwid::fw_check([
                parts[0].clone(),
                parts[1].clone(),
                parts[2].clone(),
                parts[3].clone(),
            ])
            && let Ok(key) = crate::fwid::fw_to_key([
                parts[0].clone(),
                parts[1].clone(),
                parts[2].clone(),
                parts[3].clone(),
            ])
            && let Ok(pkt) = crate::identity_fetch(key.clone()).await
        {
            let mut hasher = Sha256::new();
            hasher.update(&pkt.pk);
            let user_id = hex::encode(hasher.finalize());
            // Cache in background (ignore errors)
            let words_owned = words.to_string();
            let this = self.clone();
            let user_id_for_cache = user_id.clone();
            tokio::spawn(async move {
                let _ = this.register(user_id_for_cache, words_owned).await;
            });
            return Ok(Some(user_id));
        }
        Ok(None)
    }
}

// Convenience top-level helpers
pub async fn register_user_address(user_id: String, four_words: String) -> Result<()> {
    address_book().register(user_id, four_words).await
}

pub async fn get_user_four_words(user_id: &str) -> Result<Option<FourWordAddress>> {
    address_book().get_words(user_id).await
}

pub async fn get_user_by_four_words(words: &str) -> Result<Option<String>> {
    address_book().get_user(words).await
}
