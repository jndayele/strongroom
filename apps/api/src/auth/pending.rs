#![forbid(unsafe_code)]

use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::auth::opaque::{AuthError, ServerLoginState};

/// Time-to-live for an in-progress OPAQUE login state (60 seconds).
pub const LOGIN_STATE_TTL: Duration = Duration::from_secs(60);

/// Hard capacity cap for in-progress OPAQUE login states (10,000 entries).
pub const MAX_PENDING_LOGINS: usize = 10_000;

/// 32-byte random identifier for an in-progress login ceremony.
pub type LoginId = [u8; 32];

/// 16-byte UUID value representing an authenticated user row ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Uuid([u8; 16]);

impl Uuid {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// A single in-progress OPAQUE login ceremony stored in memory between `login/start` and `login/finish`.
pub struct PendingLoginEntry {
    pub login_state: ServerLoginState,
    /// `Some(Uuid)` for a known user, or `None` for the unknown-email dummy path.
    pub user_id: Option<Uuid>,
    created_at: Instant,
}

impl fmt::Debug for PendingLoginEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingLoginEntry")
            .field("login_state", &"[redacted]")
            .field("user_id", &self.user_id)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Bounded, thread-safe in-memory store for in-progress OPAQUE login states.
///
/// ### Capacity & Eviction Policy
/// - Each entry expires after [`LOGIN_STATE_TTL`] (60 seconds).
/// - On every [`PendingLoginStore::insert`], all expired entries are purged first.
/// - If the store is still at [`MAX_PENDING_LOGINS`] (10,000 active entries) after purging
///   expired entries, the new login attempt is **rejected** rather than evicting an older
///   unexpired entry. This prevents an unauthenticated flood from evicting legitimate users'
///   in-flight login ceremonies before they can call `login/finish`.
/// - Uses `std::sync::Mutex` because all critical sections are fast, synchronous in-memory
///   operations; the lock guard is never held across an `.await` point.
pub struct PendingLoginStore {
    entries: Mutex<HashMap<LoginId, PendingLoginEntry>>,
}

impl Default for PendingLoginStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PendingLoginStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingLoginStore")
            .field("entries", &"[redacted]")
            .finish()
    }
}

impl PendingLoginStore {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Purges expired entries as of `now`, checks the 10,000-entry hard cap, and inserts a new
    /// pending login entry keyed by 32 random bytes from `OsRng`.
    pub fn insert(
        &self,
        login_state: ServerLoginState,
        user_id: Option<Uuid>,
        now: Instant,
    ) -> Result<LoginId, AuthError> {
        let mut guard = self.entries.lock().map_err(|_| AuthError)?;

        // 1. Purge all expired entries first.
        guard.retain(|_, entry| now.saturating_duration_since(entry.created_at) < LOGIN_STATE_TTL);

        // 2. Enforce hard capacity cap: reject new attempts when full rather than evicting valid in-flight logins.
        if guard.len() >= MAX_PENDING_LOGINS {
            return Err(AuthError);
        }

        // 3. Generate a 32-byte random key from OsRng.
        let mut login_id = [0u8; 32];
        OsRng.fill_bytes(&mut login_id);

        guard.insert(
            login_id,
            PendingLoginEntry {
                login_state,
                user_id,
                created_at: now,
            },
        );

        Ok(login_id)
    }

    /// Atomically removes and returns the entry for `login_id` if it exists and has not expired as of `now`.
    /// Because `remove` is unconditional, every `login_id` is strictly single-use.
    pub fn take(
        &self,
        login_id: &LoginId,
        now: Instant,
    ) -> Result<(ServerLoginState, Option<Uuid>), AuthError> {
        let mut guard = self.entries.lock().map_err(|_| AuthError)?;
        let entry = guard.remove(login_id).ok_or(AuthError)?;

        if now.saturating_duration_since(entry.created_at) >= LOGIN_STATE_TTL {
            return Err(AuthError);
        }

        Ok((entry.login_state, entry.user_id))
    }

    /// Returns the current number of stored entries (used by tests to inspect capacity).
    pub fn len(&self) -> Result<usize, AuthError> {
        let guard = self.entries.lock().map_err(|_| AuthError)?;
        Ok(guard.len())
    }

    /// Returns true if the store currently has no entries.
    pub fn is_empty(&self) -> Result<bool, AuthError> {
        Ok(self.len()? == 0)
    }
}
