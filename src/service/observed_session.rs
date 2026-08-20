//! A relayed session the pool **observes** but does not own — and the notice it owes that session's
//! owner when the slot is retired (**dig_ecosystem#1871**, **#71**).
//!
//! # Why observation and notification are one type
//!
//! [`GossipHandle::adopt_relayed_inbound_handle`](crate::GossipHandle::adopt_relayed_inbound_handle)
//! registers a peer whose `dig_nat::PeerSession` stays with the CALLER, because the caller is serving
//! the peer on it. The pool therefore holds a [`dig_nat::ClosedHandle`] — enough to answer *"is this
//! peer still up?"* for the departed-peer reaper, and deliberately not enough to hang up on a peer
//! another task is mid-conversation with.
//!
//! That is correct for a slot the pool merely RELINQUISHES. It is wrong for one the pool RETIRES: when
//! a newer session supersedes this one, or the pool displaces it to admit a discovered holder, the
//! session is obsolete and only its owner can end it. A `ClosedHandle` observes; it cannot tell anyone
//! anything. So an observed session carries the observation AND the callback that reaches its owner,
//! and the two cannot be registered apart — a slot with no way to notify its owner is exactly the
//! silent accounting failure this pairing exists to prevent.

/// The callback the pool invokes when it RETIRES the slot an [`ObservedSession`] backs.
///
/// Ownership is unchanged by this: the pool runs the CALLER's code and the caller decides what to do
/// — usually close the session it is still serving. Fired at most once, after the peer-map lock is
/// released, and never on a slot the pool merely relinquishes (see [`ObservedSession`]).
pub struct SupersedeNotice(Box<dyn FnOnce() + Send>);

impl SupersedeNotice {
    /// Wrap the caller's notification. It must not block: the pool calls it inline while finishing an
    /// admission, so signalling a task (a `oneshot`, an `AtomicBool` + `Notify`, a channel send) is
    /// the intended shape rather than an inline teardown that awaits.
    pub fn new(notify: impl FnOnce() + Send + 'static) -> Self {
        SupersedeNotice(Box::new(notify))
    }

    /// Deliver the notice, consuming it — so a slot can never notify its owner twice.
    pub(crate) fn fire(self) {
        (self.0)();
    }
}

impl std::fmt::Debug for SupersedeNotice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SupersedeNotice(..)")
    }
}

/// A relayed `dig_nat` session the pool watches on the caller's behalf: a liveness observer plus the
/// notice owed to the session's owner when the pool retires its slot.
///
/// Construct one with [`ObservedSession::new`] and hand it to
/// [`GossipHandle::adopt_relayed_inbound_handle`](crate::GossipHandle::adopt_relayed_inbound_handle).
#[derive(Debug)]
pub struct ObservedSession {
    closed: dig_nat::ClosedHandle,
    on_superseded: SupersedeNotice,
}

impl ObservedSession {
    /// Pair the session's liveness observer with the notice that reaches its owner.
    ///
    /// `closed` MUST observe the session serving THIS peer
    /// ([`dig_nat::PeerSession::closed_handle`]) — it is the slot's only departure signal, so a handle
    /// for a different or already-dead session makes the peer reap immediately or never.
    /// `on_superseded` MUST reach whoever holds that same session.
    pub fn new(closed: dig_nat::ClosedHandle, on_superseded: impl FnOnce() + Send + 'static) -> Self {
        ObservedSession {
            closed,
            on_superseded: SupersedeNotice::new(on_superseded),
        }
    }

    /// Whether the observed session's transport has already closed — one atomic load, never awaits.
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.is_closed()
    }

    /// Take the notice, leaving the session unobservable to a second retirement.
    pub(crate) fn into_notice(self) -> SupersedeNotice {
        self.on_superseded
    }
}
