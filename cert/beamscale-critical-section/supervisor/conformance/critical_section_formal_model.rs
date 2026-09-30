//! Bounded model checker for durable critical-section failover.
//! The model focuses on fencing/lease handoff, not Redis implementation details.

use std::collections::{HashSet, VecDeque};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Holder {
    None,
    A,
    B,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum RequestId {
    None,
    R1,
    R2,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct State {
    now: u8,
    current_owner_epoch: u8,
    lease_owner_epoch: u8,
    sequence: u8,
    holder: Holder,
    request_id: RequestId,
    expires_at: u8,
    inherited: bool,
}

#[derive(Clone, Copy, Debug)]
enum Action {
    Tick,
    Failover,
    Acquire { holder: Holder, request_id: RequestId },
    Renew { holder: Holder, owner_epoch: u8, sequence: u8 },
    Release { holder: Holder, owner_epoch: u8, sequence: u8 },
}

const MAX_TIME: u8 = 4;
const MAX_OWNER_EPOCH: u8 = 3;
const MAX_SEQUENCE: u8 = 4;
const LEASE: u8 = 2;

fn initial() -> State {
    State {
        now: 0,
        current_owner_epoch: 1,
        lease_owner_epoch: 0,
        sequence: 0,
        holder: Holder::None,
        request_id: RequestId::None,
        expires_at: 0,
        inherited: false,
    }
}

fn expire(mut s: State) -> State {
    if s.holder != Holder::None && s.now >= s.expires_at {
        s.holder = Holder::None;
        s.request_id = RequestId::None;
        s.expires_at = 0;
        s.inherited = false;
    }
    s
}

fn valid_holder(holder: Holder) -> bool {
    matches!(holder, Holder::A | Holder::B)
}

fn owns(s: State, holder: Holder, owner_epoch: u8, sequence: u8) -> bool {
    s.holder == holder
        && !s.inherited
        && s.lease_owner_epoch == owner_epoch
        && s.current_owner_epoch == owner_epoch
        && s.sequence == sequence
        && s.now < s.expires_at
}

fn invariant(s: State) -> bool {
    if s.current_owner_epoch == 0 || s.current_owner_epoch > MAX_OWNER_EPOCH {
        return false;
    }
    if s.sequence > MAX_SEQUENCE {
        return false;
    }
    match s.holder {
        Holder::None => s.expires_at == 0 && !s.inherited && s.request_id == RequestId::None,
        Holder::A | Holder::B => {
            s.expires_at > s.now
                && s.request_id != RequestId::None
                && s.lease_owner_epoch > 0
                && s.lease_owner_epoch <= s.current_owner_epoch
                && (!s.inherited || s.lease_owner_epoch < s.current_owner_epoch)
                && (s.inherited || s.lease_owner_epoch == s.current_owner_epoch)
        }
    }
}

fn step(input: State, action: Action) -> Option<State> {
    let s = expire(input);
    let next = match action {
        Action::Tick if s.now < MAX_TIME => expire(State { now: s.now + 1, ..s }),
        Action::Failover if s.current_owner_epoch < MAX_OWNER_EPOCH => {
            let inherited = s.holder != Holder::None;
            State {
                current_owner_epoch: s.current_owner_epoch + 1,
                inherited,
                ..s
            }
        }
        Action::Acquire { holder, request_id }
            if valid_holder(holder)
                && request_id != RequestId::None
                && s.holder == Holder::None
                && s.sequence < MAX_SEQUENCE =>
        {
            State {
                holder,
                request_id,
                lease_owner_epoch: s.current_owner_epoch,
                sequence: s.sequence + 1,
                expires_at: (s.now + LEASE).min(MAX_TIME + LEASE),
                inherited: false,
                ..s
            }
        }
        Action::Acquire { holder, request_id }
            if valid_holder(holder)
                && request_id != RequestId::None
                && !s.inherited
                && s.holder == holder
                && s.request_id == request_id =>
        {
            // Idempotent replay: no new fence and no TTL extension.
            s
        }
        Action::Renew {
            holder,
            owner_epoch,
            sequence,
        } if owns(s, holder, owner_epoch, sequence) => State {
            expires_at: (s.now + LEASE).min(MAX_TIME + LEASE),
            ..s
        },
        Action::Release {
            holder,
            owner_epoch,
            sequence,
        } if owns(s, holder, owner_epoch, sequence) => State {
            holder: Holder::None,
            request_id: RequestId::None,
            expires_at: 0,
            inherited: false,
            ..s
        },
        _ => return None,
    };
    assert!(
        next.current_owner_epoch >= input.current_owner_epoch,
        "owner epoch regressed: {:?} -> {:?}", input, next
    );
    assert!(
        invariant(next),
        "invalid state: {:?} --{:?}--> {:?}",
        input,
        action,
        next
    );
    Some(next)
}

fn actions() -> Vec<Action> {
    let mut out = vec![Action::Tick, Action::Failover];
    for holder in [Holder::A, Holder::B] {
        for request_id in [RequestId::R1, RequestId::R2] {
            out.push(Action::Acquire { holder, request_id });
        }
        for owner_epoch in 1..=MAX_OWNER_EPOCH {
            for sequence in 1..=MAX_SEQUENCE {
                out.push(Action::Renew {
                    holder,
                    owner_epoch,
                    sequence,
                });
                out.push(Action::Release {
                    holder,
                    owner_epoch,
                    sequence,
                });
            }
        }
    }
    out
}

fn main() {
    let initial = initial();
    assert!(invariant(initial));
    let mut seen = HashSet::from([initial]);
    let mut queue = VecDeque::from([initial]);
    let mut transitions = 0usize;

    while let Some(state) = queue.pop_front() {
        for action in actions() {
            if let Some(next) = step(state, action) {
                transitions += 1;
                if seen.insert(next) {
                    queue.push_back(next);
                }
            }
        }
    }

    // Witness the key failover shape: an active old lease is inherited under
    // a newer owner epoch and cannot become a fresh grant until it expires.
    assert!(seen.iter().any(|s| {
        s.inherited
            && s.holder != Holder::None
            && s.lease_owner_epoch < s.current_owner_epoch
    }));
    assert!(seen.iter().any(|s| {
        s.current_owner_epoch >= 2
            && !s.inherited
            && s.holder != Holder::None
            && s.lease_owner_epoch == s.current_owner_epoch
    }));

    // Same request can replay only while the same owner still owns the live
    // lease. A failover marks the lease inherited, disabling replay until
    // persisted expiry.
    let granted = State {
        now: 0,
        current_owner_epoch: 1,
        lease_owner_epoch: 1,
        sequence: 1,
        holder: Holder::A,
        request_id: RequestId::R1,
        expires_at: 2,
        inherited: false,
    };
    assert_eq!(
        step(
            granted,
            Action::Acquire {
                holder: Holder::A,
                request_id: RequestId::R1,
            }
        ),
        Some(granted),
    );
    assert_eq!(
        step(
            granted,
            Action::Acquire {
                holder: Holder::A,
                request_id: RequestId::R2,
            }
        ),
        None,
    );
    let failed_over = step(granted, Action::Failover).expect("failover");
    assert!(failed_over.inherited);
    assert_eq!(
        step(
            failed_over,
            Action::Acquire {
                holder: Holder::A,
                request_id: RequestId::R1,
            }
        ),
        None,
    );

    println!(
        "bmscl critical-section formal model: explored {} states / {} transitions; invariants hold",
        seen.len(),
        transitions
    );
}
