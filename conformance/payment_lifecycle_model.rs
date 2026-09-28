use std::collections::{HashSet, VecDeque};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum Phase {
    Created,
    Authorized,
    Captured,
    Refunded,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct State {
    phase: Phase,
    captures: u8,
}

impl State {
    fn created() -> Self {
        return Self {
            phase: Phase::Created,
            captures: 0,
        };
    }
}

fn next_states(state: State) -> Vec<State> {
    let next = match state.phase {
        Phase::Created => State {
            phase: Phase::Authorized,
            captures: 0,
        },
        Phase::Authorized => State {
            phase: Phase::Captured,
            captures: 1,
        },
        Phase::Captured => State {
            phase: Phase::Refunded,
            captures: 1,
        },
        Phase::Refunded => state,
    };

    return vec![next];
}

fn main() {
    let initial = State::created();
    let mut queue = VecDeque::from([initial]);
    let mut seen = HashSet::from([initial]);
    let mut edges = 0_u64;

    while let Some(state) = queue.pop_front() {
        assert!(state.captures <= 1, "double capture");

        for next in next_states(state) {
            edges += 1;

            assert!(next.phase >= state.phase, "payment state regressed");
            assert!(
                next.captures >= state.captures,
                "capture count regressed"
            );

            if next.phase >= Phase::Captured {
                assert_eq!(
                    next.captures, 1,
                    "captured/refunded payment missing capture"
                );
            }

            if seen.insert(next) {
                queue.push_back(next);
            }
        }
    }

    let refunded = State {
        phase: Phase::Refunded,
        captures: 1,
    };
    assert!(seen.contains(&refunded), "refunded state is unreachable");

    println!(
        "payment lifecycle model: {} states, {edges} transitions",
        seen.len()
    );

    return;
}
