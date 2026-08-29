---- MODULE audit_liveness ----
EXTENDS Naturals, FiniteSets, Sequences, TLC

\* flywheel_connectors-angoc.13.4 (Phase S.4)
\* Abstract liveness model for the fcp-audit chain replication: every
\* appended entry is eventually durably stored on at least THRESHOLD of
\* REPLICAS zones, and every replica's local chain grows monotonically.
\* The concrete Rust alignment lives in crates/fcp-audit/src/ (writers
\* per-zone) + crates/fcp-store/src/offline.rs (replica drain).

CONSTANTS
    Replicas,        \* finite set of replica zone ids (e.g. {1, 2, 3})
    Threshold,       \* quorum required for "durable" (e.g. 2)
    MaxEntries,      \* state-space bound for TLC
    MaxAppendsBeforeReplicate  \* fairness throttle: bound the number
                               \* of consecutive Appends without a
                               \* Replicate so liveness obligations
                               \* don't accumulate without bound

ASSUME
    /\ Threshold \in 1..Cardinality(Replicas)
    /\ MaxEntries \in 1..32
    /\ MaxAppendsBeforeReplicate \in 1..16

\* entries : Seq(Nat) — the canonical append-ordered sequence of entry
\*   sequence numbers as observed by the writer. Index in this sequence
\*   is the seq number minus 1.
\* held : [Replica -> SUBSET (1..MaxEntries)] — for each replica, the
\*   set of entry seq numbers currently durable on that replica's local
\*   chain. Monotonicity invariant: held[r] only grows.
\* pending_appends_since_replicate : counter for the fairness bound.
VARIABLES entries, held, pending_appends_since_replicate

vars == <<entries, held, pending_appends_since_replicate>>

Init ==
    /\ entries = <<>>
    /\ held = [r \in Replicas |-> {}]
    /\ pending_appends_since_replicate = 0

\* The primary writer always holds the entry on at least one replica
\* on Append (otherwise the entry would be lost on the writer reboot).
\* We model the primary as the smallest-id replica in `Replicas`.
PrimaryReplica == CHOOSE r \in Replicas : \A other \in Replicas : r <= other

\* Renamed from `Append` to `AppendEntry` so the action name does not
\* shadow the `Sequences!Append` operator we call inside it.
AppendEntry ==
    /\ Len(entries) < MaxEntries
    /\ pending_appends_since_replicate < MaxAppendsBeforeReplicate
    /\ LET next_seq == Len(entries) + 1 IN
        /\ entries' = Append(entries, next_seq)
        /\ held' = [held EXCEPT ![PrimaryReplica] = held[PrimaryReplica] \cup {next_seq}]
        /\ pending_appends_since_replicate' = pending_appends_since_replicate + 1

\* Replicate: any replica that holds an entry can copy it to another
\* replica that doesn't yet hold it. This models the gossip / drain
\* path described in fcp-store's offline replica synchronization.
Replicate ==
    /\ \E src \in Replicas, dst \in Replicas, seq \in held[src] :
        /\ src # dst
        /\ seq \notin held[dst]
        /\ held' = [held EXCEPT ![dst] = held[dst] \cup {seq}]
    /\ UNCHANGED entries
    /\ pending_appends_since_replicate' = 0

Next == AppendEntry \/ Replicate

\* Strong fairness on Replicate guarantees that whenever a Replicate
\* action is continuously enabled, it eventually fires. Combined with
\* the Append throttle (pending_appends_since_replicate <
\* MaxAppendsBeforeReplicate), the model has bounded staleness.
Spec == Init /\ [][Next]_vars /\ SF_vars(Replicate)

\* ── Safety / invariants ───────────────────────────────────────────────

\* Monotonic chain growth per replica: held only ever expands.
\* TLA+ models this as an action-level property (next-state relation
\* never shrinks held); we encode it as the box-prop in the spec via
\* the absence of any Remove action, but also assert structural
\* well-formedness as an invariant.
NoUnknownEntryHeld ==
    \A r \in Replicas :
        \A seq \in held[r] : seq \in 1..Len(entries)

ChainOrderConsistent ==
    \A i \in DOMAIN entries : entries[i] = i

Safety ==
    /\ entries \in Seq(1..MaxEntries)
    /\ Len(entries) <= MaxEntries
    /\ NoUnknownEntryHeld
    /\ ChainOrderConsistent

\* ── Liveness ──────────────────────────────────────────────────────────

\* Durable(seq) iff at least Threshold replicas hold the entry.
Durable(seq) == Cardinality({ r \in Replicas : seq \in held[r] }) >= Threshold

\* Every appended entry is eventually durable. Quantification over
\* concrete seq values (1..MaxEntries) keeps the property checkable;
\* the implicit "for every appended entry" follows from monotonic
\* chain growth + the bounded model.
Liveness ==
    \A seq \in 1..MaxEntries :
        (seq \in 1..Len(entries)) ~> Durable(seq)

\* ── Bounded-staleness recoverability ──────────────────────────────────
\* No entry is appended that cannot reach durability under SF_vars
\* (Replicate). Given the throttle, after at most
\* MaxAppendsBeforeReplicate consecutive Appends, the next step MUST
\* be a Replicate, so durability progress is guaranteed.
Recoverability_progress_invariant ==
    pending_appends_since_replicate <= MaxAppendsBeforeReplicate

Recoverability == Recoverability_progress_invariant

\* ── Failure-injection helpers (used by alignment tests) ───────────────
\* When the alignment harness deliberately sets THRESHOLD > |Replicas|,
\* Liveness becomes vacuously false and TLC must surface a counter-
\* example. The Safety invariant alone is insufficient to catch this;
\* Liveness is the load-bearing property for the audit-chain durability
\* claim.

====
