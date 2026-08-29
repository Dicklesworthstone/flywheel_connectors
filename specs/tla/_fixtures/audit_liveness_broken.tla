---- MODULE audit_liveness_broken ----
EXTENDS Naturals, FiniteSets, Sequences, TLC

\* Deliberately broken fixture for flywheel_connectors-angoc.13.4. The
\* production spec's `Durable(seq)` predicate is forced FALSE so TLC
\* must surface a counter-example for the `Liveness` property — no
\* entry can ever reach durability, so once any Append fires, the
\* `(seq \in 1..Len(entries)) ~> Durable(seq)` obligation is forever
\* unsatisfied.
\*
\* The alignment test for this fixture asserts that TLC RETURNS A
\* COUNTER-EXAMPLE (non-zero exit + "Liveness" mentioned in stderr).
\* If TLC accepts this fixture, the production property is too weak
\* and the bead's audit-durability claim is not actually being checked.

CONSTANTS Replicas, Threshold, MaxEntries, MaxAppendsBeforeReplicate

ASSUME
    /\ Threshold \in 1..Cardinality(Replicas)
    /\ MaxEntries \in 1..32
    /\ MaxAppendsBeforeReplicate \in 1..16

VARIABLES entries, held, pending_appends_since_replicate

vars == <<entries, held, pending_appends_since_replicate>>

Init ==
    /\ entries = <<>>
    /\ held = [r \in Replicas |-> {}]
    /\ pending_appends_since_replicate = 0

PrimaryReplica == CHOOSE r \in Replicas : \A other \in Replicas : r <= other

AppendEntry ==
    /\ Len(entries) < MaxEntries
    /\ pending_appends_since_replicate < MaxAppendsBeforeReplicate
    /\ LET next_seq == Len(entries) + 1 IN
        /\ entries' = Append(entries, next_seq)
        /\ held' = [held EXCEPT ![PrimaryReplica] = held[PrimaryReplica] \cup {next_seq}]
        /\ pending_appends_since_replicate' = pending_appends_since_replicate + 1

Replicate ==
    /\ \E src \in Replicas, dst \in Replicas, seq \in held[src] :
        /\ src # dst
        /\ seq \notin held[dst]
        /\ held' = [held EXCEPT ![dst] = held[dst] \cup {seq}]
    /\ UNCHANGED entries
    /\ pending_appends_since_replicate' = 0

Next == AppendEntry \/ Replicate

Spec == Init /\ [][Next]_vars /\ SF_vars(Replicate)

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

\* INTENTIONALLY BROKEN: durability is unsatisfiable, so Liveness fails
\* the moment any entry is appended.
Durable(seq) == FALSE

Liveness ==
    \A seq \in 1..MaxEntries :
        (seq \in 1..Len(entries)) ~> Durable(seq)

Recoverability_progress_invariant ==
    pending_appends_since_replicate <= MaxAppendsBeforeReplicate

Recoverability == Recoverability_progress_invariant

====
