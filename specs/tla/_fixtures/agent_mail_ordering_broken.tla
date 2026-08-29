---- MODULE agent_mail_ordering_broken ----
EXTENDS Naturals, FiniteSets, Sequences, TLC

\* Deliberately broken fixture for flywheel_connectors-angoc.13.5. The
\* production spec's `Deliver` action carries a causal-ordering guard
\* (`Len(messages_at[r][s]) = seq - 1`) that forces in-order delivery
\* per (recipient, sender). This fixture removes that guard so the
\* recipient may deliver messages out of order, and TLC must surface a
\* `CausalDelivery` counter-example.
\*
\* The alignment / CI gate asserts that TLC RETURNS A COUNTER-EXAMPLE
\* on this fixture; if TLC accepts the broken spec, the production
\* `CausalDelivery` invariant is too weak.

CONSTANTS Senders, Recipients, MaxMsgs

ASSUME
    /\ MaxMsgs \in 1..16
    /\ Cardinality(Senders) >= 1
    /\ Cardinality(Recipients) >= 1

VARIABLES send_count, messages_at, buffered

vars == <<send_count, messages_at, buffered>>

Init ==
    /\ send_count = [s \in Senders |-> 0]
    /\ messages_at = [r \in Recipients |-> [s \in Senders |-> <<>>]]
    /\ buffered = [r \in Recipients |-> {}]

Send ==
    \E s \in Senders :
        /\ send_count[s] < MaxMsgs
        /\ LET next_seq == send_count[s] + 1 IN
            /\ send_count' = [send_count EXCEPT ![s] = next_seq]
            /\ buffered' = [r \in Recipients |->
                              buffered[r] \cup {<<s, next_seq>>}]
            /\ UNCHANGED messages_at

\* INTENTIONALLY BROKEN: the production spec requires
\* `Len(messages_at[r][s]) = seq - 1` (deliver only after all
\* causally-prior messages have been delivered). This fixture drops
\* that guard; deliver can fire on any buffered message regardless of
\* whether its predecessors arrived first.
Deliver ==
    \E r \in Recipients :
        \E msg \in buffered[r] :
        LET s == msg[1] IN
        LET seq == msg[2] IN
        /\ messages_at' = [messages_at EXCEPT
                              ![r] = [@ EXCEPT ![s] = Append(@, seq)]]
        /\ buffered' = [buffered EXCEPT ![r] = @ \ {msg}]
        /\ UNCHANGED send_count

Next == Send \/ Deliver

Spec == Init /\ [][Next]_vars /\ WF_vars(Deliver)

NoGapsInbox ==
    \A r \in Recipients, s \in Senders :
        \A i \in DOMAIN messages_at[r][s] : messages_at[r][s][i] = i

NoDoubleDelivery ==
    \A r \in Recipients :
        \A msg \in buffered[r] :
            LET s == msg[1] IN
            LET seq == msg[2] IN
            seq > Len(messages_at[r][s])

WithinBounds ==
    /\ \A s \in Senders : send_count[s] \in 0..MaxMsgs
    /\ \A r \in Recipients, s \in Senders :
        Len(messages_at[r][s]) <= send_count[s]

Safety ==
    /\ NoGapsInbox
    /\ NoDoubleDelivery
    /\ WithinBounds

CausalDelivery ==
    \A r \in Recipients, s \in Senders :
        \A i, j \in 1..Len(messages_at[r][s]) :
            (i < j) => (messages_at[r][s][i] < messages_at[r][s][j])

Liveness ==
    \A r \in Recipients, s \in Senders, seq \in 1..MaxMsgs :
        (seq <= send_count[s]) ~> (Len(messages_at[r][s]) >= seq)

====
