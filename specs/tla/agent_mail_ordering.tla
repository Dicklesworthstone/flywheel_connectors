---- MODULE agent_mail_ordering ----
EXTENDS Naturals, FiniteSets, Sequences, TLC

\* flywheel_connectors-angoc.13.5 (Phase S.5)
\* Abstract causal-delivery model for agent-mail messages under HLC
\* (Hybrid Logical Clock) ordering. Concrete property: if message A
\* causally precedes message B at the sender (HLC-A < HLC-B), then
\* every recipient delivers A before B in its inbox.
\*
\* The runtime alignment lives in the agent-mail MCP server's message
\* delivery loop; this spec abstracts the wire path away and focuses
\* on the per-pair (sender, recipient) ordering invariant.

CONSTANTS
    Senders,      \* finite set of sender agent ids (e.g. {"s1", "s2"})
    Recipients,   \* finite set of recipient agent ids
    MaxMsgs       \* per-sender outbound message-count bound

ASSUME
    /\ MaxMsgs \in 1..16
    /\ Cardinality(Senders) >= 1
    /\ Cardinality(Recipients) >= 1

\* Local HLC per agent: a pair (l, c) where l is the logical-physical
\* component and c is the counter. We model it as a single natural
\* number `clock` per sender; that's sufficient for the causal-order
\* property because per-sender send order IS the only causality we
\* track (no cross-sender happens-before in this abstract model).
\*
\* send_count : [Sender -> 0..MaxMsgs] — per-sender next-seq counter.
\* messages_at : [Recipient -> [Sender -> Seq(1..MaxMsgs)]] —
\*   delivered seq numbers per (recipient, sender) pair, in delivery order.
\* buffered : [Recipient -> SUBSET (Senders \X (1..MaxMsgs))] —
\*   messages that have arrived at the recipient but not yet been
\*   delivered into the inbox. A message must wait in the buffer
\*   until every causally-prior message from the same sender has been
\*   delivered.
VARIABLES send_count, messages_at, buffered

vars == <<send_count, messages_at, buffered>>

Init ==
    /\ send_count = [s \in Senders |-> 0]
    /\ messages_at = [r \in Recipients |-> [s \in Senders |-> <<>>]]
    /\ buffered = [r \in Recipients |-> {}]

\* Send: a sender s emits the next message (seq = send_count[s] + 1)
\* to ALL recipients. Each recipient's buffer gains the new entry.
Send ==
    \E s \in Senders :
        /\ send_count[s] < MaxMsgs
        /\ LET next_seq == send_count[s] + 1 IN
            /\ send_count' = [send_count EXCEPT ![s] = next_seq]
            /\ buffered' = [r \in Recipients |->
                              buffered[r] \cup {<<s, next_seq>>}]
            /\ UNCHANGED messages_at

\* Deliver: a recipient r pops a buffered message (s, seq) into its
\* inbox FROM SENDER s, but ONLY IF every smaller seq from s has
\* already been delivered. This is the causal-ordering guard: deliver
\* only when all causal predecessors are already in the inbox.
Deliver ==
    \E r \in Recipients :
        \E msg \in buffered[r] :
        LET s == msg[1] IN
        LET seq == msg[2] IN
        /\ Len(messages_at[r][s]) = seq - 1
        /\ messages_at' = [messages_at EXCEPT
                              ![r] = [@ EXCEPT ![s] = Append(@, seq)]]
        /\ buffered' = [buffered EXCEPT ![r] = @ \ {msg}]
        /\ UNCHANGED send_count

Next == Send \/ Deliver

\* Weak fairness on Deliver: a buffered message MUST eventually be
\* delivered if it stays continuously deliverable.
Spec == Init /\ [][Next]_vars /\ WF_vars(Deliver)

\* ── Safety / invariants ───────────────────────────────────────────────

\* Each recipient's per-sender inbox is a prefix-ordered sequence of
\* seq numbers starting at 1 (no gaps, no reordering).
NoGapsInbox ==
    \A r \in Recipients, s \in Senders :
        \A i \in DOMAIN messages_at[r][s] : messages_at[r][s][i] = i

\* No message is both buffered AND already in the inbox.
NoDoubleDelivery ==
    \A r \in Recipients :
        \A msg \in buffered[r] :
            LET s == msg[1] IN
            LET seq == msg[2] IN
            seq > Len(messages_at[r][s])

\* Send-count and inbox stay within bounds.
WithinBounds ==
    /\ \A s \in Senders : send_count[s] \in 0..MaxMsgs
    /\ \A r \in Recipients, s \in Senders :
        Len(messages_at[r][s]) <= send_count[s]

Safety ==
    /\ NoGapsInbox
    /\ NoDoubleDelivery
    /\ WithinBounds

\* ── Causal-delivery property (the load-bearing claim) ────────────────

\* For every recipient r and every sender s, if msg A (seq=i) is
\* causally before msg B (seq=j) at the sender (i < j), then in r's
\* per-sender inbox A appears at position i and B at position j (and
\* j > i, so A precedes B in the delivered order). This is exactly
\* what `NoGapsInbox` already enforces — but stated as a per-pair
\* property for clarity.
CausalDelivery ==
    \A r \in Recipients, s \in Senders :
        \A i, j \in 1..Len(messages_at[r][s]) :
            (i < j) => (messages_at[r][s][i] < messages_at[r][s][j])

\* ── Liveness ──────────────────────────────────────────────────────────

\* Every sent message is eventually delivered to every recipient.
\* `~>` is "leads to" — always (P implies eventually Q).
Liveness ==
    \A r \in Recipients, s \in Senders, seq \in 1..MaxMsgs :
        (seq <= send_count[s]) ~> (Len(messages_at[r][s]) >= seq)

====
