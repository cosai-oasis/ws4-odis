# The ODIS Router

## Summary

ODIS divides agent access across three layers. The [Passport](../ODIS.md#31-layer-1--the-passport-identity--attestation) establishes the agent's software and running instance, from which a short-lived Agent Runtime Credential bound to that instance is issued; the [Bridge](../ODIS.md#32-layer-2--the-bridge-delegation--access) records who the agent acts for and what authority it holds, and carries that authority to downstream systems; the [Router](../ODIS.md#33-layer-3--the-router-discovery--governance) governs discovery of, and calls to, tools and services. This document specifies how the Router evaluates and enforces each call.

## Scope

This document specifies how a Router handles each call to a tool or service: verifying the caller, resolving the actual target, obtaining a policy decision, and enforcing it. It also covers rate limits, revocation, tool discovery, audit records, Router placement and composition, and the Router's dependencies.

Out of scope:

1. Agent Runtime Credential issuance and Bridge authority grants, which ODIS defines in [§3.1](../ODIS.md#31-layer-1--the-passport-identity--attestation) and [§3.2](../ODIS.md#32-layer-2--the-bridge-delegation--access). This document specifies only what the Router requires from them.
2. Policy languages, policy engines, and the Router-to-engine transport. This document specifies the facts the Router supplies and the decisions it must handle.
3. General inspection of request and result content, including sensitive data in free text and instructions intended to redirect an agent. Deployments can add content inspection alongside the Router.

## 1. Request flow architecture

A Router sits on the path between an agent and the tools and services the agent calls. [Section 4.1](#41-invoice-payment) follows one call through it.

### 1.1 Components and flow

```
  Agent
    │  call, with the Bridge's token
    ▼
  ╔═ Router ════════════════════════════════════════════════════════╗

    1 Intake             keeps an unchanged copy of the call
    │
    ▼
    2 Token verifier     ◀── keys of trusted Bridges, revocation information
    │
    ▼
    3 Target resolver    ◀── routing configuration, tool registry
    │
    ▼
    4 Request builder    ──── decision request ────▶  Policy engine
                                                          │
    6 Enforcer           ◀─── decision (5) ───────────────┘
    │  works from the copy kept at step 1
    │
    ├──▶ 7 Audit record
    │
  ╚═│═══════════════════════════════════════════════════════════════╝
    ▼
  Tool or service     receives the evaluated call, or nothing
```

1. **Receive:** retain the call as received, record the time, and assign an evaluation ID.
2. **Verify:** check the Bridge token and proof of possession ([2.1.2](#212-caller-verification)).
3. **Resolve:** determine the actual server, operation, and resources ([2.1.3](#213-target-resolution)).
4. **Request a decision:** send the policy engine the required and declared inputs ([2.1.4](#214-policy-request)).
5. **Validate the decision:** confirm the response belongs to this evaluation and is still fresh ([2.1.5](#215-decisions)).
6. **Enforce:** meet any obligations, recheck revocation, apply a downstream credential, and dispatch the evaluated call, or stop ([2.1.6](#216-hand-off-to-the-provider-adapter), [2.1.8](#218-revocation), [2.2.1](#221-obligations)).
7. **Record:** write the decision record ([2.1.11](#2111-audit)). Where [RTR-64](#rtr-64-durable-record-before-irreversible-effects) applies, the component performing an irreversible effect commits an intent before that effect and records its outcome afterward.

The Router verifies inputs and enforces outcomes; a policy engine applies organizational rules to Router-supplied inputs and decides. The Router and the policy engine can run together or separately. The Router's components can share a process or run separately, but the agent does not control them (RTR-01). Verification and target resolution use trusted keys, revocation data, routing configuration, and registry records rather than agent-supplied claims.

Most tools do not understand ODIS tokens. ODIS assigns credential translation to Layer 2 ([§3.2](../ODIS.md#32-layer-2--the-bridge-delegation--access)): a Provider Adapter conveys ODIS credentials to a native-mode target or obtains a target-native credential in bridge mode (ODIS-L2-15), and a Cache and Revocation Manager holds derived credentials and invalidates them on revocation. The Router does not take on that role; it decides, and only then lets the adapter act ([2.1.6](#216-hand-off-to-the-provider-adapter)). The adapter can run in the same gateway as the Router, be called by it, or sit later in the path.

The Router's inputs arrive in three ways:

- **With the request:** each call carries the signed Bridge token with agent, principal, and authority facts, and a call without one is refused (RTR-03). Carrying it does not let the agent misuse it: the token is signed, bound to the agent's key (RTR-05), and presented by the authorized presenter (ODIS-L2-13). With trusted Bridge keys held locally, the Router need not contact the Passport, Bridge, or registry for each call.
- **Ahead of time:** signed bundles can provide routing configuration, target facts, and Bridge keys. Revocation events and risk signals can be pushed into a local store. The Router then uses local lookups.
- **At the Router:** rate-limit counters, calls under evaluation, and pending audit records require Router-controlled state.

### 1.2 Trust inputs

The Router never sees raw attestation evidence, only the Bridge's signed account of the credential issuer's results.

The Bridge records authority granted by an entitled party, such as a principal or administrator. Principal, task, and permissions are grant decisions rather than facts established by technical evidence. The Router relies on the Bridge's signed claims about them.

The Router verifies a Bridge token rather than the Agent Runtime Credential itself. ODIS defines the credential ([§6.2](../ODIS.md#62-agent-runtime-credential-descriptor)) and the Passport RFC the Bridge token (BRG-14). A Router need only support Bridge tokens, though its trust depends on the Bridges it accepts. A careless credential issuer, over-permissive Bridge, or compromised policy engine can still cause incorrect decisions that the Router cannot detect.

The agent chooses the requested tool, operation, and arguments. The Router treats these as inputs to evaluate, retains the request, and forwards only the request that was evaluated. Other inputs, such as a self-reported model, a tool's read-only description, or a risk signal with an unconfirmed source, can be useful but are marked unverified for the policy engine (RTR-16).

| Input | Source and treatment |
|---|---|
| Requested tool, operation, and arguments | Agent-supplied; evaluated as untrusted input. Only the evaluated request is forwarded. |
| Agent and running instance | The credential issuer's results, carried in the Bridge token. |
| Principal and task | Authority recorded in the Bridge token. |
| Authority for the call | Bridge token, already narrowed by all applicable limits; the Router does not recompute it. |
| Session | Bridge token or Router records, never an agent-supplied identifier. |
| Actual server and tool | Router configuration or a trusted registry; the Router resolves aliases chosen by the agent. |
| Time and decision identifier | Assigned by the Router for freshness and replay checks. |
| Risk signals | Source, freshness, and subject checked by the Router; otherwise marked unverified. |

### 1.3 Placement

Wherever it runs, a Router sits between the model's instructions and the agent's actions: every governed action passes through it. A Router can run at the agent, in a gateway, or in front of a tool. A deployment can use several Routers on one path, and each Router can consult several decision sources ([2.1.9](#219-composition-and-coverage)). Placement depends on:

- **Isolation:** nothing the model controls can reach the Router's code, configuration, keys, or the downstream credentials it uses (RTR-01). A separate protected component can satisfy this, and so can an in-process one under the conditions in RTR-01.
- **Visibility:** a Router can apply a rule only if it sees the facts the rule needs. Without them it denies (RTR-03), which still enforces the rule but also blocks calls the rule would allow.
- **Coverage:** organization-wide rules belong on paths used by all agents; agent-specific rules can run near that agent (RTR-46).

| Position | Can observe | Might lack |
|---|---|---|
| At the agent: an in-process hook, sidecar, or local proxy | Each call, the sequence of calls within a task (trajectory), and the agent's stated reason for a call (unverified) | Other agents' activity and proof that no alternate tool path exists |
| Gateway | Calls to tools behind it and totals across those agents | The agent's internal reason for a call |
| In front of the tool | Effects on the tool's data, result size, and local access rules | Delegation context unless forwarded |

In any of these forms, a Router at the agent has to meet RTR-01; in-process, that rules out agents with tools that run code or write files unless keys and credentials are held outside the process.

A gateway is a useful starting point for organization-wide policy because it is outside the agent's control and sees traffic to the tools behind it. It does not see tools that run locally, such as file, shell, or code-execution tools, so governing those needs a Router at the agent (RTR-02). Agent-specific and tool-specific rules might also require additional Routers.

### 1.4 Threats addressed

| Risk | Mitigation |
|---|---|
| An agent presents forged identity or authority, or a copied token. | Bridge token checks and proof of possession (RTR-05, RTR-06). |
| A call reaches a tool through an alias that policy does not cover. | Policy evaluates the resolved target, and aliases share limits (RTR-12, RTR-13, RTR-36). |
| New or split sessions are used to evade limits or detection. | Limits keyed by agent, delegation and principal, not only session (RTR-36, [Section 3.7](#37-authority-limit-keys)). |
| A stale token or decision is replayed. | Per-call checks, single-use tokens and permits, evaluation identifiers (RTR-10, RTR-11, RTR-22, RTR-24). |
| The Router forwards a request different from the one evaluated. | Dispatch must match the evaluated call (RTR-23). |
| The agent reaches a tool directly, bypassing the Router. | No bypass, and the agent never holds downstream credentials (RTR-02, RTR-27). |
| Content the agent reads redirects it (prompt injection). | Nothing the model influences can alter the Router, and every call is decided (RTR-01, RTR-20). |
| A host operator disables a Router on the agent's machine. | An independently administered Router on every protected path (RTR-47). |

## 2. Requirements

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals. Each requirement names the party it binds; most bind the Router.

- **Required** ([2.1](#21-required)) applies to every Router at or above the requirement's profile, and to every deployment that uses one.
- **Optional** ([2.2](#22-optional)) can be omitted. A Router or deployment that implements an optional capability MUST meet its requirements.
- **Profile** is a provisional tag naming the lowest ODIS conformance profile ([ODIS §8.1](../ODIS.md#81-profile-definitions)) at which the requirement would apply when a Router handles a call. For an optional capability, it names the profile at which ODIS would expect the capability, or "no profile" if none.
- Terms defined in the [Glossary](#glossary), notably *verified attribute*, *unverified input*, *evaluated call*, *cleared for dispatch*, and *enforceable permit*, carry those meanings in requirements.
- Each requirement's heading is followed by its profile and **Ref**, which lists related ODIS requirements, without the `ODIS-` prefix ([ODIS §5](../ODIS.md#5-requirements)), and ODIS sections (§).

### 2.1 Required

#### 2.1.1 General

##### RTR-01 Router integrity

*Core; §3.3*

The Router MUST be outside the agent's control: the agent, and anything the model can influence (tools that run code or write files, plugins loaded into the agent's process, and any memory or file those can reach), MUST NOT be able to read the Router's keys or the downstream credentials it uses, or alter the Router's code, configuration, or state. Content an agent reads can contain instructions that redirect its behavior (prompt injection), so nothing the model can influence can be trusted to enforce policy. A Router inside the agent's process often cannot meet this, but an embedded check can if the agent has no such tools and keys and credentials are held outside the process.

##### RTR-02 No bypass

*Core; L3-08*

The agent MUST NOT be able to bypass the Router on the way to a tool. A path around the Router makes every other requirement moot.

##### RTR-03 Fail closed

*Core; L2-01, L2-13*

The Router MUST deny the call if it cannot establish any required fact, complete a required check, or interpret an input, including when revocation data is unavailable. An incomplete check MUST NOT permit a call.

#### 2.1.2 Caller verification

Before seeking a policy decision, the Router establishes the caller's identity and authority and verifies that the caller is the credential holder. Some facts are checked when a token is issued; others on every call.

##### RTR-04 Required facts

*Core; L1-09, L2-13*

For each call, the Router MUST establish (1) the agent and its running instance, (2) the principal for whom it acts, (3) its authority for this call, and (4) that the caller holds the agent's private key. ODIS does not require a particular artifact to carry these facts, provided the Router can verify them.

##### RTR-05 Proof of possession

*Core; L1-09*

The Router MUST verify that the caller holds the private key the token is bound to, for example a proof signed with that key (DPoP or a WIMSE Workload Proof Token), an HTTP Message Signature, or a mutually authenticated TLS connection bound to the token. A copied token alone MUST NOT be accepted. The caller is the component that holds the key and presents the request: the agent's runtime, or in the sidecar and SDK patterns ([ODIS §7.2](../ODIS.md#72-deployment-patterns)) the isolated presenter (L2-13). Where the Router is a separate hop, the presenter proves possession to it on that hop. Where the Router runs inside the presenter, isolation from the agent (RTR-01) takes the place of that proof.

##### RTR-06 Bridge token checks

*Core; L2-13, L3-02*

For a call carrying a Bridge token, the Router MUST check (1) a valid signature from a Bridge configured as trusted, (2) expiry and revocation status, (3) an audience that includes the Router or the target tool, (4) proof of possession of the bound key, and (5) that the call is within the token's task and resource limits.

##### RTR-07 Bridge token issuance

*Core; L1-05, L3-04, §6.3*

For a Bridge token to stand in for the Agent Runtime Credential, the Bridge MUST carry the credential issuer's results the Router needs in its signed token, MUST bind the token to the same private key as that credential, and MUST set the token to expire no later than it. Revoking the credential MUST also revoke tokens derived from it. The Router can then verify Bridge tokens without parsing Agent Runtime Credentials.

##### RTR-08 Issuance-time checks

*Core; L1-02, L2-06, L2-14*

At issuance, the credential issuer checks that the agent's software was approved, and the Bridge checks that the Agent Runtime Credential is genuine and that each delegation passed on no more authority than it received. The Router MAY rely on those results only in a token from a Bridge configured as trusted.

##### RTR-09 Cross-organization calls

*Extended; L1-07*

For a call from another organization, the receiving organization's Bridge MUST check the incoming credentials and delegations and issue its own token. The Router MUST still rely only on a Bridge it trusts.

##### RTR-10 Per-call checks

*Core; L3-04*

Expiry, revocation, and the principal's continuing authority can change after issuance, so the Router MUST check them on every call. Revocation data MAY be cached within the deployment's declared revocation delay.

##### RTR-11 Single-use tokens

*Core*

A single-use token MUST be consumed by exactly one component on the call path. The deployment MUST identify that component; other components MUST verify the token without consuming it, so they do not reject it as a replay.

#### 2.1.3 Target resolution

The Router resolves a call to its actual target before requesting a policy decision, so that the decision covers the operation and resources that will be reached.

##### RTR-12 Resolved target

*Core; §6.4*

Before requesting a decision, the Router MUST determine (1) the operation type: a tool invocation, resource read, prompt fetch, or other operation the binding supports; (2) the service that will handle the call, identified through trusted routing information, with the attributes policy can depend on, such as owner and region; (3) the tool or endpoint and the action it performs; (4) every resource the call affects: the data the operation reads or changes, such as a record, file, or collection, identified by URI. For example, the invoice an argument identifies, or the destination collection of a create operation. Where the affected records are known only when the operation runs, such as a search or a server-side bulk update, the resource is the named collection or scope the operation can reach; and (5) the gateway entry point or namespace, if present, because a deployment can grant access to different virtual servers. For a web API, the Router uses the method, address, and relevant fields. Policy MUST be evaluated against the resolved target, not the caller-visible name.

##### RTR-13 Resolution sources

*Core; §6.4*

When the Router runs in the gateway, the gateway's routing configuration MUST determine both the target evaluated and the target invoked. If they run separately, the gateway MUST provide a trusted mapping or a signed statement of the target resolved for each call. In either case, the evaluated target MUST match the actual destination. The gateway MAY choose among instances of that service after the decision, but only instances with the evaluated attributes that also meet any constraint the decision imposes, such as region. A trusted tool or service registry MAY supplement that mapping. Protocol-specific bindings define how calls map to policy actions and resources, including which arguments identify resources or matter to the decision. The agent supplies the name and arguments but MUST NOT supply the mapping used to interpret them; otherwise it could present a sensitive call as a harmless one.

##### RTR-14 Resolution failure

*Core; §6.4*

The Router MUST deny a call if it cannot resolve the name, server, or affected resources, or if resolution would require an unknown target or a wildcard. It MUST NOT substitute a wildcard for resources it cannot identify or infer a safe target from incomplete information. A named, bounded collection is not a wildcard.

##### RTR-15 Target attributes

*Core; §6.4*

Policies can use a target's owner, data sensitivity, or storage location. Each attribute MUST record its source and verification status, and SHOULD record its observation time and validity period. Registry attributes from a trusted source are verified. A tool's self-description, such as a read-only label, counts as verified only where the deployment trusts the tool's provider (RTR-34); otherwise the Router MAY pass it to the policy engine as an unverified input.

#### 2.1.4 Policy request

##### RTR-16 Request content

*Core; L3-06, §6.4*

After verifying the caller and resolving the target, the Router MUST send the policy engine a decision request ([Section 3.1](#31-policy-request)) carrying facts the Router established and identifying any unverified inputs. The Router MUST check each risk signal's source, freshness, and subject, and otherwise mark it unverified. The policy engine need not parse Agent Runtime Credentials, Bridge tokens, or their supporting proof.

##### RTR-17 Policy input declaration

*Core; CC-07*

A deployment MUST publish a policy input declaration ([Section 3.3](#33-policy-input-declaration)) for each policy engine. A test can then check that each request contains only required fields and declared optional inputs.

##### RTR-18 Input minimization

*Core; CC-07*

The Router MUST include the required fields and only the optional inputs needed for the decision, as named in the engine's policy input declaration. Arguments, the delegation chain, the task description, and the software digest can contain sensitive information and MUST be sent only when declared. Raw credentials, private keys, and secrets MUST NOT be sent. If a required input is unavailable or cannot meet its declared verification level, the Router MUST deny the call.

#### 2.1.5 Decisions

The Router acts on a policy decision only for the call evaluated and while that decision remains valid.

##### RTR-19 Decision outcomes

*Core; L3-06, §6.4*

The policy engine MUST return one of the outcomes in [Section 3.4](#34-policy-response). They MUST remain distinct for audit and operations, because a policy refusal and an evaluation failure require different responses. A policy that allows by default MUST return `permit` when no rule matches; `not_applicable` stops the call.

##### RTR-20 Enforceable permit

*Core; §6.4*

Only an enforceable permit allows dispatch. The Router MUST stop the call on any other outcome, on a missing or unreadable response, or on a permit that is not enforceable, and MUST record the reason so operators can distinguish policy refusals from failures.

##### RTR-21 Guidance and advice

*Core; §6.4*

When a denial includes guidance for the caller (`context`), such as requesting manager approval before retrying a payment, the Router MUST return it to the caller. Guidance does not authorize a later call; a retry is evaluated like any other. `advice` is nonbinding ([Section 3.4](#34-policy-response)); the Router MAY record or surface it, and MUST NOT let it stop or change a call.

##### RTR-22 Evaluation identifiers

*Core; CC-01, §6.4*

The Router MUST assign each policy request an `evaluation_id` that identifies that decision and is unique across every Router whose records can be correlated. The policy engine MUST copy it into the response, and the Router MUST accept the response only for the matching pending evaluation. `request_trace_id` only correlates records: one request can produce several evaluations, for example after a retry or at several Routers, so it MUST NOT identify a decision.

##### RTR-23 Evaluated call

*Core; L2-13*

The Router MUST retain the incoming call unchanged as the evaluated call, apart from any argument binding (RTR-66), and derive the policy request from it. Before dispatch, it MUST confirm that the call it is about to send still matches the evaluated call; if it does not, or the permit's obligations change, it MUST obtain a new decision. The Router MAY add a downstream credential after the decision but MUST NOT change the evaluated operation or arguments.

##### RTR-24 Freshness and single use

*Core; L2-13*

A permit MUST authorize at most one dispatch, and only within its validity period ([Section 3.4](#34-policy-response)). Revocation is still checked before dispatch (RTR-42); a short decision lifetime does not replace that check.

##### RTR-25 External policy engines

*Core; L3-06*

When the policy engine runs as a separate service, the Router and the engine MUST authenticate each other and protect the integrity of the request and response in transit between them. An in-process engine shares the Router's trust boundary.

#### 2.1.6 Hand-off to the Provider Adapter

Most tools require a credential issued for their own access system, such as an OAuth token, cloud role, or API key, rather than an ODIS token. These requirements cover when the Provider Adapter can act for a call and what the Router requires of it. The adapter's own behaviour is specified by ODIS-L2-08, L2-10 and L2-15.

##### RTR-26 Decision before credential

*Core; L2-13, §7.2*

The Provider Adapter MUST obtain or attach a downstream credential for a call only after that call is cleared for dispatch, and only for that call.

##### RTR-27 Credential custody

*Core; L2-10*

A downstream credential for a permitted call MUST stay with the Provider Adapter or the Router (ODIS-L2-10). The agent MUST NOT receive, store, or present one; otherwise it could bypass the Router with an unevaluated call.

##### RTR-28 Credential scope

*Core; L2-10*

The downstream credential SHOULD be as narrow as the tool's access system allows: the target tool, the operation's required permissions, and a short lifetime. Where it is still broader than the evaluated call, the Provider Adapter MUST use it only for that call (ODIS-L2-10).

##### RTR-29 Key-bound Bridge tokens

*Core; L2-12*

The Provider Adapter MUST NOT present an agent's key-bound Bridge token to another identity provider, since it cannot prove possession of the agent's key. It obtains downstream credentials on its own identity (ODIS-L2-12).

##### RTR-30 Egress mode

*Core; L2-15*

The Router MUST dispatch through the egress mode the Provider Adapter declares for the target (ODIS-L2-15), and MUST NOT fall back from bridge mode to forwarding the agent's credentials.

##### RTR-31 Credential reuse

*Core; L2-11*

Caching and invalidating derived credentials belong to the Cache and Revocation Manager ([§3.2](../ODIS.md#32-layer-2--the-bridge-delegation--access)). A cached credential MUST NOT stand in for a decision: every call using one MUST have its own permit and fit both the credential's limits and that permit.

##### RTR-32 Exchange audit linkage

*Core; CC-06*

The Provider Adapter MUST record each exchange with the call's `evaluation_id`, so it links to the decision record (RTR-52, [Section 3.6](#36-decision-record)).

#### 2.1.7 Authority limits

Rate limits depend on activity across calls. Authority limits cap the use of delegated authority; load protection ([RTR-61](#rtr-61-load-protection)) is separate.

##### RTR-33 Limit definition

*Core; L3-03*

Each limit MUST define what is counted, over what period, and which key shares the count ([Section 3.7](#37-authority-limit-keys)). A limit can count all calls, a class of operations such as payments, or a quantity such as the total amount paid, over a window such as a minute, hour, or day. A deployment MAY apply several windows to the same count, such as per minute and per day, so a burst within a long window is also bounded.

##### RTR-34 Destructive classification

*Core; L3-03*

Destructive operations include actions such as deleting, paying, or sending when the effect is hard to undo. Their classification MAY come from the tool's own declaration where the deployment trusts the tool's provider, and a deployment-configured mapping MUST take precedence over it. An operation with no classification from a trusted source MUST be treated as destructive.

##### RTR-35 Counting

*Core; L3-03*

Authority limits MUST use verified attributes. The Router enforces them before dispatch and counts only calls it dispatches: a refusal MUST NOT consume an allowance, though a deployment MAY count refusals separately (RTR-38). Checking a limit and taking a unit MUST be one atomic step, so concurrent calls cannot together exceed a limit shared across Router instances (RTR-37). The Router MAY keep the counters itself or use a rate-limit service, and MAY pass current totals to the policy engine as inputs.

##### RTR-36 Count keys

*Core; L3-03*

An authority limit MUST be keyed by one or more of the keys in [Section 3.7](#37-authority-limit-keys). Each key MUST be a verified attribute, and aliases for the same tool MUST share a count. A deployment MAY combine keys, such as payments per delegation or total amount per principal; a call MUST satisfy every applicable limit.

##### RTR-37 Counter state

*Core; L3-03*

Router instances enforcing the same limit MUST share counters, and counts MUST survive Router restarts; otherwise traffic spread across instances or restarts can exceed the limit. If counter state is unavailable, calls subject to the limit MUST stop until it can be checked (RTR-49).

##### RTR-38 Repeated breaches

*Core; L3-03*

Repeated breaches of an authority limit MAY lead a deployment to block the offending delegation or agent ([RTR-63](#rtr-63-router-initiated-revocation)). Breaches of load-protection limits (RTR-61), where used, MUST NOT, since their keys are not verified.

#### 2.1.8 Revocation

Revocation ends trust before a token expires. It can stop one decision, a delegation, a session, an agent, or activity on a principal's behalf.

##### RTR-39 Change timing

*Core; L3-04*

Routine changes, such as approving new software or changing role permissions, MAY wait until short-lived credentials are renewed but MUST take effect within one renewal period; this avoids mass reissuance after broad configuration changes. Urgent changes, such as suspension, agent compromise, or withdrawal of a principal's permission, MUST propagate through revocation events, and components relying on affected tokens MUST act within the deployment's declared delay. ODIS limits that delay to 300 seconds within a trust domain. The events might also need to reach other organizations that trust the agent.

##### RTR-40 Revocation levels

*Core; L3-04, L3-05*

The Router MUST take the action in [Section 3.8](#38-revocation-levels) for each revocation level. Agent-level revocation is the ODIS kill switch. Session-level revocation depends on the still-open definition and identification of an agent session.

##### RTR-41 Revocation sources

*Core; L3-04*

The Router MAY receive signed revocation events, fetch signed revocation lists, or query the issuer when a token is used or a cached answer expires. The OpenID Foundation's Shared Signals Framework SHOULD be used for push. Queries add issuer availability to the call path; events and lists permit local checks. The Router MUST accept revocation data only from a party authorized to revoke the subject, with integrity and replay protection and an unambiguous subject identifier.

##### RTR-42 Revocation checkpoints

*Core; L3-04*

The Router MUST check revocation (1) at token verification, rejecting a revoked caller before policy evaluation; (2) before obtaining a downstream credential and again as the final step before sending the call, because approval or other work might have delayed dispatch after the first check; and (3) before releasing a result, withholding it if authority was revoked. For a stream, the Router MUST check again at intervals no longer than the declared revocation delay, and MUST stop further release once authority is revoked or its revocation data is older than that delay (RTR-43). The tool action cannot be undone, and data already released cannot be recalled. No further check is needed after the call, but after-call obligations still run for actions already taken.

##### RTR-43 Stale revocation data

*Core; L3-04*

If current revocation data is unavailable, the Router MAY rely on cached data only within the declared delay. Once it is older, the Router MUST stop accepting affected tokens until the data is refreshed (RTR-49).

#### 2.1.9 Composition and coverage

##### RTR-44 Decision sources

*Core; L3-03, L3-06*

A Router MAY consult a policy engine, rate-limit service, fraud check, or other decision sources. Any source MAY stop a call or add conditions; a source MUST NOT override another's refusal or alter the verified inputs presented to the others. The Router MUST record each source's decision. Order matters when a source counts usage (RTR-35).

##### RTR-45 Multiple Routers

*Extended; L3-02, L3-08*

A call MUST proceed only if every Router on its path permits it. Each Router MUST verify the call and apply its own policies; another Router's permit MUST NOT replace its decision. Each Router MUST record its own outcome, including a denial that prevents the call from reaching later Routers.

##### RTR-46 Policy coverage

*Extended; L3-08*

The deployment MUST identify which policies each Router enforces and ensure each required policy is enforced on every path it covers; merely placing a Router somewhere on the path does not establish policy coverage. Organization-wide rules SHOULD be enforced on paths used by all agents, including unregistered agents and those owned by other teams. Agent-specific rules MAY run near that agent.

##### RTR-47 Host compromise

*Extended; L3-08*

If host operators can disable controls on the agent's machine, every protected path to a tool MUST cross a Router they cannot modify. That independently administered Router MUST enforce every rule that has to survive host compromise, including authority limits, revocation, and limits on destructive operations. Local file and shell tools might have no network path through such a Router; a deployment requiring this protection MUST route those calls through an independent Router or explicitly exclude them from its coverage claim. A local Router MAY still enforce additional agent-specific rules.

#### 2.1.10 Dependencies

The Router needs trusted keys, revocation data, routing information, policy decisions, and state to handle a call.

##### RTR-48 Freshness bounds

*Core; L2-11, L3-04*

Deployments MAY reduce live dependencies by supplying inputs before they are needed ([Section 1.1](#11-components-and-flow)), but preloaded data can become stale, so the deployment MUST declare a freshness bound for each source, such as token lifetime, configuration expiry, or the allowed revocation delay.

##### RTR-49 Dependency failure

*Core*

When a dependency is unavailable, the Router MUST behave as in [Section 3.9](#39-dependency-behavior). Deployments needing continued service MUST make the relevant dependency as available as the Router, for example by running the policy engine locally, pushing revocation data, or delivering configuration ahead of time. An in-process policy engine also removes the need to authenticate and protect messages over a Router-to-engine network connection (RTR-25).

#### 2.1.11 Audit

##### RTR-50 Decision records

*Core; CC-01, CC-02*

The Router MUST create one decision record ([Section 3.6](#36-decision-record)) per decision for calls that pass through it, including refusals made before the policy engine is consulted, such as a revoked token. The records link a dispatched call to the decision that permitted it, show whether the dispatched operation and arguments matched those evaluated, and support attribution across the Bridge, Router, provider adapter, and tool.

##### RTR-51 Audit data minimization

*Core; CC-06, CC-07*

The Router MUST NOT record raw tokens, private keys, downstream credentials, or other secrets. Arguments and other request content can be sensitive, so the Router MUST record them only when the deployment requires them. Retention rules apply to all stored data.

##### RTR-52 Record correlation

*Core; CC-01*

The Bridge records its grant, the Router its decision, the provider adapter the final credential exchange, and the tool can record execution. The exchange and decision records SHOULD share the `evaluation_id`. Each Router on a path MUST record its own decision; the `request_trace_id` correlates those records.

##### RTR-53 Audit write rule

*Core; CC-01*

Audit records MUST NOT be used as policy inputs, and logging settings MUST NOT change authority. The deployment MUST declare whether a durable record is required before irreversible effects (RTR-64). Where it is not, the Router MAY proceed when a write fails and MUST report the recording gap.

### 2.2 Optional

#### 2.2.1 Obligations

An obligation is a condition attached to a permit ([Section 3.5](#35-obligation)). Its stage determines whether the Router can dispatch the call, release its result, or commit to follow-up work.

##### RTR-54 Obligation support

*no profile; §6.4*

Obligation support is optional. An obligation the Router does not support or cannot meet makes the permit unenforceable (RTR-20), so a Router without obligation support denies any permit carrying one; an engine can instead deny with guidance about a later request (RTR-21). A Router that supports obligations MUST fulfill all obligations on a permit. Each obligation MUST identify its definition by URL and version, its stage, and any parameters; a bare name such as `redact` is insufficient because its meaning can differ between deployments. The deployment MUST publish the supported definitions, versions, and the component responsible for each.

##### RTR-55 Before the call

*no profile; L2-02*

The Router MUST hold the call until the condition is met. For approval, it MAY wait or return a pending status for a later retry. An approval MUST be bound to the exact evaluated call; it MUST NOT authorize, for example, a larger payment or another invoice. An approval does not extend the decision's validity: if the decision has expired, the Router MUST obtain a fresh decision before dispatch, with the approval presented as met, and repeat its current-state checks, including revocation (RTR-42).

##### RTR-56 Before result release

*no profile*

The call proceeds, but the Router MUST withhold the result until the condition is met, such as removing a bank account field. If fulfillment fails, the result MUST NOT be released. Conditions meant to prevent the action MUST be staged before the call, since dispatch cannot be undone.

##### RTR-57 After the call

*no profile*

The Router MUST perform the follow-up work, such as notification or retention. Before dispatch, it MUST secure a durable commitment to that work, for example in a queue that survives a restart; if it cannot, the call MUST be denied.

#### 2.2.2 Discovery

Tool lists shape what an agent can attempt and reveal what a deployment offers. These requirements apply when discovery passes through the Router.

##### RTR-58 Authority filtering

*Extended; L3-01*

The Router MUST verify the caller's token before answering a list request and MUST record the request, so invalid callers receive no tool inventory and requests remain attributable. Before release, the Router MUST filter the list to tools the agent could plausibly use, using verified Bridge authority, the tools permitted in the agent's registration, and each tool's resolved identity, which reduces fruitless attempts and disclosure of the tool inventory; aliases for the same tool MUST receive the same treatment. Filtering is necessarily coarse: a later decision can depend on arguments, such as a payment amount, that are absent from the list request, so a listed tool can still be denied when called. Filtering a discovery list is not enforcement: a call to a tool the agent was not shown is evaluated like any other.

##### RTR-59 Tool descriptions

*Extended; L3-01*

Descriptions often come from the tools and can be inaccurate, stale, or written to redirect the model. The Router MAY confirm that a description came from the resolved tool but MUST NOT treat its content as verified. Inspecting descriptions for misleading instructions is content inspection, outside this document's scope; deployments can add it.

##### RTR-60 List updates

*Extended; L3-01*

The Router MUST update the offered list when authority changes through renewal or revocation, or when tools are added or removed. Where the protocol supports change notifications, the Router MUST use them to prompt the agent to fetch the list again.

#### 2.2.3 Other capabilities

##### RTR-61 Load protection

*no profile*

Load protection guards against floods and runaway loops. It MAY run before token verification, where it can protect verification and policy-engine capacity; the deployment chooses where to place it. It MUST count every request, including denials, and MUST use only information available at that point, such as network address, connection, or client certificate. Using an unverified claimed identity would let forged traffic exhaust another agent's allowance.

##### RTR-62 Request extensions

*no profile; §6.4*

A deployment MAY add its own fields to the policy request as extensions, each with a versioned definition. A policy engine MUST ignore extensions it does not use, unless the policy input declaration says the decision depends on them.

##### RTR-63 Router-initiated revocation

*no profile; L3-04*

Within its own authority, the Router MAY block an agent, session, or delegation locally when a policy calls for it, for example after detecting misuse, and MAY revoke downstream credentials it obtained itself. Anything broader, such as revoking an agent's credentials or a principal's session, belongs to the party that issued them; the Router MUST report to that party rather than revoking directly.

##### RTR-64 Durable record before irreversible effects

*Safety; CC-01*

Where the deployment requires durable records (RTR-53), the component performing an effect that cannot be undone, such as dispatching the call, obtaining or minting a downstream credential, sending an approval request or notification, or revoking within its own authority (RTR-63), MUST commit a record before the effect, MUST NOT perform the effect if that write fails, and MUST record the outcome afterward. A record without an outcome means the effect might have happened. Deployments claiming the strictest ODIS profile, which already requires tamper-evident logs, SHOULD adopt this behavior.

##### RTR-65 Record integrity

*Safety; CC-01*

Deployments needing strong assurance MUST make later alteration or deletion of records detectable, by hash-chaining records or an equivalent append-only log, and MUST store them beyond the agent host operator's control. A signed policy response MAY be retained as decision evidence.

##### RTR-66 Argument binding

*no profile; L2-13*

A deployment MAY configure the Router to set an argument from a verified attribute, overriding any value the agent supplied, such as a tool's `on_behalf_of` from the verified principal, or to normalize an argument to the tool's declared schema by a declared, deterministic rule. Binding MUST run before evaluation, so the policy request and dispatch both use the bound call, MUST NOT change the operation or add arguments other than bound ones, and MUST be recorded in the decision record. Selecting the service or instance that handles the call is target resolution (RTR-12, RTR-13), not binding.

## 3. Schemas and reference tables

Field names are provisional.

### 3.1 Policy request

The request groups inputs by policy concern:

- **Agent:** identity, running instance, owner, and policy profile.
- **Principal:** the person or service represented, plus declared attributes such as roles or department.
- **Authority:** actions, resources, and constraints remaining after all delegation limits, as recorded by the Bridge.
- **Scope:** the task and, once defined by ODIS, the session.
- **Target:** the resolved operation, resources, and target attributes.
- **Environment:** current conditions, including risk signals labeled by verification status.

"When declared" fields appear only if the policy input declaration ([Section 3.3](#33-policy-input-declaration)) requests them.

| Field | Required | Description |
|---|---|---|
| `schema_version` | Yes | Request format version |
| `evaluation_id` | Yes | Router-assigned unique decision ID, copied in the response |
| `request_trace_id` | Yes | Cross-component log correlation; never identity or authority evidence |
| `request_timestamp` | Yes | Router receipt time; never agent-supplied |
| **agent** | | |
| `agent.agent_id` | Yes | Agent resolved through registration |
| `agent.runtime_instance_id` | Yes | Running agent instance |
| `agent.registration_record_ref` | Yes | Checked registration version |
| `agent.policy_profile_ref` | Yes | Assigned policy profile |
| `agent.owner_ref` | Recommended | Owning team, application, or business unit |
| `agent.software_hash` | When declared | Running software digest |
| **principal** | | |
| `principal.id` | Yes | Person or service the agent represents |
| `principal.type` | Yes | `human` or `service` |
| `principal.authentication_context` | When declared | How and when the principal signed in |
| `principal.attributes` | When declared | Facts about the principal, such as roles, groups or department, each with its source and whether it was verified. The declaration names which attributes are sent |
| **authority** | | |
| `authority.delegation_id`, `authority.issuer` | Yes | Delegation ID and issuing Bridge |
| `authority.actions` | Yes | Allowed actions after all limits |
| `authority.resources` | Yes | Allowed resources after all limits |
| `authority.constraints` | Yes | Applicable conditions, such as a payment limit |
| `authority.expires_at` | Yes | Earliest applicable expiry |
| `authority.attenuation_profile_ref` | Yes | Interpretation of actions, resources, and constraints |
| `authority.delegation_depth` | Recommended | Number of delegation steps from the principal |
| `authority.delegation_chain` | When declared | The full history of how authority was passed on |
| **scope** | | |
| `scope.task_id` | Yes | Task containing the call |
| `scope.session_id` | Once defined | Session containing the call |
| `scope.task_description` | When declared | Readable task description |
| **target** | | |
| `target.operation_kind` | Yes | Kind of operation defined by the binding, such as tool invocation, resource read, or prompt fetch |
| `target.called_tool` | Yes | Caller-visible tool name |
| `target.namespace` | If used | Gateway namespace or virtual server |
| `target.upstream_server` | Yes | Server handling the call |
| `target.upstream_tool` | If applicable | Tool on that server |
| `target.operation` | Yes | Operation within the tool or service |
| `target.resources` | Yes | Every affected resource; never a wildcard |
| `target.attributes` | Optional | Target facts with source and verification status |
| `target.arguments` | When declared | Requested arguments |
| **environment** | | |
| `environment.runtime_risk_signals` | Optional | Risk signals, each with its source and whether it was verified |

Deployments can add fields as extensions (RTR-62).

### 3.2 Labeled values

Principal attributes, target attributes, and risk signals carry each fact as an object with `value`, `source`, and `verified` ([Section 4.2](#42-policy-request)). Target attributes should also record observation time and validity period (RTR-15).

### 3.3 Policy input declaration

The deployment publishes one declaration per policy engine (RTR-17). It names:

- the optional fields the engine receives;
- the argument paths it receives, such as `amount` or `payment.currency`, which let the Router select individual arguments;
- the source of each; and
- the verification status each requires.

### 3.4 Policy response

| Outcome | Meaning |
|---|---|
| `permit` | The call can proceed if the Router can enforce every condition. |
| `deny` | An applicable policy refused the call. |
| `not_applicable` | No policy covered the call. |
| `indeterminate` | Evaluation failed or a required source was unavailable. |

| Field | Required | Description |
|---|---|---|
| `evaluation_id` | Yes | Copied from the request to bind the response to one evaluation |
| `decision` | Yes | `permit`, `deny`, `not_applicable` or `indeterminate` |
| `issued_at`, `expires_at` | Yes | Decision issue and expiry times |
| `reason` | Recommended | Decision reason, distinguishing refusal from failure |
| `obligations` | Optional | Conditions attached to a permit ([Section 3.5](#35-obligation)) |
| `advice` | Optional | Nonbinding information, such as an audit note or operator warning |
| `context` | Optional | Caller guidance for a later request |

### 3.5 Obligation

| Field | Description |
|---|---|
| `id` | URL identifying the obligation definition |
| `version` | Definition version |
| `stage` | `before_dispatch`, `before_release`, or `after_call` (RTR-55 to RTR-57) |
| `params` | Parameters the definition takes |

### 3.6 Decision record

One per decision (RTR-50). Each includes the following. If the Router denies before verifying identity or resolving the target, fields it could not establish are omitted; any unverified claims it retains are labeled as such:

- the `evaluation_id`, `request_trace_id`, receipt time, and decision time;
- the agent, running instance, and software digest, which supports later attribution of actions to a particular software version;
- the principal, original delegation, and task;
- the caller-visible name, resolved tool, and affected resources;
- the policy request evaluated, with arguments only where the deployment requires them (RTR-51), any arguments bound and their sources (RTR-66), and the response;
- the overall decision and reason, plus each consulted source's decision;
- obligations and whether each was met;
- whether the call was dispatched and, if not, where it stopped; and
- a reference to any downstream credential used, never the credential itself.

### 3.7 Authority-limit keys

| Key | Scope and constraint |
|---|---|
| Agent | One agent; sub-agents receive separate allowances. |
| Original delegation | All work under a grant, including sub-agents; the Bridge token carries this identifier so fan-out cannot multiply the limit. |
| Principal | Work done for one person or service across agents. |
| Task | One task; sub-agents can have different task IDs, so the original delegation is more reliable for shared work. |
| Session | One run of activity, once ODIS defines sessions. |
| Tool or operation | The resolved target, shared by all aliases for it. |

### 3.8 Revocation levels

| Level | Scope and Router action |
|---|---|
| Decision | Cancel one permit before dispatch; a retry requires a new decision. |
| Token or delegation | Reject later calls under that grant and discard derived downstream credentials. |
| Session | Reject later calls in that session. |
| Agent | Reject the agent's tokens across all tasks and sessions, including derived credentials. |
| Principal | Reject tokens naming the principal across all agents acting for them. |

### 3.9 Dependency behavior

| Dependency | Delivery | If unavailable |
|---|---|---|
| Trusted Bridge keys | Locally held and refreshed | Reject tokens whose signing keys cannot be confirmed. |
| Revocation data | Pushed events or fetched lists | Stop affected calls once cached data exceeds the declared delay. |
| Routing and target facts | Signed bundles | Use the last valid configuration until it expires; deny calls that cannot be resolved. |
| Policy engine | Local or separate service | Stop calls; no decision can be made. |
| Rate-limit counters | State shared by Router instances | Stop calls subject to authority limits. |
| Downstream credential issuer | Identity provider reached by the adapter | Stop calls needing a new credential; reuse a cached one only within its limits and after a separate permit. |
| Audit store | Local buffer or central store | Follow the deployment's declared rule: stop calls or report a recording gap (RTR-53). |

## 4. Examples

### 4.1 Invoice payment

Alice, who works in finance, authorizes an agent to reconcile quarterly invoices and pay invoices up to USD 1,000. The Bridge issues a token naming Alice, the task, and the limit, and binds it to the agent's private key.

The agent requests `invoices.pay` through a gateway tool named `finance__erp`, with `invoice_id` 4411, `amount` 250, and `currency` USD. The gateway name is an alias for a payment tool on the company's ERP server; the name alone does not identify the actual target.

1. **Receive.** The Router retains the call as received, records the time, and assigns a decision identifier. Later steps refer to the retained request.
2. **Verify.** The Router checks the Bridge token's trusted issuer, expiry, revocation status, and proof of possession. It obtains the agent identity, Alice, the task, and the USD 1,000 limit from the token.
3. **Resolve.** Trusted routing configuration maps `finance__erp` to the ERP payment tool and interprets `invoice_id` 4411 as the affected invoice. A trusted registry can add target attributes such as owner and data sensitivity. The agent supplies the name and arguments; the Router determines their meaning.
4. **Request a decision.** The Router supplies the policy engine with the agent, principal, task, authority, resolved target and invoice, amount, and currency ([Section 4.2](#42-policy-request)). It sends only the inputs the policy requires, never the agent's tokens or keys.
5. **Validate the decision.** Under the example policy, USD 250 is within Alice's limit, so the engine returns a permit ([Section 4.3](#43-permit)). The Router checks that the response matches this decision and remains fresh.
6. **Enforce.** Any decision the Router cannot fully enforce prevents dispatch. A condition such as manager approval holds the call until satisfied. Because the ERP server does not accept Bridge tokens, the Router checks revocation and the Bridge's ERP adapter obtains a credential limited to this payment. Immediately before dispatch, the Router checks revocation again, because authority might have been withdrawn while the call was held. The Router attaches the credential, without exposing it to the agent or changing the evaluated operation and arguments, and sends the retained call to the ERP tool.
7. **Record.** The Router writes an audit record linking the agent, Alice, the task, the decision, and the dispatched call.

### 4.2 Policy request

The payment in [Section 4.1](#41-invoice-payment) produces a request such as this, with required fields and the finance policy's declared optional inputs:

```json
{
  "schema_version": "1",
  "evaluation_id": "ev_7f3c9a",
  "request_trace_id": "tr_51b2e0",
  "request_timestamp": "2026-09-30T14:02:11Z",
  "agent": {
    "agent_id": "agents/invoice-reconciler",
    "runtime_instance_id": "ri_04d1",
    "registration_record_ref": "registry.example.com/reg_19@7",
    "policy_profile_ref": "profiles/finance-agents",
    "owner_ref": "teams/finance-ops"
  },
  "principal": {
    "id": "users/alice",
    "type": "human",
    "attributes": {
      "roles": { "value": ["finance-clerk"], "source": "https://idp.example.com", "verified": true }
    }
  },
  "authority": {
    "delegation_id": "dl_88a0",
    "issuer": "https://bridge.example.com",
    "actions": ["invoices:read", "invoices:pay"],
    "resources": ["https://erp.example.com"],
    "constraints": { "max_amount": 1000, "currency": "USD" },
    "expires_at": "2026-09-30T14:30:00Z",
    "attenuation_profile_ref": "https://example.com/profiles/finance/v1",
    "delegation_depth": 1
  },
  "scope": { "task_id": "task_reconcile_q3" },
  "target": {
    "operation_kind": "invoke",
    "called_tool": "finance__erp",
    "namespace": "vs/finance-tools",
    "upstream_server": "https://erp.example.com/mcp",
    "upstream_tool": "erp",
    "operation": "invoices.pay",
    "resources": ["https://erp.example.com/invoices/4411"],
    "attributes": {
      "classification": { "value": "confidential", "source": "https://registry.example.com", "verified": true }
    },
    "arguments": { "amount": 250, "currency": "USD" }
  }
}
```

The declaration selects amount, currency, and Alice's roles. Invoice 4411 appears as a resolved resource rather than a raw argument.

### 4.3 Permit

Permit for the request in [Section 4.2](#42-policy-request):

```json
{
  "evaluation_id": "ev_7f3c9a",
  "decision": "permit",
  "issued_at": "2026-09-30T14:02:11Z",
  "expires_at": "2026-09-30T14:02:41Z",
  "reason": { "code": "within_payment_limit" }
}
```

### 4.4 Denial with guidance

Denial with guidance for a USD 5,000 payment:

```json
{
  "evaluation_id": "ev_8a21d0",
  "decision": "deny",
  "issued_at": "2026-09-30T14:05:40Z",
  "expires_at": "2026-09-30T14:06:10Z",
  "reason": { "code": "over_payment_limit" },
  "context": { "message": "Payments over 1,000 USD need a finance manager's approval. Request approval and retry." }
}
```

### 4.5 Permit with obligations

A permit for the USD 250 payment, requiring removal of the bank account field and notification to finance:

```json
{
  "evaluation_id": "ev_7f3c9a",
  "decision": "permit",
  "issued_at": "2026-09-30T14:02:11Z",
  "expires_at": "2026-09-30T14:02:41Z",
  "obligations": [
    {
      "id": "https://example.com/obligations/remove-fields",
      "version": "1",
      "stage": "before_release",
      "params": { "fields": ["bank_account"] }
    },
    {
      "id": "https://example.com/obligations/notify",
      "version": "1",
      "stage": "after_call",
      "params": { "channel": "finance-payments" }
    }
  ]
}
```

### 4.6 Variations

- A USD 5,000 payment exceeds the limit and is denied before reaching the ERP server ([Section 4.4](#44-denial-with-guidance)).
- If withdrawal of Alice's authority has revoked the token, verification stops the call before policy evaluation.
- Another alias for the same payment tool resolves to the same target and policy. A gateway can expose the payment tool as `finance__erp` or `erp_payments`, while unrelated servers can each offer a tool named `search`; policy based on a caller-visible name could miss an alias or conflate different tools.
- For a web API, resolution uses the request method, address, and relevant fields; the remaining steps are the same.
- The downstream credential for the payment should not permit vendor administration or ledger access.
- Ten payments per hour and USD 5,000 per hour constrain different risks.

## 5. Open questions

References identify the affected requirements or ODIS issues.

- **Result governance:** The Router can enforce conditions on a result before releasing it, such as removing a field (RTR-56), but ODIS has not yet defined general result governance. An authorized call can return excessive data or instructions intended to redirect the agent. Deciding which results require inspection, and how, overlaps with content inspection. Should the Router's responsibilities extend to results generally?
- **Sessions:** Sessions are referred to where they matter but are not yet defined by ODIS. What defines a session, how is it identified for limits, revocation, and audit, and what does terminating one involve (L3-04)? ([Section 3.7](#37-authority-limit-keys), [Section 3.8](#38-revocation-levels), RTR-50; #25)
- **Client application identity:** A coding assistant or similar application can sign in separately from the agent and principal. Should its identity appear in the policy request, marked unverified until ODIS defines a check? (Section 3.1; #13)
- **Sandbox identity:** Should a sandbox and the agents or sub-agents it hosts have separate identities? Which identity does the Router verify? (RTR-04)
- **Default arguments:** Should a minimum set of call arguments always reach the policy engine, rather than only those declared by a policy? (RTR-18)
- **Delegation history:** The field table recommends delegation depth and sends the full chain only when declared. Should depth or organizational hops be required by default? (Section 3.1)
- **Common obligations:** Should ODIS define common obligation types with fixed handling for approval, field removal, and notification, while leaving their details to deployments? This could make policies portable without standardizing a full vocabulary. ODIS does not currently define a standard list. (RTR-54)
- **Policy-engine chaining:** The Router stops on a final `not_applicable` response. Is it acceptable for deployments to finish chaining engines before returning one response to the Router? (RTR-19)
- **Decisions across Routers:** May one Router pass a signed decision to another instead of each deciding independently? How would the decision be protected and bound to the call? (RTR-45)
- **Evaluation coverage:** Must every call pass through a Router? Within a Router every call is decided (RTR-20), but no current ODIS profile requires a Router on every path: L3-02 is a SHOULD in Extended. (#23)
- **Credential issuer:** Does the Passport (PR #39) or a Verifier in the Bridge (PR #40) appraise evidence against the registration record and issue the Agent Runtime Credential? The Router input is unchanged either way. (RTR-07, RTR-08; #33)
- **Profile tags:** The profile tags in Section 2 are provisional. Which requirements belong in Core, Extended, and Safety?

## Glossary

**Advice.** Nonbinding information returned by a policy engine. The Router can ignore it without stopping a call.

**Agent.** Software that uses an AI model to call tools and services on a principal's behalf.

**Authority limit.** A cap on delegated activity, such as payments per hour, counted against verified attributes. Compare load protection.

**Bridge.** The ODIS layer that records who an agent acts for and what authority it holds, and carries that authority to downstream systems.

**Binding.** Protocol-specific rules that map calls to policy actions and resources and identify arguments relevant to a decision.

**Bridge token.** The Bridge's signed token for the Router, defined in the Passport RFC (BRG-14).

**Claim.** A statement in a token, such as an agent identity or permission.

**Cleared for dispatch.** An evaluated call that every required decision source has permitted (RTR-44) and whose before-dispatch obligations are met (RTR-55).

**Decision identifier.** The Router's unique `evaluation_id` for one policy evaluation, echoed in its response.

**Decision source.** A policy engine, rate-limit service, or other check consulted by the Router. Any source can stop a call or add conditions.

**Delegation.** A grant of authority from a principal to an agent, or from one agent to another. The original delegation is the first grant in a chain, from the principal.

**Dispatch.** Sending the evaluated call to the tool. Nothing reaches the tool before dispatch.

**Downstream credential.** A credential accepted by a tool, obtained or applied after a permit and never given to the agent.

**Enforceable permit.** A `permit` that matches the pending evaluation, is within its validity period and unused, and carries only obligations the Router supports and can meet.

**Evaluated call.** The call as the Router received and retained it, after any argument binding (RTR-66), from which the policy request is derived and which dispatch must match: operation, arguments, resolved target, and route.

**Gateway.** A component that offers tools from several servers under its own names. The Router often runs within it.

**Kill switch.** Agent-level revocation that invalidates the agent's tokens across tasks and sessions and discards derived credentials (ODIS-L3-05).

**Load protection.** An early limit that counts every request against observable attributes such as network address or connection. Compare authority limit.

**Namespace.** A named group of tools within a gateway, such as a virtual server, that can be offered to different agents.

**Native-mode target.** A tool that understands ODIS tokens and checks them itself (ODIS-L2-15).

**Obligation.** A condition attached to a permit, with a stage at which it must be met, such as approval before dispatch.

**Agent Runtime Credential.** Defined in [ODIS §6.2](../ODIS.md#62-agent-runtime-credential-descriptor).

**Passport.** The ODIS layer that establishes an agent's software and running instance.

**Policy engine.** The component that applies an organization's rules to a call and returns a decision.

**Policy input declaration.** A published list, per engine, of optional fields and argument paths it receives, their sources, and required verification levels.

**Principal.** The person or service an agent is working for.

**Proof of possession.** Evidence that the caller controls the private key tied to a token; a copied token alone is insufficient.

**Provider adapter.** The Bridge component that obtains a tool credential from Bridge-recorded authority ([ODIS §3.2](../ODIS.md#32-layer-2--the-bridge-delegation--access)).

**Registration record.** An organization's record of an agent: its owner, the software it is approved to run, and the rules that apply to it ([ODIS §6.1](../ODIS.md#61-agent-registration-record)).

**Resource.** The data a call reads or changes, identified by URI, such as a record, file, or collection. Not the server or tool that handles the call, and not the MCP operation of the same name. Granted authority (`authority.resources`) can name a broader resource that contains it.

**Resolved target.** The actual server, operation, and resources determined by the Router, including the tool when applicable.

**Revocation.** Ending trust in a token, delegation, session, agent or principal before its lifetime runs out.

**Router.** The ODIS layer that verifies calls, resolves targets, obtains policy decisions, and enforces them on the path to tools.

**Token.** A signed set of claims issued by one party and checked by another.

**Trace identifier.** An identifier that follows a request across every component that handles it, used to join their logs. It does not distinguish separate decisions about the same request.

**Trust domain.** Systems under one administrative authority that trust the same issuers, often but not always one organization.

**Unverified input.** A value the Router passes to the policy engine without having established it, such as an agent's stated reason for a call or a tool's self-description, marked so the engine can weigh it.

**Verified attribute.** A value the Router takes from a verified Bridge token, the resolved target, or its own records, never from the agent's request.

**Verify.** Check a token's trusted issuer, expiry, revocation status, and proof that the presenter holds its bound key.