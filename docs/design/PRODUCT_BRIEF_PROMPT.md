# SecureOTA — Product Brief Prompt (for building the UI with your design system)

Paste the block below into Claude / Claude Design **together with your design system**
(your DESIGN.md / tokens) and the `UI_STRUCTURE_AND_COMPONENTS.md` file. It tells the model
who the product is for and why it exists, so what gets built serves the real users — while
your design system supplies the look.

---

## PROMPT — copy from here ↓

You are a senior product designer and front-end engineer. Build the web UI/UX for
**SecureOTA** using the design system I am providing (apply its tokens, type, and visual
language exactly — do not invent a new aesthetic). Use the attached structure/component
spec for the screens, components, states, and data. Build the product for the users and
needs described below, not as a generic dashboard.

### The business idea
SecureOTA is a platform for delivering **cryptographically secure over-the-air firmware
updates** to fleets of IoT / ESP32 devices. It closes the gap between "I wrote new
firmware" and "every device in the field is safely running it" — with signing,
verification, per-architecture targeting, health-gated rollout, and an auditable trail.
The promise: **update the fleet without bricking devices or trusting an unsigned binary.**

### The problem / market need
Shipping firmware to physical devices is high-stakes and under-served:
- A bad update can **brick a device** that is physically unreachable — recovery means a
  truck roll or a USB cable, which doesn't scale.
- Most hobby/DIY OTA setups push **unsigned** binaries over plain HTTP — anyone on the
  path can inject malicious firmware.
- Fleets are **heterogeneous** (ESP32, ESP8266, other MCUs); one binary does not fit all,
  and pushing the wrong architecture is a silent failure.
- Teams lack **visibility**: which devices updated, which failed, which are quarantined,
  and proof that what shipped is what was signed.
The market need is a trustworthy, observable OTA control plane that treats the update as a
security event, not a file copy — usable by small teams and students, not just large IoT
vendors with bespoke infrastructure.

### Target audience (design for these people)
1. **Firmware / embedded engineer (primary).** Writes the code, needs to flash a board
   over USB during development and push OTA to test devices. Cares about: fast serial
   flashing, clear compile/upload logs, knowing a device actually took the update.
2. **Fleet / DevOps operator.** Manages many deployed devices. Cares about: fleet health
   at a glance, safe staged rollout, rollback safety, an audit trail, and never exposing
   hardware or the network without explicit consent.
3. **Security-conscious lead / reviewer.** Cares about: signed manifests, verified
   binaries, key management, who authorized what, and no silent "success" claims.
4. **Student / small-team maker (accessible tier).** Wants the secure workflow without
   standing up heavy infrastructure — a clean, guided UI that explains each step.

### Jobs to be done (what users come to do)
- "Flash this board on my desk over USB, safely, and see it worked."
- "Publish a signed firmware release and roll it out to compatible devices only."
- "See which devices are online, on what version, and which need updating."
- "Grant — and revoke — this app's access to a COM port or my local network, on purpose."
- "Prove that what shipped matches what was signed, and see who authorized it."
- "Know immediately when an update fails or a device is quarantined."

### Product principles the UI must express
- **Trust is the product.** Signing, verification, and consent must be visible, not
  buried. Risky actions (touch hardware, push firmware) feel deliberate and auditable.
- **The device is the source of truth.** Never show optimistic success; reflect real
  device heartbeats and evidence.
- **Consent before capability.** COM ports and the local network are locked until the
  operator grants access; grants expire and are shown.
- **Guide the novice, don't slow the expert.** Clear empty states and next steps for
  newcomers; fast, keyboard-friendly paths for daily operators.
- **Fast and honest.** Responsive under real fleet data; errors state the cause and the
  exact next step.

### Success criteria (what "good" looks like)
- A new user can go **login → grant access → flash a board (or publish OTA) → see it
  confirmed** without reading docs.
- Every screen answers "what's the state, what do I do next, and can I trust it?"
- The security story (signed, verified, who authorized) is legible to a non-expert.
- It feels like a professional security/monitoring tool, on-brand with the provided
  design system, and fast.

### Your task
Design and build the full UI for the routes and components in the attached structure spec,
applying my design system. Deliver responsive (mobile / laptop / wide), theme-aware
(light + dark), accessible screens, with the states each component needs (loading / empty
/ error / permission-denied / success). Show how the core journey connects: **login →
dashboard → host-access grant → serial flash or OTA publish → confirmed update.**

## PROMPT — copy to here ↑

---

## Notes for you (not part of the prompt)

- Attach three things in the same message: **(1) your design system**, **(2)
  `UI_STRUCTURE_AND_COMPONENTS.md`**, **(3) this prompt.** The design system drives the
  look; the structure file drives the build; this prompt drives *who it's for*.
- This brief is deliberately about **users, business, and market** — not visuals — because
  your design system already answers the visual question. That division keeps the model
  from re-inventing your aesthetic.
- If you want a sharper pitch (e.g., a specific vertical like smart-agriculture sensors or
  industrial gateways), tell me the vertical and I'll tighten the audience + jobs sections
  to it.
