# Equilibrium — A Threshold Law for Security Economics

**Live demo:** _add your GitHub Pages URL here after deployment_
**Built for:** Moonshot Hackathon 2026

---

## The problem

Security spending is decided by guesswork. Companies patch "everything, eventually." Bug bounty programs pick payout numbers by gut feel. Nobody can say *why* an attack happened, only that it did. There is no calculable, falsifiable theory of when an attack becomes rational — only intuition dressed up as best practice.

## The core idea — the Threshold Law

Every attacker, rational or not, is implicitly running one comparison:

```
effective cost to attack  <  expected gain from attacking
```

When cost is lower than gain, attack is rational. When cost exceeds gain, it isn't. That's it. That single inequality — call it **Θ** — is the unifying law underneath three things that look like separate problems:

| Scenario | What it actually does to Θ |
|---|---|
| **Patch timing** | Lowers expected gain (reduces residual risk) |
| **Bug bounty pricing** | Raises effective attacker cost directly |
| **Resource allocation** | Spreads a fixed budget to push as many systems as possible across Θ at once |

This is a **falsifiable claim**: real-world exploitation rates should show a sharp transition near Θ, not a smooth gradient, because rational attackers behave like a step function, not a dial. `validate.js` tests exactly this against two live, free, public datasets.

## Extension 1 — Repeated games

The static model answers "what's optimal right now." Real attackers learn. `simulateRepeatedGame()` models an attacker updating their belief about your defenses after each probe, using a Bayesian-flavored update rule. The web app's "Repeated Game" panel lets you run this live and watch the threat escalate or fade over 12 rounds.

## Extension 2 — Ransomware payment policy

A different, harder question: once an attack has already succeeded, should the victim pay? This is a live, contested real-world policy debate (several governments and insurers have proposed banning ransom payments outright). The model adds a financing feedback loop — **ransom paid this round funds attacker capability next round** — which is what makes paying individually rational but collectively self-defeating.

Running the comparison with realistic defaults produces a genuinely non-obvious result: **banning payments makes total victim harm worse for the first ~17 rounds, then crosses over and becomes net-beneficial from round 18 onward.** This wasn't designed in — it emerged from testing, and an earlier version of the model had a bug where the ban did nothing at all (documented in commit history / build process).

## What's in this repo

| File | What it is |
|---|---|
| `index.html` | The interactive web app — sliders, live charts, all three scenarios, the Threshold Law view, the repeated game, and the ransomware policy comparison. Pure client-side JS, no backend, works on any phone browser. |
| `engine.js` | The core math, as a standalone Node module. Same logic as `index.html`, structured for the API server and for direct testing. |
| `server.js` | A zero-dependency REST API (Node's built-in `http` only — no `npm install` required) exposing every model as an endpoint. Run with `node server.js`. |
| `validate.js` | Tests the Threshold Law's falsifiable claim against two real, live, public datasets: [FIRST.org EPSS](https://www.first.org/epss/) (exploitation probability scores) and [CISA's Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (ground truth of confirmed exploits). No API key needed. Run with `node validate.js` on any machine with internet. |
| `selftest.js` | Proves the analysis logic in `validate.js` is correct, using synthetic data with known ground-truth shapes — run this first, before trusting results against real data. No internet required. Run with `node selftest.js`. |

## Running it yourself

**Web app:** just open `index.html` in any browser, or visit the live demo link above.

**API server** (no setup, no dependencies):
```bash
node server.js
curl http://localhost:3000/scenarios
```

**Validation against real data:**
```bash
node selftest.js    # verify the analysis logic first (offline)
node validate.js    # then test against real EPSS/KEV data (needs internet)
```

## Honest limitations

This is a first-order model, and the paper is explicit about where it breaks down:

- The repeated-game belief update is a simplified heuristic, not a full POMDP solution — it captures the *direction* of belief drift correctly, not exact convergence rates.
- The ransomware financing feedback loop uses a simplified linear model. Real attacker reinvestment (tooling, affiliate recruitment, infrastructure) is more complex.
- `validate.js` tests a **proxy relationship** (EPSS score vs. KEV membership), not a direct measurement of the engine's exact cost/gain parameters, which aren't publicly measurable at CVE-level granularity.
- The ransomware model's "rounds" aren't calibrated to real time units — that would require real incident data we didn't have time to source this week.

We think stating these limitations clearly is more credible than hiding them, not less.

## Philosophy

Most security tools tell you *what's vulnerable*. This tells you *why an attack is or isn't economically rational*, and what would need to change to flip that. It's not a better scanner — it's a different question entirely.
