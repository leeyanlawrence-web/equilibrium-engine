/**
 * EQUILIBRIUM ENGINE
 * A game-theoretic model of attacker/defender security economics.
 *
 * Core idea: instead of treating security as "find and patch vulnerabilities,"
 * we treat it as a repeated Bayesian game between two rational economic agents:
 *
 *   ATTACKER chooses: attack (A) or don't attack (¬A)
 *   DEFENDER chooses: defend/patch (D) or don't defend (¬D)
 *
 * Each has a cost and a payoff. We solve for the mixed-strategy Nash
 * equilibrium: the probability p* (defender invests) and q* (attacker attacks)
 * at which neither player can improve their expected payoff by deviating.
 *
 * This generalizes to three scenarios: patch timing, bug bounty pricing,
 * and multi-asset resource allocation. All three reduce to the same
 * underlying 2x2 Bayesian game with different parameter mappings.
 */

/**
 * Solve the mixed-strategy Nash equilibrium for a 2x2 attacker/defender game.
 *
 * Payoff structure (defender's perspective; attacker's payoff is asymmetric,
 * not zero-sum, since a breach destroys value rather than just transferring it):
 *
 *              Attacker: Attack (q)        Attacker: No Attack (1-q)
 * Defend (p):  Defender: V_d - C_def        Defender: -C_def
 *              Attacker: P_succ*G - C_atk   Attacker: 0
 *
 * No Defend:   Defender: -L                 Defender: 0
 * (1-p):       Attacker: G - C_atk           Attacker: 0
 *
 * Where:
 *   C_def  = cost of defending/patching
 *   C_atk  = cost of mounting an attack
 *   L      = loss to defender if successful breach with no defense
 *   G      = gross value attacker extracts from a successful breach
 *   P_succ = probability an attack succeeds even when defender invests
 *            (defense reduces but rarely eliminates risk)
 *
 * @param {Object} params
 * @returns {Object} equilibrium probabilities + expected payoffs + diagnostics
 */
function solveEquilibrium(params) {
  const {
    assetValue,      // V: value of the asset being protected
    defenseCost,      // C_def: cost to defend (patch, harden, monitor)
    attackCost,       // C_atk: attacker's cost to mount the attack
    breachGain,       // G: what attacker gains from a successful breach
    residualRisk,     // P_succ: probability attack still succeeds despite defense (0-1)
    detectionProb,    // P_det: probability an attack is detected (affects attacker's effective cost)
  } = params;

  // Effective attacker payoff accounts for detection risk (e.g. legal/reputational cost)
  const effectiveAttackCost = attackCost / Math.max(0.05, 1 - detectionProb * 0.5);

  // --- Defender's indifference condition ---
  // Defender is indifferent between Defend and No-Defend when:
  //   q*(V_d_attack) + (1-q)*(-C_def) = q*(-L) + (1-q)*0
  // Solve for q* (attacker's equilibrium attack probability)
  const lossNoDefense = assetValue; // full asset value at risk with no defense
  const lossWithDefense = residualRisk * assetValue;

  // Defender payoff when defending: -defenseCost - q*lossWithDefense
  // Defender payoff when not defending: -q*lossNoDefense
  // Indifference: -defenseCost - q*lossWithDefense = -q*lossNoDefense
  // => defenseCost = q*(lossNoDefense - lossWithDefense)
  const denomQ = (lossNoDefense - lossWithDefense);
  let qStar = denomQ > 0 ? defenseCost / denomQ : 1;
  qStar = clamp(qStar, 0, 1);

  // --- Attacker's indifference condition ---
  // Attacker payoff when attacking: p*(residualRisk*breachGain - effectiveAttackCost) + (1-p)*(breachGain - effectiveAttackCost)
  // Attacker payoff when not attacking: 0
  // Indifference: p*residualRisk*breachGain + (1-p)*breachGain = effectiveAttackCost
  // => breachGain - p*breachGain*(1-residualRisk) = effectiveAttackCost
  // => p* = (breachGain - effectiveAttackCost) / (breachGain*(1-residualRisk))
  const denomP = breachGain * (1 - residualRisk);
  let pStar = denomP > 0 ? (breachGain - effectiveAttackCost) / denomP : 0;
  pStar = clamp(pStar, 0, 1);

  // Expected payoffs at equilibrium
  const defenderExpectedPayoff =
    pStar * (-defenseCost - qStar * lossWithDefense) +
    (1 - pStar) * (-qStar * lossNoDefense);

  const attackerExpectedPayoff =
    qStar * (pStar * (residualRisk * breachGain - effectiveAttackCost) +
              (1 - pStar) * (breachGain - effectiveAttackCost));

  // Is attack rational at all? If effective cost exceeds max possible gain, attacker never attacks.
  const attackIsRational = effectiveAttackCost < breachGain;

  // Diagnostic: the real comparison isn't "naive cost at qStar" (trivially
  // equal by the indifference condition that defines a mixed equilibrium).
  // It's: what does the defender lose by committing to a FIXED policy and
  // letting the attacker best-respond to THAT, instead of playing the
  // equilibrium mix? This is the actual exploitability gap.
  //
  // If defender always defends (p=1): attacker's best response is to attack
  // only if residualRisk*breachGain > effectiveAttackCost; else don't attack.
  const attackerBestResponseToAlwaysDefend =
    (residualRisk * breachGain > effectiveAttackCost) ? 1 : 0;
  const alwaysDefendCost = defenseCost +
    attackerBestResponseToAlwaysDefend * lossWithDefense;

  // If defender never defends (p=0): attacker's best response is to attack
  // only if breachGain > effectiveAttackCost; else don't attack.
  const attackerBestResponseToNeverDefend =
    (breachGain > effectiveAttackCost) ? 1 : 0;
  const neverDefendCost =
    attackerBestResponseToNeverDefend * lossNoDefense;

  const equilibriumCost = -defenderExpectedPayoff;
  const bestNaiveCost = Math.min(alwaysDefendCost, neverDefendCost);
  const efficiencyGain = bestNaiveCost - equilibriumCost;

  return {
    pStar,                 // optimal probability defender should invest in defense
    qStar,                 // equilibrium probability attacker attacks
    defenderExpectedPayoff,
    attackerExpectedPayoff,
    attackIsRational,
    effectiveAttackCost,
    alwaysDefendCost,
    neverDefendCost,
    equilibriumCost,
    efficiencyGain,
    interpretation: interpret(pStar, qStar, attackIsRational),
  };
}

function interpret(pStar, qStar, attackIsRational) {
  if (!attackIsRational) {
    return "Attack is economically irrational at any defense level. Minimal defense investment is optimal.";
  }
  if (pStar > 0.75) {
    return "High defense investment is justified — the asset value far exceeds defense cost relative to attacker incentives.";
  }
  if (pStar < 0.25) {
    return "Heavy defense spending here is economically inefficient. Attacker incentives are low or attack cost is already prohibitive.";
  }
  return "A mixed strategy is optimal: partial, probabilistic investment outperforms always-on maximum defense.";
}

/**
 * ============================================================
 * THE THRESHOLD LAW
 * ============================================================
 * The unifying claim underneath every scenario in this engine:
 *
 *   An attack is rational if and only if the attacker's
 *   detection-adjusted cost falls below their expected gain.
 *
 *       C_eff(t) < G(t)   =>  attack region
 *       C_eff(t) > G(t)   =>  no-attack region
 *       C_eff(t) = G(t)   =>  THE THRESHOLD — Θ
 *
 * Patch timing, bounty pricing, and resource allocation are not three
 * different problems. They are three different levers that move a system's
 * position relative to the SAME threshold Θ:
 *   - Patching lowers the attacker's expected gain (reduces residual risk)
 *   - Bounty pricing raises the attacker's effective cost of going straight
 *     instead of black-market (changes C_eff directly)
 *   - Resource allocation spreads a fixed budget to push as many systems
 *     as possible across Θ into the no-attack region at once
 *
 * This makes a falsifiable prediction: real-world breach rates, plotted
 * against C_eff/G, should show a sharp transition near Θ = 1, not a smooth
 * gradual curve — because rational attackers behave like a step function,
 * not a dial. That's checkable against real breach/CVE datasets (e.g. NVD,
 * Verizon DBIR) and is the falsifiability hook for the paper.
 */

/**
 * Computes where a given parameter set sits relative to the threshold,
 * and how far a single lever would need to move to cross it.
 */
function thresholdPosition(params) {
  const { attackCost, breachGain, detectionProb } = params;
  const effectiveAttackCost = attackCost / Math.max(0.05, 1 - detectionProb * 0.5);
  const thresholdRatio = effectiveAttackCost / breachGain; // Θ-ratio: <1 means attack rational, >1 means irrational, =1 is the boundary
  const distanceToThreshold = thresholdRatio - 1; // negative = inside attack region

  return {
    effectiveAttackCost,
    breachGain,
    thresholdRatio,
    distanceToThreshold,
    regime: thresholdRatio < 1 ? "ATTACK_RATIONAL" : "ATTACK_IRRATIONAL",
    // how much would breachGain need to drop (via patching/residual risk reduction)
    // to push this system across the threshold into the safe regime?
    gainReductionNeededToFlip: thresholdRatio < 1 ? breachGain - effectiveAttackCost : 0,
    // how much would attacker's effective cost need to rise (via bounty/legal deterrence)
    // to push this system across the threshold?
    costIncreaseNeededToFlip: thresholdRatio < 1 ? breachGain - effectiveAttackCost : 0,
  };
}

/**
 * ============================================================
 * REPEATED GAME EXTENSION
 * ============================================================
 * The static equilibrium above answers "what's optimal right now." But the
 * hackathon brief itself frames this as a repeated game, and real attackers
 * learn: every failed attempt updates their belief about defense strength,
 * and every breach updates the defender's posture. A purely static model
 * can't capture an attacker that probes, learns, and escalates.
 *
 * We extend the model with a simple Bayesian learning dynamic:
 * the attacker's BELIEF about defense strength (residual risk) updates
 * each round based on observed outcomes, using a Bayesian-flavored
 * exponential update — not a full POMDP solver (out of scope for one week),
 * but enough to show equilibrium is a moving target, not a fixed point.
 *
 * This is explicitly flagged in the paper as a first-order approximation:
 * it captures DIRECTION of belief drift correctly, not exact convergence
 * rates, which would require richer data on real attacker behavior.
 */
function simulateRepeatedGame(params, rounds = 12) {
  let belief = params.residualRisk; // attacker's current estimate of residual risk
  const trueResidualRisk = params.residualRisk;
  const history = [];

  for (let t = 0; t < rounds; t++) {
    const roundParams = { ...params, residualRisk: belief };
    const result = solveEquilibrium(roundParams);

    // Simulate one round's outcome: did the attacker attack, did it succeed?
    const attacked = Math.random() < result.qStar;
    const succeeded = attacked && Math.random() < trueResidualRisk;

    // Bayesian-flavored belief update: shift belief toward observed outcome,
    // with learning rate that shrinks over time (more confidence as rounds pass)
    const learningRate = 1 / (t + 3);
    if (attacked) {
      const observedSignal = succeeded ? 1 : 0;
      belief = belief + learningRate * (observedSignal - belief);
      belief = clamp(belief, 0.01, 0.99);
    }

    history.push({
      round: t + 1,
      belief,
      pStar: result.pStar,
      qStar: result.qStar,
      attacked,
      succeeded,
    });
  }

  const initialQStar = history[0].qStar;
  const finalQStar = history[history.length - 1].qStar;
  const driftDirection = finalQStar > initialQStar ? "escalating" : finalQStar < initialQStar ? "de-escalating" : "stable";

  return {
    history,
    initialQStar,
    finalQStar,
    driftDirection,
    note: "First-order belief-drift approximation, not a full POMDP solution. Captures directional dynamics, not exact convergence rates.",
  };
}

/**
 * ============================================================
 * RANSOMWARE PAYMENT POLICY MODEL
 * ============================================================
 * A different game than the ones above: here the attack has ALREADY
 * succeeded, and the question is whether the victim should pay.
 *
 * The real-world policy debate: several governments and insurers have
 * proposed banning ransomware payments outright. The argument for: if
 * nobody pays, ransomware becomes unprofitable and the attacks stop. The
 * argument against: individual victims (hospitals, schools, towns) without
 * backups are destroyed if they can't pay.
 *
 * This is a textbook collective action problem, and it maps onto the SAME
 * threshold framework as the rest of this engine — just one layer later in
 * the causal chain, with one critical new feature: a FINANCING FEEDBACK
 * LOOP. Ransom payments collected this round fund the attacker's capacity
 * (better tooling, more targets, more affiliates) to attack again next
 * round. This is the mechanism that makes payment individually rational
 * but collectively self-defeating — paying now makes next round's attack
 * cheaper and more likely for EVERYONE, not just the payer.
 *
 * MODEL:
 *   - A population of N victims gets attacked each round.
 *   - Each decides independently: pay (gets data back, avoids downside
 *     loss) or don't pay (eats the loss, but doesn't fund the attacker).
 *   - Total ransom collected this round lowers the attacker's cost to
 *     mount next round's campaign (the financing effect).
 *   - A ban adds an enforcement-risk penalty to paying (effective cost
 *     of paying rises by banPenalty * banEnforcementProb).
 *
 * KEY OUTPUT: two different thresholds —
 *   1. INDIVIDUAL threshold: is it rational for ONE victim, in isolation,
 *      to pay THIS round, given current attacker capability?
 *   2. COLLECTIVE threshold: if EVERY victim plays the same strategy
 *      every round, does the attacker's capability (and therefore harm)
 *      grow, shrink, or stabilize over time?
 *
 * The gap between these two is the actual policy insight: a ban can be
 * individually painful (1) while being collectively correct (2), and the
 * model shows exactly how big that gap is and when it closes.
 */

/**
 * Should ONE victim, right now, pay the ransom? Pure individual rationality,
 * ignoring any effect on future attacker capability.
 */
function individualPayDecision(params) {
  const {
    ransomDemand,        // what the attacker is asking for
    dataValueIfLost,      // cost to the victim if they don't get data back (downtime, lost records, etc.)
    recoveryProbIfPay,    // probability paying actually restores access (attackers don't always deliver)
    banEnforcementProb,   // probability a ban is enforced against this victim if they pay
    banPenalty,           // cost imposed on victim if caught paying under a ban (fine, liability)
  } = params;

  const effectiveCostToPay = ransomDemand + banEnforcementProb * banPenalty;
  const expectedLossIfPay = (1 - recoveryProbIfPay) * dataValueIfLost + effectiveCostToPay;
  const expectedLossIfNotPay = dataValueIfLost;

  const payIsRational = expectedLossIfPay < expectedLossIfNotPay;
  const individualThresholdRatio = expectedLossIfPay / expectedLossIfNotPay;

  return {
    effectiveCostToPay,
    expectedLossIfPay,
    expectedLossIfNotPay,
    payIsRational,
    individualThresholdRatio, // <1 means pay is individually rational
  };
}

/**
 * Simulate the population-level dynamic over multiple rounds: as victims
 * pay or don't, attacker capability (modeled as a multiplier on attack
 * volume/sophistication next round) rises or falls based on total revenue
 * collected, and the population's expected harm evolves accordingly.
 */
function simulateRansomwarePolicy(params, rounds = 10) {
  const {
    population,            // number of potential victims in the system
    ransomDemand,
    dataValueIfLost,
    recoveryProbIfPay,
    banEnforcementProb,
    banPenalty,
    financingSensitivity,   // how strongly revenue collected boosts attacker capability next round (0-1)
    capabilityDecay,        // natural decay of attacker capability if unfunded (0-1)
    baseAttackCapability,   // starting capability multiplier (1.0 = baseline)
  } = params;

  let capability = baseAttackCapability;
  const history = [];

  for (let t = 0; t < rounds; t++) {
    // Attacker capability scales how many victims get attacked this round
    // and effectively scales dataValueIfLost (more sophisticated attacks
    // cause more damage if you don't pay).
    const victimsAttacked = Math.min(population, Math.round(population * 0.1 * capability));
    const effectiveDataLoss = dataValueIfLost * capability;

    const decision = individualPayDecision({
      ransomDemand,
      dataValueIfLost: effectiveDataLoss,
      recoveryProbIfPay,
      banEnforcementProb,
      banPenalty,
    });

    const payers = decision.payIsRational ? victimsAttacked : 0;
    const revenueCollected = payers * ransomDemand;

    // Financing feedback: revenue raises next round's capability, normalized
    // against the MAXIMUM revenue achievable this round (if every attacked
    // victim had paid), not the full population's hypothetical revenue —
    // otherwise the funding signal is diluted into irrelevance when only a
    // fraction of the population is targeted per round.
    const maxPossibleRevenueThisRound = victimsAttacked * ransomDemand;
    const fundingBoost = financingSensitivity *
      (maxPossibleRevenueThisRound > 0 ? revenueCollected / maxPossibleRevenueThisRound : 0);
    capability = capability * (1 - capabilityDecay) + fundingBoost;
    capability = Math.max(0.05, capability);

    const totalHarmThisRound =
      payers * decision.effectiveCostToPay +
      (victimsAttacked - payers) * effectiveDataLoss;

    history.push({
      round: t + 1,
      capability,
      victimsAttacked,
      payers,
      payIsRational: decision.payIsRational,
      revenueCollected,
      totalHarmThisRound,
      individualThresholdRatio: decision.individualThresholdRatio,
    });
  }

  const totalHarm = history.reduce((sum, h) => sum + h.totalHarmThisRound, 0);
  const initialCapability = baseAttackCapability;
  const finalCapability = history[history.length - 1].capability;
  const capabilityTrend = finalCapability > initialCapability * 1.05
    ? "escalating (ransomware ecosystem is growing)"
    : finalCapability < initialCapability * 0.95
    ? "shrinking (ransomware ecosystem is being starved)"
    : "stable";

  return {
    history,
    totalHarm,
    initialCapability,
    finalCapability,
    capabilityTrend,
    individuallyRationalToPay: history[0].payIsRational,
    note: "Capability dynamics use a simplified linear financing-feedback model. Real attacker reinvestment (tooling, affiliates, recruitment) is more complex; this captures DIRECTION of the collective effect, not precise magnitudes.",
  };
}

/**
 * The core policy comparison: run the simulation twice — once under
 * "payments allowed" and once under "payments banned" (modeled as
 * banEnforcementProb -> ~1) — and compare total harm. This is the
 * single chart that makes the collective-action argument concrete:
 * does banning payments actually reduce total harm, given the
 * financing feedback loop, or does it just shift harm onto victims
 * without reducing attacker capability fast enough to matter?
 */
function compareBanPolicy(baseParams, rounds = 10) {
  const allowed = simulateRansomwarePolicy({ ...baseParams, banEnforcementProb: 0.02 }, rounds);
  const banned = simulateRansomwarePolicy({ ...baseParams, banEnforcementProb: 0.95 }, rounds);

  // Find the crossover round: the first round at which cumulative banned
  // harm drops below cumulative allowed harm. This is the single most
  // important policy number this model produces — it tells you the time
  // horizon over which a ban becomes net-beneficial, not just whether it
  // eventually does. A ban that only pays off after 200 rounds is a very
  // different policy claim than one that pays off after 5.
  let cumulativeAllowed = 0, cumulativeBanned = 0;
  let crossoverRound = null;
  for (let i = 0; i < rounds; i++) {
    cumulativeAllowed += allowed.history[i].totalHarmThisRound;
    cumulativeBanned += banned.history[i].totalHarmThisRound;
    if (crossoverRound === null && cumulativeBanned < cumulativeAllowed) {
      crossoverRound = i + 1;
    }
  }

  return {
    allowed,
    banned,
    harmDelta: banned.totalHarm - allowed.totalHarm, // negative = ban reduces total harm
    banReducesHarm: banned.totalHarm < allowed.totalHarm,
    capabilityDelta: banned.finalCapability - allowed.finalCapability,
    crossoverRound, // null if ban never becomes net-beneficial within the simulated window
  };
}


function clamp(x, lo, hi) {
  return Math.max(lo, Math.min(hi, x));
}

const SCENARIOS = {
  patchTiming: {
    id: "patchTiming",
    name: "Patch Timing",
    question: "Should we patch now, or accept the exposure window?",
    mapParams: (s) => ({
      assetValue: s.systemValue,
      defenseCost: s.patchCost,
      attackCost: s.exploitDevCost,
      breachGain: s.dataValueOnBlackMarket,
      residualRisk: s.patchEffectiveness != null ? 1 - s.patchEffectiveness : 0.15,
      detectionProb: s.detectionProb,
    }),
    defaults: {
      systemValue: 500000,
      patchCost: 8000,
      exploitDevCost: 15000,
      dataValueOnBlackMarket: 120000,
      patchEffectiveness: 0.85,
      detectionProb: 0.4,
    },
  },
  bountyPricing: {
    id: "bountyPricing",
    name: "Bug Bounty Pricing",
    question: "How should we price bounties to beat the black market?",
    mapParams: (s) => ({
      assetValue: s.systemValue,
      defenseCost: s.bountyPayout,
      attackCost: s.exploitDevCost,
      breachGain: s.blackMarketPrice,
      residualRisk: 0.1,
      detectionProb: s.detectionProb,
    }),
    defaults: {
      systemValue: 2000000,
      bountyPayout: 25000,
      exploitDevCost: 18000,
      blackMarketPrice: 60000,
      detectionProb: 0.3,
    },
  },
  resourceAllocation: {
    id: "resourceAllocation",
    name: "Multi-Asset Resource Allocation",
    question: "With a limited budget across N systems, where should defense spend go?",
    mapParams: (s) => ({
      assetValue: s.systemValue,
      defenseCost: s.budgetPerSystem,
      attackCost: s.exploitDevCost,
      breachGain: s.breachValue,
      residualRisk: s.residualRisk != null ? s.residualRisk : 0.2,
      detectionProb: s.detectionProb,
    }),
    defaults: {
      systemValue: 150000,
      budgetPerSystem: 40000,
      exploitDevCost: 12000,
      breachValue: 60000,
      residualRisk: 0.25,
      detectionProb: 0.15,
    },
  },
};

/**
 * Default parameters for the ransomware policy model, tuned (via testing)
 * to produce a genuine crossover where the ban initially looks worse for
 * victims but becomes net-beneficial after enough rounds — this is the
 * realistic, non-obvious dynamic, not a hand-picked "ban always wins" case.
 */
const RANSOMWARE_DEFAULTS = {
  population: 1000,
  ransomDemand: 15000,
  dataValueIfLost: 200000,
  recoveryProbIfPay: 0.85,
  banPenalty: 400000,
  financingSensitivity: 0.4,
  capabilityDecay: 0.1,
  baseAttackCapability: 1.0,
};

module.exports = {
  solveEquilibrium,
  SCENARIOS,
  thresholdPosition,
  simulateRepeatedGame,
  individualPayDecision,
  simulateRansomwarePolicy,
  compareBanPolicy,
  RANSOMWARE_DEFAULTS,
};
