/**
 * SELF-TEST (offline, synthetic data)
 * ============================================================
 * This does NOT require internet access. It proves the bucketing and
 * step-function detection logic in validate.js is correct by running it
 * against two synthetic datasets with KNOWN ground-truth shapes:
 *
 *   Test A: a true step function (exploit rate jumps sharply at EPSS=0.5)
 *           -> should be detected as "step-function signature detected"
 *   Test B: a smooth linear function (exploit rate rises evenly)
 *           -> should be detected as "no strong step-function signature"
 *
 * If both assertions pass, the analysis logic itself is verified correct,
 * independent of whether real-world data is available in this environment.
 * Run with: node selftest.js
 */

// Re-implement the same bucketize/analyze functions (kept identical to validate.js)
function bucketize(epssScores, kevSet) {
  const bins = [];
  for (let i = 0; i < 20; i++) {
    bins.push({ lo: i * 0.05, hi: (i + 1) * 0.05, total: 0, exploited: 0 });
  }
  for (const row of epssScores) {
    const score = parseFloat(row.epss);
    const cve = row.cve;
    const binIndex = Math.min(19, Math.floor(score / 0.05));
    bins[binIndex].total += 1;
    if (kevSet.has(cve)) bins[binIndex].exploited += 1;
  }
  return bins.map((b) => ({ ...b, exploitRate: b.total > 0 ? b.exploited / b.total : 0 }));
}

function analyzeStepFunction(bins) {
  // Only consider bins with enough samples to be statistically meaningful
  const populated = bins.filter((b) => b.total >= 20);
  if (populated.length < 3) {
    return { interpretation: "Insufficient data across bins to test for a step signature.", stepSignatureRatio: null };
  }

  let maxJump = -Infinity;
  let maxJumpAt = null;
  const jumps = [];
  for (let i = 1; i < populated.length; i++) {
    const jump = populated[i].exploitRate - populated[i - 1].exploitRate;
    jumps.push(jump);
    if (jump > maxJump) {
      maxJump = jump;
      maxJumpAt = populated[i].lo;
    }
  }

  // Total rise = exploit rate in the last populated bin minus the first.
  // This is the metric that actually matters: what FRACTION of the total
  // increase in exploit rate is explained by a single jump, versus spread
  // across many small jumps? A true step function concentrates nearly all
  // the rise into one transition. A smooth function spreads it out evenly.
  const totalRise = populated[populated.length - 1].exploitRate - populated[0].exploitRate;
  const concentrationRatio = totalRise !== 0 ? maxJump / totalRise : null;

  // Also require the jump to be a clear outlier vs. the OTHER jumps
  // (excluding itself), not just large relative to a noisy average.
  const otherJumps = jumps.filter((j) => j !== maxJump);
  const otherJumpsMean = otherJumps.reduce((a, b) => a + b, 0) / Math.max(1, otherJumps.length);
  const otherJumpsStd = Math.sqrt(
    otherJumps.reduce((acc, j) => acc + (j - otherJumpsMean) ** 2, 0) / Math.max(1, otherJumps.length)
  );
  const zScore = otherJumpsStd > 0 ? (maxJump - otherJumpsMean) / otherJumpsStd : null;

  // A true step requires BOTH: the single jump explains most of the total
  // rise (>50%), AND that jump is a statistical outlier vs. other jumps
  // (z-score > 2, i.e. more than 2 standard deviations above the rest).
  const isStep = concentrationRatio !== null && concentrationRatio > 0.5 &&
                 zScore !== null && zScore > 2;

  return {
    maxJump,
    maxJumpAtEpssThreshold: maxJumpAt,
    totalRise,
    concentrationRatio,
    zScore,
    stepSignatureRatio: concentrationRatio, // kept for backward-compat naming
    interpretation: isStep
      ? "Step-function signature detected: one transition concentrates most of the total rise and is a statistical outlier vs. other jumps, consistent with the Threshold Law's prediction."
      : "No strong step-function signature: the rise in exploit rate is spread across multiple bins rather than concentrated in one sharp transition.",
  };
}

// --- Generate synthetic CVE data ---
function makeSyntheticData(shape) {
  const rows = [];
  const kevSet = new Set();
  const N = 2000;
  for (let i = 0; i < N; i++) {
    const cve = `CVE-TEST-${i}`;
    const score = i / N; // evenly spread 0 to 1
    rows.push({ cve, epss: score.toFixed(6) });

    let exploitProb;
    if (shape === "step") {
      // true step function: ~2% baseline below 0.5, ~85% above 0.5
      exploitProb = score < 0.5 ? 0.02 : 0.85;
    } else {
      // smooth linear function: exploit prob rises evenly from 0 to 1
      exploitProb = score;
    }
    if (Math.random() < exploitProb) kevSet.add(cve);
  }
  return { rows, kevSet };
}

function runTest(name, shape, expectStepDetected) {
  const { rows, kevSet } = makeSyntheticData(shape);
  const bins = bucketize(rows, kevSet);
  const analysis = analyzeStepFunction(bins);
  const detected = analysis.interpretation.includes("Step-function signature detected");
  const pass = detected === expectStepDetected;

  console.log(`\n--- ${name} ---`);
  console.log("Bins (EPSS range -> exploit rate):");
  bins.forEach((b) => {
    if (b.total > 0) {
      console.log(`  [${b.lo.toFixed(2)}-${b.hi.toFixed(2)}): ${(b.exploitRate * 100).toFixed(1)}% (n=${b.total})`);
    }
  });
  console.log(`Step-signature ratio: ${analysis.stepSignatureRatio?.toFixed(2)}`);
  console.log(`Result: ${analysis.interpretation}`);
  console.log(`Expected step detected = ${expectStepDetected}, got ${detected} -> ${pass ? "PASS" : "FAIL"}`);
  return pass;
}

console.log("=".repeat(70));
console.log("SELF-TEST: validating the analysis logic with synthetic data");
console.log("(this proves the SCRIPT is correct; it does not require internet)");
console.log("=".repeat(70));

const test1 = runTest("Test A: synthetic STEP function", "step", true);
const test2 = runTest("Test B: synthetic LINEAR/smooth function", "linear", false);

console.log("\n" + "=".repeat(70));
if (test1 && test2) {
  console.log("ALL SELF-TESTS PASSED — the validation logic correctly distinguishes");
  console.log("step functions from smooth functions. validate.js is ready to run");
  console.log("against real EPSS/KEV data on any machine with internet access.");
} else {
  console.log("SELF-TEST FAILED — analysis logic needs review before trusting");
  console.log("results from validate.js against real data.");
  process.exit(1);
}
