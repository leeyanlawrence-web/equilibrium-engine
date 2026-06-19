/**
 * THRESHOLD LAW VALIDATION
 * ============================================================
 * Tests the central falsifiable claim of the Equilibrium Engine against
 * real-world data:
 *
 *   CLAIM: rational attacker behavior should look like a STEP FUNCTION
 *   around the threshold Θ, not a smooth gradient. Vulnerabilities with
 *   EPSS scores above some cutoff should be disproportionately likely
 *   to appear in CISA's Known Exploited Vulnerabilities (KEV) catalog —
 *   the ground-truth list of vulnerabilities actually exploited in the
 *   wild — and that relationship should show a sharper transition than
 *   a naive linear model would predict.
 *
 * DATA SOURCES (both free, public, no API key required):
 *   1. EPSS  — https://api.first.org/data/v1/epss
 *      Daily-updated probability (0-1) that each CVE will be exploited
 *      in the wild in the next 30 days. ~340,000 CVEs scored.
 *   2. CISA KEV — https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
 *      The authoritative, ground-truth list of CVEs CONFIRMED to have
 *      been exploited. This is our "did an attack actually happen" label.
 *
 * METHOD:
 *   - Pull all KEV CVE IDs (the "exploited = 1" ground truth set)
 *   - Pull EPSS scores for a large sample of CVEs (exploited + not)
 *   - Bucket CVEs by EPSS score into bins (0-0.05, 0.05-0.1, ... 0.95-1.0)
 *   - For each bin, compute: what fraction of CVEs in that bin are in KEV?
 *   - If the Threshold Law's step-function prediction holds, the KEV
 *     fraction should jump sharply at some EPSS cutoff, not increase
 *     smoothly and linearly across bins.
 *
 * HOW TO RUN (no setup, no dependencies, no API key):
 *   node validate.js
 *
 * NOTE ON HONESTY: EPSS itself is a machine-learned probability, not a
 * direct measurement of attacker cost/gain as in our model's parameters.
 * This validation tests a PROXY relationship: EPSS-as-proxy-for-threshold-
 * position vs. KEV-as-proxy-for-attack-occurred. It is suggestive evidence
 * for the step-function claim, not a direct test of our exact cost/gain
 * parameters, which aren't publicly measurable at CVE-level granularity.
 * This limitation is stated explicitly in the Moonshot Paper.
 */

const https = require("https");

function fetchJSON(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { "User-Agent": "equilibrium-engine-validation/1.0" } }, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error(`Failed to parse JSON from ${url}: ${e.message}`));
        }
      });
    }).on("error", reject);
  });
}

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_URL_ALL = "https://api.first.org/data/v1/epss?envelope=true&pretty=false";

async function fetchAllEpssPaginated(maxPages = 50, pageSize = 1000) {
  // EPSS API paginates with offset/limit; this is the most reliable way
  // to get a large, representative, NON-biased sample (default order is
  // by CVE ID, not by score, so this avoids selection bias toward
  // high-score CVEs which would invalidate the bucket comparison).
  let all = [];
  for (let page = 0; page < maxPages; page++) {
    const offset = page * pageSize;
    const url = `https://api.first.org/data/v1/epss?limit=${pageSize}&offset=${offset}`;
    const json = await fetchJSON(url);
    if (!json.data || json.data.length === 0) break;
    all = all.concat(json.data);
    if (json.data.length < pageSize) break; // reached the end
  }
  return all;
}

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
  return bins.map((b) => ({
    ...b,
    exploitRate: b.total > 0 ? b.exploited / b.total : 0,
  }));
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
  // What FRACTION of the total increase in exploit rate is explained by
  // a single jump, versus spread across many small jumps? A true step
  // function concentrates nearly all the rise into one transition.
  const totalRise = populated[populated.length - 1].exploitRate - populated[0].exploitRate;
  const concentrationRatio = totalRise !== 0 ? maxJump / totalRise : null;

  // Require the jump to be a statistical outlier vs. the OTHER jumps too,
  // not just large relative to a noisy average.
  const otherJumps = jumps.filter((j) => j !== maxJump);
  const otherJumpsMean = otherJumps.reduce((a, b) => a + b, 0) / Math.max(1, otherJumps.length);
  const otherJumpsStd = Math.sqrt(
    otherJumps.reduce((acc, j) => acc + (j - otherJumpsMean) ** 2, 0) / Math.max(1, otherJumps.length)
  );
  const zScore = otherJumpsStd > 0 ? (maxJump - otherJumpsMean) / otherJumpsStd : null;

  // A true step requires BOTH: the single jump explains most of the total
  // rise (>50%), AND that jump is a statistical outlier (z-score > 2).
  const isStep = concentrationRatio !== null && concentrationRatio > 0.5 &&
                 zScore !== null && zScore > 2;

  return {
    maxJump,
    maxJumpAtEpssThreshold: maxJumpAt,
    totalRise,
    concentrationRatio,
    zScore,
    stepSignatureRatio: concentrationRatio,
    interpretation: isStep
      ? "Step-function signature detected: one transition concentrates most of the total rise and is a statistical outlier vs. other jumps, consistent with the Threshold Law's prediction."
      : "No strong step-function signature: the rise in exploit rate is spread across multiple bins rather than concentrated in one sharp transition.",
  };
}

async function main() {
  console.log("=".repeat(70));
  console.log("THRESHOLD LAW VALIDATION — fetching real data, no API key needed");
  console.log("=".repeat(70));

  console.log("\n[1/3] Fetching CISA KEV catalog (ground truth: exploited CVEs)...");
  const kevData = await fetchJSON(KEV_URL);
  const kevSet = new Set((kevData.vulnerabilities || []).map((v) => v.cveID));
  console.log(`      -> ${kevSet.size} confirmed-exploited CVEs in KEV catalog`);

  console.log("\n[2/3] Fetching EPSS scores (sampling via pagination, unbiased order)...");
  const epssRows = await fetchAllEpssPaginated(50, 1000); // up to 50,000 CVEs
  console.log(`      -> ${epssRows.length} CVEs with EPSS scores retrieved`);

  console.log("\n[3/3] Bucketing by EPSS score and computing KEV exploit rate per bucket...");
  const bins = bucketize(epssRows, kevSet);
  bins.forEach((b) => {
    console.log(
      `      EPSS [${b.lo.toFixed(2)}-${b.hi.toFixed(2)}): ` +
      `${b.exploited}/${b.total} in KEV ` +
      `(${(b.exploitRate * 100).toFixed(2)}%)`
    );
  });

  const analysis = analyzeStepFunction(bins);
  console.log("\n" + "=".repeat(70));
  console.log("ANALYSIS");
  console.log("=".repeat(70));
  console.log(`Largest single-bin jump in exploit rate: ${(analysis.maxJump * 100).toFixed(2)} pts`);
  console.log(`Located at EPSS ≈ ${analysis.maxJumpAtEpssThreshold}`);
  console.log(`Total rise across all populated bins: ${(analysis.totalRise * 100).toFixed(2)} pts`);
  console.log(`Concentration ratio (jump / total rise): ${analysis.concentrationRatio?.toFixed(2)}`);
  console.log(`Z-score of jump vs. other jumps: ${analysis.zScore?.toFixed(2)}`);
  console.log(`\n${analysis.interpretation}`);
  console.log("\nNote: this tests a PROXY relationship (EPSS vs. KEV membership),");
  console.log("not a direct measurement of the engine's cost/gain parameters.");
  console.log("See the Moonshot Paper for full discussion of this limitation.");
}

main().catch((err) => {
  console.error("\nValidation script failed:", err.message);
  console.error("This usually means no internet access in this environment.");
  console.error("Run on any machine with internet — no API key, no signup required.");
  process.exit(1);
});
