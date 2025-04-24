let reportData = []; // Holds all scanned results for export

// === SINGLE ADDRESS SCAN ===
async function assessRisk() {
  const address = document.getElementById("btcAddress").value.trim();
  const results = document.getElementById("results");
  const usageDisplay = document.getElementById("usageScore");
  const vulnDisplay = document.getElementById("vulnScore");
  const usageReasons = document.getElementById("usageReasons");
  const vulnReasons = document.getElementById("vulnReasons");
  const usageRec = document.getElementById("usageRecommendations");
  const vulnRec = document.getElementById("vulnRecommendations");
  const balanceDisplay = document.getElementById("balanceSnapshot");
  const exposureDisplay = document.getElementById("exposureScore");

  if (!address) {
    alert("Please enter a Bitcoin address.");
    return;
  }

  const usage = await analyzeUsageRisk(address);
  const vuln = await analyzeVulnerabilityRisk(address);
  const nonce = await checkNonceReuse(address);
  const exposure = await getHistoricalExposure(address);

  usageDisplay.textContent = `Usage Risk: ${usage.level} ${getRiskEmoji(usage.level)}`;
  vulnDisplay.textContent = `Vulnerability Risk: ${vuln.level} ${getRiskEmoji(vuln.level)}`;
  exposureDisplay.textContent = `Historical Exposure: ${exposure.level}`;
  balanceDisplay.textContent = `Balance Snapshot: ${usage.balanceBTC} BTC / ~$${usage.balanceUSD}`;

  applyRiskColor(usageDisplay, usage.level);
  applyRiskColor(vulnDisplay, vuln.level);

  usageReasons.innerHTML = "";
  vulnReasons.innerHTML = "";

  usage.reasons.forEach(reason => {
    const li = document.createElement("li");
    li.textContent = reason;
    usageReasons.appendChild(li);
  });

  vuln.reasons.forEach(reason => {
    const li = document.createElement("li");
    li.textContent = reason;
    vulnReasons.appendChild(li);
  });

  usageRec.innerHTML = (usage.level === "High" || usage.level === "Critical")
    ? "Recommendation: Avoid sending funds to this address."
    : "";

  vulnRec.innerHTML = (vuln.level === "High" || vuln.level === "Critical")
    ? "Recommendation: Treat this address as potentially compromised."
    : "";

  if (nonce.level === "Critical") {
    const div = document.createElement("div");
    div.innerHTML = `<strong>Nonce Risk:</strong> ${nonce.level} <br><em>${nonce.reasons.join("<br>")}</em>`;
    results.appendChild(div);
  }

  results.classList.remove("hidden");
}

function getRiskEmoji(level) {
  return level === "Low" ? "🟢" : level === "Moderate" ? "🟡" : level === "High" ? "🟠" : "🔴";
}

function applyRiskColor(element, level) {
  element.classList.remove("risk-low", "risk-moderate", "risk-high");
  if (level === "Low") element.classList.add("risk-low");
  else if (level === "Moderate") element.classList.add("risk-moderate");
  else element.classList.add("risk-high");
}

async function analyzeUsageRisk(address) {
  let score = 0;
  let reasons = [];
  let balanceBTC = 0;
  let balanceUSD = 0;

  try {
    const response = await fetch(`https://blockstream.info/api/address/${address}`);
    if (!response.ok) throw new Error("Failed to fetch address data.");
    const data = await response.json();

    const txCount = data.chain_stats.tx_count || 0;
    if (txCount < 3) {
      score += 1;
      reasons.push(`Low transaction activity (${txCount} txs) – possibly burner or attack wallet.`);
    } else if (txCount > 10) {
      score += 2;
      reasons.push(`High reuse detected (${txCount} txs).`);
    }

    const balanceSats = data.chain_stats.funded_txo_sum - data.chain_stats.spent_txo_sum;
    balanceBTC = balanceSats / 1e8;
    balanceUSD = (balanceBTC * 60000).toFixed(2); // Placeholder BTC/USD

    if (balanceSats === 0) {
      reasons.push("Address has no remaining balance. Possibly emptied or inactive.");
    }
  } catch (err) {
    score += 1;
    reasons.push("Unable to fetch blockchain data – fallback risk assumed.");
    console.error("API Error:", err);
  }

  let level = "Low";
  if (score >= 3 && score < 6) level = "Moderate";
  else if (score >= 6 && score < 9) level = "High";
  else if (score >= 9) level = "Critical";

  return { level, reasons, balanceBTC, balanceUSD };
}

async function getHistoricalExposure(address) {
  try {
    const res = await fetch(`https://blockstream.info/api/address/${address}`);
    const data = await res.json();
    const firstSeen = data.chain_stats.first_seen || 0;
    const timestamp = new Date(firstSeen * 1000);
    const year = timestamp.getFullYear();

    if (year <= 2013) return { level: "High (early BTC era)" };
    if (year <= 2017) return { level: "Moderate (mid-era)" };
    return { level: "Low (recent)" };
  } catch (err) {
    return { level: "Unknown" };
  }
}

// The rest of the code remains unchanged and will be updated next if desired: nonce signature entropy analysis, UI theme, clipboard utility, etc.
