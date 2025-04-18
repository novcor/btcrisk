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

  if (!address) {
    alert("Please enter a Bitcoin address.");
    return;
  }

  const usage = await analyzeUsageRisk(address);
  const vuln = await analyzeVulnerabilityRisk(address);

  usageDisplay.textContent = `Usage Risk: ${usage.level}`;
  vulnDisplay.textContent = `Vulnerability Risk: ${vuln.level}`;

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
    ? "Recommendation: Avoid sending funds to this address. Monitor activity before interacting. Consider additional wallet hygiene checks."
    : "";

  vulnRec.innerHTML = (vuln.level === "High" || vuln.level === "Critical")
    ? "Recommendation: Treat this address as potentially compromised. Do not store significant funds here. Rotate to a freshly generated wallet using a secure tool."
    : "";

  results.classList.remove("hidden");
}

// === BULK FILE UPLOAD AND SCAN ===
async function processUploadedFile() {
  const fileInput = document.getElementById("addressFile");
  const file = fileInput.files[0];
  if (!file) {
    alert("Please select a file.");
    return;
  }

  const content = await file.text();
  const lines = content.split(/\r?\n/).map(line => line.trim()).filter(line => line);
  const total = lines.length;

  reportData = [];
  const grouped = { Low: [], Moderate: [], High: [], Critical: [] };
  const resultsContainer = document.getElementById("bulkDetails");
  resultsContainer.innerHTML = "";

  // Show progress bar
  document.getElementById("progressContainer").classList.remove("hidden");

  for (let i = 0; i < lines.length; i++) {
    const address = lines[i];

    try {
      const usage = await analyzeUsageRisk(address);
      const vuln = await analyzeVulnerabilityRisk(address);

      reportData.push({
        address,
        usageRisk: usage.level,
        vulnRisk: vuln.level,
        usageReasons: usage.reasons,
        vulnReasons: vuln.reasons
      });

      const div = document.createElement("div");
      div.classList.add("address-card");
      div.innerHTML = `
        <strong>Address:</strong> ${address}<br>
        <span class="risk-label ${getRiskClass(usage.level)}">Usage Risk: ${usage.level}</span><br>
        <span class="risk-label ${getRiskClass(vuln.level)}">Vulnerability Risk: ${vuln.level}</span><br>
        <em>${(usage.level === "High" || usage.level === "Critical") ? "Avoid sending funds." : ""}</em><br>
        <em>${(vuln.level === "High" || vuln.level === "Critical") ? "Treat as potentially compromised." : ""}</em>
        <hr>
      `;
      resultsContainer.appendChild(div);

      grouped[usage.level]?.push(address);
      grouped[vuln.level]?.push(address);
    } catch (err) {
      console.error(`Error scanning address ${address}:`, err);
      const errorDiv = document.createElement("div");
      errorDiv.classList.add("address-card");
      errorDiv.innerHTML = `
        <strong>Address:</strong> ${address}<br>
        <span class="risk-label risk-high">Error scanning address</span><br>
        <em>This address may be malformed or unreachable via API.</em>
        <hr>
      `;
      resultsContainer.appendChild(errorDiv);
    }

    // Update progress
    const percent = Math.round(((i + 1) / total) * 100);
    document.getElementById("progressText").innerText = `${percent}%`;
    document.getElementById("progressBarFill").style.width = `${percent}%`;
  }

  document.getElementById("progressContainer").classList.add("hidden");
  document.getElementById("bulkResults").classList.remove("hidden");
  displayRiskGroups(grouped);
}

// === RISK GROUP SUMMARY ===
function displayRiskGroups(grouped) {
  const container = document.getElementById("riskGroups");
  container.innerHTML = "";

  for (const level of ["Critical", "High", "Moderate", "Low"]) {
    if (grouped[level].length > 0) {
      const groupDiv = document.createElement("div");
      groupDiv.innerHTML = `<strong>${level} Risk:</strong><br>${grouped[level].join("<br>")}<br><br>`;
      container.appendChild(groupDiv);
    }
  }
}

// === EXPORT CUSTOM REPORT ===
function downloadFilteredReport() {
  const highOnly = document.getElementById("filterHighOnly").checked;
  const vulnOnly = document.getElementById("filterVulnerableOnly").checked;
  const format = document.getElementById("reportFormat").value;

  const filtered = reportData.filter(entry => {
    const usageRiskOK = !highOnly || ["High", "Critical"].includes(entry.usageRisk);
    const vulnRiskOK = !vulnOnly || ["High", "Critical"].includes(entry.vulnRisk);
    return usageRiskOK && vulnRiskOK;
  });

  let content = "";
  let filename = `riskbtc_report_${Date.now()}`;

  if (format === "json") {
    content = JSON.stringify(filtered, null, 2);
    filename += ".json";
  } else if (format === "csv") {
    const headers = ["Address", "Usage Risk", "Vulnerability Risk"];
    const rows = filtered.map(e => [e.address, e.usageRisk, e.vulnRisk].join(","));
    content = [headers.join(","), ...rows].join("\n");
    filename += ".csv";
  } else if (format === "txt") {
    content = filtered.map(e =>
      `Address: ${e.address}\nUsage Risk: ${e.usageRisk}\nVulnerability Risk: ${e.vulnRisk}\n`
    ).join("\n");
    filename += ".txt";
  }

  const blob = new Blob([content], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

// === HELPERS ===
function getRiskClass(level) {
  if (level === "Low") return "risk-low";
  if (level === "Moderate") return "risk-moderate";
  return "risk-high";
}

function applyRiskColor(element, level) {
  element.classList.remove("risk-low", "risk-moderate", "risk-high");
  if (level === "Low") element.classList.add("risk-low");
  else if (level === "Moderate") element.classList.add("risk-moderate");
  else element.classList.add("risk-high");
}

// === RISK ANALYSIS ===
async function analyzeUsageRisk(address) {
  let score = 0;
  let reasons = [];

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

    const balance = data.chain_stats.funded_txo_sum - data.chain_stats.spent_txo_sum;
    if (balance === 0) {
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

  return { level, reasons };
}

async function analyzeVulnerabilityRisk(address) {
  let score = 0;
  let reasons = [];

  if (address.startsWith("1")) {
    score += 2;
    reasons.push("Legacy P2PKH format – more commonly generated by older or insecure wallets.");
  }

  const weakVanityPrefixes = ["1Love", "1Free", "1God", "1Win", "1Lucky", "1Q2W3E", "1Bitcoin"];
  if (weakVanityPrefixes.some(prefix => address.startsWith(prefix))) {
    score += 3;
    reasons.push("Weak vanity prefix – may have been generated using a short or predictable pattern.");
  }

  const repeatingCharPattern = /(.)\1{4,}/;
  if (repeatingCharPattern.test(address)) {
    score += 2;
    reasons.push("Address contains repeated characters – may be low entropy or brute-forced.");
  }

  const lowercase = address.toLowerCase();
  const englishWords = ["god", "love", "bitcoin", "password", "wallet", "money"];
  if (englishWords.some(word => lowercase.includes(word))) {
    score += 2;
    reasons.push("Contains readable English words – possible brainwallet or vanity phrase.");
  }

  const knownCompromised = false; // Future dataset support
  if (knownCompromised) {
    score += 10;
    reasons.push("Address matches known leaked private key.");
  }

  let level = "Low";
  if (score >= 3 && score < 6) level = "Moderate";
  else if (score >= 6 && score < 9) level = "High";
  else if (score >= 9) level = "Critical";

  return { level, reasons };
async function checkNonceReuse(address) {
  try {
    const response = await fetch(`https://blockstream.info/api/address/${address}/txs`);
    const txs = await response.json();
    const rSet = new Set();
    const seenR = new Map();
    let reused = false;
    let details = [];

    const txids = txs.slice(0, 10).map(tx => tx.txid);

    for (const txid of txids) {
      const txRes = await fetch(`https://blockstream.info/api/tx/${txid}`);
      const txData = await txRes.json();

      for (const vin of txData.vin || []) {
        if (vin.scriptsig_asm && vin.scriptsig_asm.includes("3045") || vin.scriptsig_asm.includes("3044")) {
          const hexParts = vin.scriptsig_asm.split(" ")[0]; // DER sig
          const r = extractRfromDER(hexParts);
          if (r) {
            if (rSet.has(r)) {
              reused = true;
              details.push(`R value reused in txid: ${txid}`);
            } else {
              rSet.add(r);
              seenR.set(r, txid);
            }
          }
        }
      }
    }

    if (reused) {
      return {
        level: "Critical",
        reasons: ["Signature R-value reused — cryptographic nonce vulnerability detected.", ...details]
      };
    }

    return { level: "Low", reasons: [] };

  } catch (err) {
    console.error(`Nonce scan failed for ${address}`, err);
    return {
      level: "Unknown",
      reasons: ["Unable to fetch transactions for nonce check."]
    };
  }
}

function extractRfromDER(derHex) {
  try {
    // Remove 0x30 prefix and length bytes
    let i = 4;
    if (derHex.startsWith("30")) {
      i = 6;
    }
    let rLen = parseInt(derHex.substr(6, 2), 16);
    let r = derHex.substr(8, rLen * 2);
    return r;
  } catch (e) {
    return null;
  }
}
}
