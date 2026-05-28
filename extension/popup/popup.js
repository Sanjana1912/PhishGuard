// popup.js
// Runs every time user clicks the extension icon
// Gets current tab URL → calls backend → fills in the UI

const BACKEND_URL = "http://127.0.0.1:8000"; // change to production URL when deployed
const DASHBOARD_URL = "http://localhost:5173"; // your React dashboard URL

// ── Grab all the DOM elements we'll update ──────────────
const header = document.getElementById("header");
const domainName = document.getElementById("domainName");
const riskBadge = document.getElementById("riskBadge");
const loadingState = document.getElementById("loadingState");
const resultState = document.getElementById("resultState");
const errorState = document.getElementById("errorState");
const scoreValue = document.getElementById("scoreValue");
const scoreBarFill = document.getElementById("scoreBarFill");
const explanationBox = document.getElementById("explanationBox");
const explanationText = document.getElementById("explanationText");
const vtValue = document.getElementById("vtValue");
const domainAgeValue = document.getElementById("domainAgeValue");
const urlhausValue = document.getElementById("urlhausValue");
const typosquatValue = document.getElementById("typosquatValue");
const dashboardBtn = document.getElementById("dashboardBtn");

// ── Main function — runs on popup open ──────────────────
async function main() {
    try {
        // Step 1 — get the current active tab's URL
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        const url = tab.url;

        // Don't scan chrome:// or edge:// internal pages
        if (
            !url ||
            url.startsWith("chrome://") ||
            url.startsWith("edge://") ||
            url.startsWith("chrome-extension://") ||
            url.startsWith("about:")
        ) {
            showError("Cannot scan browser internal pages.");
            return;
        }

        // Show the domain in the header while loading
        const domain = extractDomain(url);
        domainName.textContent = domain;

        // Step 2 — call your FastAPI backend
        const token= localStorage.getItem("phishguard_token");

        const response = await fetch(`${BACKEND_URL}/api/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json",
                       "Authorization": `Bearer ${token}`
              },
            body: JSON.stringify({ url }),
        });

        if (!response.ok) throw new Error("Backend returned error");

        const data = await response.json();

        // Step 3 — fill in the UI with real data
        console.log(data);
        renderResult(data);

        // Step 4 — save scan_id to chrome storage for dashboard link
        chrome.storage.local.set({ lastScanId: data.scan_id });

        chrome.runtime.sendMessage({
            type: "SCAN_RESULT",
            tabId: tab.id,
            riskLevel: data.risk_level,
            explanation: data.explanation,
        });
    } catch (err) {
        console.error("PhishGuard error:", err);
        showError();
    }
}

// ── Fill UI with scan result ─────────────────────────────
function renderResult(data) {
    const level = data.risk_level.toLowerCase(); // "low", "medium", "high", "critical"
    const score = data.risk_score;

    // Hide loading, show result
    loadingState.classList.add("hidden");
    resultState.classList.remove("hidden");

    // Header color + badge
    header.className = `header ${level}`;
    riskBadge.textContent = data.risk_level;
    riskBadge.className = `badge ${level}`;

    // Score number + bar
    scoreValue.textContent = `${score} / 100`;
    scoreValue.className = `score-value ${level}`;
    scoreBarFill.style.width = `${score}%`;
    scoreBarFill.className = `score-bar-fill ${level}`;

    // Explanation (only show if there's a real threat)
    if (data.explanation && data.explanation !== "No major threats detected") {
        explanationBox.classList.remove("hidden");
        explanationText.textContent = data.explanation;
    }

    // VirusTotal card
    const vtCount = data.threat_intel.virustotal.malicious_count;
    vtValue.textContent = vtCount > 0 ? `${vtCount} flags` : "Clean";
    vtValue.className = `card-value ${vtCount > 0 ? "danger" : "safe"}`;

    // Domain age card
    const ageDays = data.features.domain_age_days;
    domainAgeValue.textContent = `${ageDays.toLocaleString()} days`;
    domainAgeValue.className = `card-value ${ageDays < 30 ? "danger" : "safe"}`;

    // URLHaus card
    const isBlacklisted = data.threat_intel.urlhaus.is_blacklisted;
    urlhausValue.textContent = isBlacklisted ? "Blacklisted" : "Clean";
    urlhausValue.className = `card-value ${isBlacklisted ? "danger" : "safe"}`;

    // Typosquatting card
    const isTypo = data.threat_intel.typosquatting.is_typosquat;
    const closestDomain = data.threat_intel.typosquatting.closest_domain;
    typosquatValue.textContent = isTypo ? closestDomain : "None";
    typosquatValue.className = `card-value ${isTypo ? "danger" : "safe"}`;

    // Dashboard button
    dashboardBtn.addEventListener("click", () => {
        chrome.tabs.create({ url: `${DASHBOARD_URL}/report/${data.scan_id}` });
    });
}

// ── Helper: extract domain from full URL ─────────────────
function extractDomain(url) {
    try {
        return new URL(url).hostname;
    } catch {
        return url;
    }
}

// ── Show error state ──────────────────────────────────────
function showError(message) {
    loadingState.classList.add("hidden");
    errorState.classList.remove("hidden");
    if (message) {
        errorState.querySelector("p").textContent = message;
    }
}

// ── Run ───────────────────────────────────────────────────
main();
