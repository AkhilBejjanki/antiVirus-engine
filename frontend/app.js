// =====================
// CONFIG
// =====================
const API_BASE = "http://localhost:8000";

// =====================
// DOM ELEMENTS
// =====================
const uploadBox       = document.getElementById("uploadBox");
const fileInput       = document.getElementById("fileInput");
const fileSelected    = document.getElementById("fileSelected");
const fileName        = document.getElementById("fileName");
const fileSize        = document.getElementById("fileSize");
const scanBtn         = document.getElementById("scanBtn");
const scanningOverlay = document.getElementById("scanningOverlay");
const resultsSection  = document.getElementById("resultsSection");
const uploadSection   = document.querySelector(".upload-section");
const resetBtn        = document.getElementById("resetBtn");

// Result elements
const verdictBox   = document.getElementById("verdictBox");
const verdictIcon  = document.getElementById("verdictIcon");
const verdictValue = document.getElementById("verdictValue");
const threatName   = document.getElementById("threatName");
const md5Value     = document.getElementById("md5Value");
const sha1Value    = document.getElementById("sha1Value");
const sha256Value  = document.getElementById("sha256Value");
const matchInfo    = document.getElementById("matchInfo");
const matchType    = document.getElementById("matchType");
const matchHash    = document.getElementById("matchHash");

// Scan step elements
const steps = [
  document.getElementById("step1"),
  document.getElementById("step2"),
  document.getElementById("step3"),
  document.getElementById("step4"),
];

let selectedFile = null;

// =====================
// FILE SELECTION
// =====================
uploadBox.addEventListener("click", () => fileInput.click());

fileInput.addEventListener("change", (e) => {
  if (e.target.files.length > 0) handleFileSelect(e.target.files[0]);
});

uploadBox.addEventListener("dragover", (e) => {
  e.preventDefault();
  uploadBox.classList.add("drag-over");
});

uploadBox.addEventListener("dragleave", () => {
  uploadBox.classList.remove("drag-over");
});

uploadBox.addEventListener("drop", (e) => {
  e.preventDefault();
  uploadBox.classList.remove("drag-over");
  if (e.dataTransfer.files.length > 0) handleFileSelect(e.dataTransfer.files[0]);
});

function handleFileSelect(file) {
  selectedFile = file;
  fileName.textContent = file.name;
  fileSize.textContent = formatBytes(file.size);
  fileSelected.style.display = "flex";
  scanBtn.disabled = false;
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

// =====================
// SCAN
// =====================
scanBtn.addEventListener("click", async () => {
  if (!selectedFile) return;
  await runScan();
});

async function runScan() {
  uploadSection.style.display = "none";
  scanningOverlay.style.display = "block";
  resultsSection.style.display = "none";

  await animateSteps();

  const formData = new FormData();
  formData.append("file", selectedFile);

  try {
    const response = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      body: formData,
    });

    if (!response.ok) throw new Error(`Server error: ${response.status}`);

    const result = await response.json();

    scanningOverlay.style.display = "none";
    showResults(result);

  } catch (error) {
    scanningOverlay.style.display = "none";
    alert(`Error: ${error.message}\n\nMake sure backend is running at ${API_BASE}`);
    resetUI();
  }
}

async function animateSteps() {
  for (let i = 0; i < steps.length; i++) {
    steps[i].classList.add("active");
    await sleep(600);
    steps[i].classList.remove("active");
    steps[i].classList.add("done");
  }
  await sleep(300);
}

// =====================
// SHOW RESULTS
// =====================
function showResults(data) {
  resultsSection.style.display = "block";

  const isMalicious  = data.verdict === "MALICIOUS";
  const isSuspicious = data.verdict === "SUSPICIOUS";

  // Verdict box
  if (isMalicious) {
    verdictBox.className   = "verdict-box malicious";
    verdictIcon.textContent = "⚠";
    threatName.textContent  = `Threat: ${data.threat_name}`;
  } else if (isSuspicious) {
    verdictBox.className   = "verdict-box suspicious";
    verdictIcon.textContent = "⚡";
    threatName.textContent  = `Matched ${data.yara_matches.length} YARA rule(s)`;
  } else {
    verdictBox.className   = "verdict-box clean";
    verdictIcon.textContent = "✓";
    threatName.textContent  = "No known threats detected";
  }

  verdictValue.textContent = data.verdict;

  // Hash values
  md5Value.textContent    = data.md5    || "—";
  sha1Value.textContent   = data.sha1   || "—";
  sha256Value.textContent = data.sha256 || "—";

  // Hash match info
  if (isMalicious && data.matched_hash) {
    matchInfo.style.display = "block";
    matchType.textContent   = data.matched_type;
    matchHash.textContent   = data.matched_hash;
  } else {
    matchInfo.style.display = "none";
  }

  // YARA results
  renderYaraResults(data.yara_matches || []);
}

// =====================
// RENDER YARA RESULTS
// =====================
function renderYaraResults(matches) {
  // Remove old YARA section if it exists
  const old = document.getElementById("yaraResults");
  if (old) old.remove();

  // If no YARA matches, nothing to show
  if (matches.length === 0) return;

  // Build YARA results HTML
  const yaraSection = document.createElement("div");
  yaraSection.id = "yaraResults";
  yaraSection.innerHTML = `
    <div class="section-label" style="margin-top: 16px;">// YARA RULE MATCHES</div>
    ${matches.map(match => `
      <div class="yara-match-card">
        <div class="yara-match-header">
          <span class="yara-rule-name">${match.rule}</span>
          <span class="yara-severity severity-${match.severity.toLowerCase()}">${match.severity}</span>
        </div>
        <div class="yara-description">${match.description}</div>
        ${match.strings.length > 0 ? `
          <div class="yara-strings">
            ${match.strings.map(s => `
              <div class="yara-string-item">
                <span class="yara-string-id">${s.identifier}</span>
                <span class="yara-string-offset">@ ${s.offset}</span>
                <span class="yara-string-value">${escapeHtml(s.value)}</span>
              </div>
            `).join("")}
          </div>
        ` : ""}
      </div>
    `).join("")}
  `;

  // Insert before reset button
  resetBtn.parentNode.insertBefore(yaraSection, resetBtn);
}

// Prevent XSS — escape HTML special characters before inserting into DOM
function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// =====================
// RESET
// =====================
resetBtn.addEventListener("click", resetUI);

function resetUI() {
  selectedFile = null;
  fileInput.value = "";
  steps.forEach(s => s.classList.remove("active", "done"));
  uploadSection.style.display = "block";
  scanningOverlay.style.display = "none";
  resultsSection.style.display = "none";
  fileSelected.style.display = "none";
  scanBtn.disabled = true;
  const yaraResults = document.getElementById("yaraResults");
  if (yaraResults) yaraResults.remove();
}

// =====================
// UTILITY
// =====================
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}