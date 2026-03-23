// =====================
// CONFIG
// =====================
const API_BASE = "http://localhost:8000"; // Change this to your deployed backend URL

// =====================
// DOM ELEMENTS
// =====================
const uploadBox     = document.getElementById("uploadBox");
const fileInput     = document.getElementById("fileInput");
const fileSelected  = document.getElementById("fileSelected");
const fileName      = document.getElementById("fileName");
const fileSize      = document.getElementById("fileSize");
const scanBtn       = document.getElementById("scanBtn");
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

// Click on upload box → open file picker
uploadBox.addEventListener("click", () => fileInput.click());

// File picker change
fileInput.addEventListener("change", (e) => {
  if (e.target.files.length > 0) {
    handleFileSelect(e.target.files[0]);
  }
});

// Drag and drop
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
  if (e.dataTransfer.files.length > 0) {
    handleFileSelect(e.dataTransfer.files[0]);
  }
});

// Handle file selection
function handleFileSelect(file) {
  selectedFile = file;

  // Show file info
  fileName.textContent = file.name;
  fileSize.textContent = formatBytes(file.size);
  fileSelected.style.display = "flex";

  // Enable scan button
  scanBtn.disabled = false;
}

// Format file size nicely
function formatBytes(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

// =====================
// SCAN BUTTON
// =====================
scanBtn.addEventListener("click", async () => {
  if (!selectedFile) return;
  await runScan();
});

// =====================
// SCAN LOGIC
// =====================
async function runScan() {
  // Hide upload, show scanning
  uploadSection.style.display = "none";
  scanningOverlay.style.display = "block";
  resultsSection.style.display = "none";

  // Animate steps
  await animateSteps();

  // Build form data to send file to backend
  const formData = new FormData();
  formData.append("file", selectedFile);

  try {
    const response = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      body: formData,
    });

    if (!response.ok) {
      throw new Error(`Server error: ${response.status}`);
    }

    const result = await response.json();

    // Hide scanning, show results
    scanningOverlay.style.display = "none";
    showResults(result);

  } catch (error) {
    scanningOverlay.style.display = "none";
    alert(`Error: ${error.message}\n\nMake sure your backend is running at ${API_BASE}`);
    resetUI();
  }
}

// Animate the scanning steps with delays
async function animateSteps() {
  for (let i = 0; i < steps.length; i++) {
    // Mark current step as active
    steps[i].classList.add("active");

    // Wait for a bit
    await sleep(600);

    // Mark as done, move to next
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

  const isMalicious = data.verdict === "MALICIOUS";

  // Verdict box style
  verdictBox.className = "verdict-box " + (isMalicious ? "malicious" : "clean");
  verdictIcon.textContent = isMalicious ? "⚠" : "✓";
  verdictValue.textContent = data.verdict;
  threatName.textContent = isMalicious
    ? `Threat: ${data.threat_name}`
    : "No known threats detected";

  // Hash values
  md5Value.textContent    = data.md5    || "—";
  sha1Value.textContent   = data.sha1   || "—";
  sha256Value.textContent = data.sha256 || "—";

  // Match info (only show if malicious)
  if (isMalicious && data.matched_hash) {
    matchInfo.style.display = "block";
    matchType.textContent   = data.matched_type;
    matchHash.textContent   = data.matched_hash;
  } else {
    matchInfo.style.display = "none";
  }
}

// =====================
// RESET
// =====================
resetBtn.addEventListener("click", resetUI);

function resetUI() {
  // Reset state
  selectedFile = null;
  fileInput.value = "";

  // Reset steps
  steps.forEach(s => {
    s.classList.remove("active", "done");
  });

  // Show upload, hide others
  uploadSection.style.display = "block";
  scanningOverlay.style.display = "none";
  resultsSection.style.display = "none";
  fileSelected.style.display = "none";
  scanBtn.disabled = true;
}

// =====================
// UTILITY
// =====================
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}