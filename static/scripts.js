// === scripts.js ===
// Safe rollback version without backend mitigation fetching

document.addEventListener("DOMContentLoaded", () => {
  console.log("✅ JS initialized — mitigation fetch disabled, static prevention mode active.");

  // === Spinner fallback (submit animation) ===
  const form = document.querySelector("form");
  if (form) {
    form.addEventListener("submit", () => {
      const submitBtn = document.getElementById("submit-button");
      const spinner = document.getElementById("spinner");
      if (submitBtn) submitBtn.style.display = "none";
      if (spinner) spinner.style.display = "block";
    });
  }

  // === Modal references ===
  const modal = document.getElementById("mitigation-modal");
  const closeButton = modal?.querySelector(".modal-close-button");
  if (closeButton) {
    closeButton.addEventListener("click", () => {
      modal.style.display = "none";
    });
  }

  // === Flask context safety ===
  if (!window.results) {
    console.warn("⚠️ No results object found — mindmap may not be rendered yet.");
  } else {
    console.log("📊 Results detected for:", window.results.identifier);
  }

  // === Global error catcher ===
  window.addEventListener("error", (e) => {
    console.error("🚨 Global JS Error caught:", e.message, "at", e.filename, e.lineno);
  });

  // === Mindmap click handling (optional static modal trigger) ===
  const container = document.getElementById("jsmind_container");
  if (container) {
    container.addEventListener("click", (e) => {
      const node = e.target.closest("jmnode");
      if (!node) return;
      const nodeText = node.innerText?.trim() || "(no text)";
      console.log("🖱️ Click:", nodeText);
      // Static info or simple notice (no backend fetch)
      showMitigationModal(nodeText);
    });
  }

  console.log("🧠 Mindmap + Static Mitigation System Ready.");
});

// === Simplified modal renderer ===
function showMitigationModal(title) {
  const modal = document.getElementById("mitigation-modal");
  const modalTitle = document.getElementById("modal-title");
  const mitList = document.getElementById("modal-mitigation-list");
  const prevList = document.getElementById("modal-prevention-list");

  if (!modal || !mitList || !prevList) {
    console.error("❌ Missing modal structure — cannot display mitigation data.");
    return;
  }

  modalTitle.textContent = `🛡️ General Security Guidance for ${title}`;

  // Use generic mitigation info
  const mitigationPoints = [
    "Regularly update software and dependencies.",
    "Implement principle of least privilege in access control.",
    "Monitor logs for unusual activities or anomalies.",
    "Patch known vulnerabilities promptly.",
    "Use secure communication protocols (HTTPS, SSH, etc.)."
  ];

  const preventionPoints = [
    "Enable MFA (Multi-Factor Authentication) wherever possible.",
    "Train users to recognize phishing or social engineering attempts.",
    "Conduct regular security audits and incident response drills.",
    "Back up critical data and verify restoration processes.",
    "Maintain a clear incident escalation and reporting policy."
  ];

  mitList.innerHTML = "";
  prevList.innerHTML = "";

  mitigationPoints.forEach((point) => {
    const li = document.createElement("li");
    li.textContent = point;
    mitList.appendChild(li);
  });

  preventionPoints.forEach((point) => {
    const li = document.createElement("li");
    li.textContent = point;
    prevList.appendChild(li);
  });

  modal.style.display = "flex";
}
