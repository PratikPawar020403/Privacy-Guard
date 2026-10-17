
/* Indian-specific detection patterns */
const indianPatterns = {
  pan: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g,
  aadhaar: /\b(?!0000\s?0000\s?0000\b)(?:[2-9]\d{3}[\s-]?){2}\d{4}\b/g,
  phone: /(?:(?:\+91|0)?[\s-]?)?[6789]\d{9}\b/g,
  account: /\b\d{9,18}\b/g,
  ifsc: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g,
  upi: /[\w.-]+@(?:oksbi|okaxis|okicici|okhdfc|ybl|ibl|upi|paytm|apl)\b/gi,
  card: /\b(?:\d{4}[\s-]?){3}\d{4}\b/g
};

/* Chrome storage helpers */
async function getTrustedDomains() {
  try {
    const result = await chrome.storage.local.get("trustedDomains");
    return result.trustedDomains || [];
  } catch (error) {
    console.warn("Could not access trusted domains:", error);
    throw error;
  }
}

async function saveTrustedDomain(domain) {
  try {
    const domains = await getTrustedDomains();

    if (!domains.includes(domain)) {
      await chrome.storage.local.set({
        trustedDomains: [...domains, domain]
      });
    }

    return true;
  } catch (error) {
    console.warn("Could not save trusted domain:", error);
    return false;
  }
}

function getLocalizedType(type) {
  const typeMap = {
    aadhaar: "Aadhaar Number",
    pan: "PAN Card",
    phone: "Phone Number",
    card: "Card Number",
    account: "Account Number",
    ifsc: "IFSC Code",
    upi: "UPI ID"
  };

  return typeMap[type] || type.toUpperCase();
}

/* Create the privacy warning */
function createModal(detected) {
  const overlay = document.createElement("div");
  overlay.className = "privacy-guard-overlay";

  const modal = document.createElement("div");
  modal.className = "privacy-modal";

  // Mask sensitive values before displaying them.
  const sanitizedDetected = detected.map(item => ({
    type: item.type,
    values: item.values.map(value => {
      if (item.type === "aadhaar") {
        return value.replace(
          /\d{4}[\s-]?\d{4}[\s-]?(\d{4})/,
          "XXXX XXXX $1"
        );
      }

      if (item.type === "pan") {
        return value.replace(
          /^([A-Z]{2})[A-Z]{3}\d{4}([A-Z])$/,
          "$1XXX XXXX$2"
        );
      }

      if (item.type === "card") {
        const digits = value.replace(/\D/g, "");
        return `XXXX XXXX XXXX ${digits.slice(-4)}`;
      }

      if (item.type === "phone") {
        return `XXXXXX${value.slice(-4)}`;
      }

      if (item.type === "account") {
        return `XXXX${value.slice(-4)}`;
      }

      return value;
    })
  }));

  // Use DOM methods and textContent to safely display detected values.
  const content = document.createElement("div");
  content.className = "modal-content";

  const heading = document.createElement("h3");
  heading.textContent = "🛡️ Privacy Alert!";

  const description = document.createElement("p");
  description.textContent =
    "We detected the following sensitive information:";

  const list = document.createElement("ul");

  sanitizedDetected.forEach(item => {
    const li = document.createElement("li");
    const strong = document.createElement("strong");

    strong.textContent = `${getLocalizedType(item.type)}: `;
    li.appendChild(strong);
    li.appendChild(
      document.createTextNode(
        item.values.slice(0, 2).join(", ") +
        (item.values.length > 2 ? "..." : "")
      )
    );

    list.appendChild(li);
  });

  const warning = document.createElement("p");
  warning.className = "warning-text";
  warning.textContent =
    "Are you sure you want to share this information?";

  const buttons = document.createElement("div");
  buttons.className = "modal-buttons";

  const rememberLabel = document.createElement("label");
  rememberLabel.className = "remember-choice";

  const rememberChoice = document.createElement("input");
  rememberChoice.type = "checkbox";
  rememberChoice.id = "remember-choice";

  rememberLabel.append(
    rememberChoice,
    document.createTextNode(" Remember this site")
  );

  const buttonGroup = document.createElement("div");
  buttonGroup.className = "button-group";

  const cancelButton = document.createElement("button");
  cancelButton.type = "button";
  cancelButton.className = "cancel-btn";
  cancelButton.textContent = "Cancel";

  const proceedButton = document.createElement("button");
  proceedButton.type = "button";
  proceedButton.className = "proceed-btn";
  proceedButton.textContent = "Proceed";

  buttonGroup.append(cancelButton, proceedButton);
  buttons.append(rememberLabel, buttonGroup);

  const loading = document.createElement("div");
  loading.className = "loading-indicator";
  loading.textContent = "Processing...";

  content.append(heading, description, list, warning, buttons, loading);
  modal.appendChild(content);
  overlay.appendChild(modal);
  document.body.appendChild(overlay);

  return { overlay, modal };
}

/* Check which categories are enabled */
function getEnabledTypes(settings) {
  return {
    aadhaar: settings.detectAadhaar !== false,
    pan: settings.detectPAN !== false,
    phone: settings.detectPhone !== false,
    account: settings.detectBank !== false,
    ifsc: settings.detectBank !== false,
    upi: true,
    card: true
  };
}

/* Scan the form */
function detectSensitiveData(form, enabledTypes) {
  const detected = [];
  const formData = new FormData(form);

  for (const [, value] of formData.entries()) {
    if (typeof value !== "string") continue;

    for (const [type, pattern] of Object.entries(indianPatterns)) {
      if (!enabledTypes[type]) continue;

      // Regexes use the global flag, so reset their state.
      pattern.lastIndex = 0;

      const matches = value.match(pattern);

      if (matches) {
        detected.push({
          type,
          values: [...new Set(matches)]
        });
      }
    }
  }

  return detected;
}

/*
 * Submit a form without firing another submit event.
 * This follows native form.submit() behavior and bypasses
 * built-in constraint validation.
 */
function submitForm(form) {
  HTMLFormElement.prototype.submit.call(form);
}

/* Main submission handler */
async function handleFormSubmission(event) {
  const form = event.target;

  if (!(form instanceof HTMLFormElement)) return;

  // Pause while settings and detection are checked.
  event.preventDefault();

  try {
    const settings = await chrome.storage.local.get([
      "enabled",
      "detectAadhaar",
      "detectPAN",
      "detectBank",
      "detectPhone"
    ]);

    // Protection disabled: submit without scanning.
    if (settings.enabled === false) {
      submitForm(form);
      return;
    }

    const domain = window.location.hostname || "localhost";
    const trustedDomains = await getTrustedDomains();

    // Trusted domains bypass warnings.
    if (trustedDomains.includes(domain)) {
      submitForm(form);
      return;
    }

    const enabledTypes = getEnabledTypes(settings);
    const detected = detectSensitiveData(form, enabledTypes);

    // No enabled sensitive pattern found.
    if (detected.length === 0) {
      submitForm(form);
      return;
    }

    const { overlay, modal } = createModal(detected);

    const cancelButton = modal.querySelector(".cancel-btn");
    const proceedButton = modal.querySelector(".proceed-btn");
    const rememberChoice = modal.querySelector("#remember-choice");
    const loading = modal.querySelector(".loading-indicator");

    // Cancel means the form stays unsubmitted.
    cancelButton.addEventListener("click", () => {
      overlay.remove();
    });

    // Prevent repeated clicks while proceeding.
    proceedButton.addEventListener("click", async () => {
      proceedButton.disabled = true;
      cancelButton.disabled = true;
      loading.style.display = "block";

      try {
        if (rememberChoice.checked) {
          const saved = await saveTrustedDomain(domain);

          if (!saved) {
            console.warn("The site could not be saved as trusted.");
          }
        }

        overlay.remove();
        submitForm(form);
      } catch (error) {
        console.error("Submission error:", error);
        proceedButton.disabled = false;
        cancelButton.disabled = false;
        loading.style.display = "none";
      }
    });
  } catch (error) {
    console.error("Privacy Guard encountered an error:", error);

    // Fail open so a storage error does not permanently block
    // the user's form submission.
    submitForm(form);
  }
}

/* Register the listener once */
document.addEventListener("submit", handleFormSubmission);

/* Inject warning styles */
const styles = `
  .privacy-guard-overlay {
    position: fixed;
    inset: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 999999;
  }

  .privacy-modal {
    background: white;
    padding: 25px;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
    max-width: 500px;
    width: 90%;
    animation: slideIn 0.3s ease-out;
  }

  @keyframes slideIn {
    from { transform: translateY(-20px); opacity: 0; }
    to { transform: translateY(0); opacity: 1; }
  }

  .privacy-modal h3 {
    color: #dc3545;
    margin: 0 0 15px;
    font-size: 1.4em;
  }

  .privacy-modal ul {
    margin: 15px 0;
    padding-left: 20px;
  }

  .privacy-modal li {
    margin: 8px 0;
    padding: 8px;
    background: #f8f9fa;
    border-radius: 4px;
    overflow-wrap: anywhere;
  }

  .warning-text {
    color: #dc3545;
    font-weight: bold;
    padding: 10px;
    border-left: 4px solid #dc3545;
    background: #fff5f5;
    margin: 15px 0;
  }

  .modal-buttons {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    margin-top: 20px;
  }

  .button-group {
    display: flex;
    gap: 10px;
  }

  .cancel-btn, .proceed-btn {
    padding: 10px 20px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-weight: 500;
    transition: all 0.2s;
  }

  .cancel-btn {
    background: #dc3545;
    color: white;
  }

  .proceed-btn {
    background: #28a745;
    color: white;
  }

  .cancel-btn:hover, .proceed-btn:hover {
    transform: translateY(-1px);
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
  }

  .cancel-btn:disabled, .proceed-btn:disabled {
    opacity: 0.6;
    cursor: wait;
  }

  .remember-choice {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 0.9em;
    color: #666;
  }

  .loading-indicator {
    text-align: center;
    margin-top: 10px;
    color: #666;
    display: none;
  }
`;

const styleSheet = document.createElement("style");
styleSheet.textContent = styles;
(document.head || document.documentElement).appendChild(styleSheet);
