
"use strict";

// Privacy Guard — Indian sensitive-data detection
const indianPatterns = {
  pan: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g,
  aadhaar: /\b(?!0000\s?0000\s?0000\b)(?:[2-9]\d{3}[\s-]?){2}\d{4}\b/g,
  phone: /(?:(?:\+91|0)?[\s-]?)?[6789]\d{9}\b/g,
  account: /\b\d{9,18}\b/g,
  ifsc: /\b[A-Z]{4}0[A-Z0-9]{6}\b/gi,
  upi: /[\w.-]+@(?:oksbi|okaxis|okicici|okhdfc|ybl|ibl|upi|paytm|apl)\b/gi,
  card: /\b(?:\d{4}[\s-]?){3}\d{4}\b/g
};

const typeLabels = {
  aadhaar: "Aadhaar Number",
  pan: "PAN Card",
  phone: "Phone Number",
  account: "Bank Account Number",
  ifsc: "IFSC Code",
  upi: "UPI ID",
  card: "Card Number"
};

// Forms approved for submission once, without another warning.
const bypassForms = new WeakSet();

// Safely read extension settings.
async function getStorageSettings() {
  try {
    if (!chrome?.storage?.local) return null;

    return await chrome.storage.local.get([
      "enabled",
      "detectAadhaar",
      "detectPAN",
      "detectBank",
      "detectPhone",
      "trustedDomains"
    ]);
  } catch (error) {
    console.warn("Privacy Guard: Could not access Chrome storage.", error);
    return null;
  }
}

// Add the current website to the trusted-sites list.
async function saveTrustedDomain(domain) {
  try {
    const result = await chrome.storage.local.get("trustedDomains");
    const domains = result.trustedDomains || [];

    if (!domains.includes(domain)) {
      await chrome.storage.local.set({
        trustedDomains: [...domains, domain]
      });
    }

    return true;
  } catch (error) {
    console.warn("Privacy Guard: Could not save trusted site.", error);
    return false;
  }
}

// Map popup settings to detection types.
function getEnabledTypes(settings) {
  return {
    aadhaar: settings.detectAadhaar !== false,
    pan: settings.detectPAN !== false,
    phone: settings.detectPhone !== false,
    account: settings.detectBank !== false,
    ifsc: settings.detectBank !== false,
    upi: settings.detectBank !== false,
    card: settings.detectBank !== false
  };
}

// Find sensitive-looking values in text form fields.
function detectSensitiveData(formData, enabledTypes) {
  const detected = [];

  for (const [, value] of formData.entries()) {
    if (typeof value !== "string" || !value.trim()) continue;

    for (const [type, pattern] of Object.entries(indianPatterns)) {
      if (!enabledTypes[type]) continue;

      pattern.lastIndex = 0;
      const matches = value.match(pattern);

      if (!matches) continue;

      let item = detected.find(entry => entry.type === type);

      if (!item) {
        item = { type, values: [] };
        detected.push(item);
      }

      for (const match of matches) {
        if (!item.values.includes(match)) {
          item.values.push(match);
        }
      }
    }
  }

  return detected;
}

// Mask sensitive values before displaying them in the warning.
function maskSensitiveValue(type, value) {
  switch (type) {
    case "aadhaar": {
      const digits = value.replace(/\D/g, "");
      return `XXXX XXXX ${digits.slice(-4)}`;
    }

    case "pan":
      return `${value.slice(0, 2)}XXX XXXX${value.slice(-1)}`;

    case "card": {
      const digits = value.replace(/\D/g, "");
      return `XXXX XXXX XXXX ${digits.slice(-4)}`;
    }

    case "phone": {
      const digits = value.replace(/\D/g, "");
      return `XXXXXX${digits.slice(-4)}`;
    }

    case "account":
      return `XXXX${value.slice(-4)}`;

    default:
      return value;
  }
}

// Build the warning using textContent to avoid injecting page data as HTML.
function createModal(detected) {
  const overlay = document.createElement("div");
  overlay.className = "privacy-guard-overlay";

  const modal = document.createElement("div");
  modal.className = "privacy-modal";
  modal.setAttribute("role", "dialog");
  modal.setAttribute("aria-modal", "true");
  modal.setAttribute("aria-labelledby", "privacy-guard-title");

  const title = document.createElement("h3");
  title.id = "privacy-guard-title";
  title.textContent = "🛡️ Privacy Alert!";

  const intro = document.createElement("p");
  intro.textContent =
    "We detected the following sensitive information:";

  const list = document.createElement("ul");

  for (const item of detected) {
    const li = document.createElement("li");
    const strong = document.createElement("strong");

    strong.textContent = typeLabels[item.type] || item.type;
    li.append(strong, document.createTextNode(": "));

    const masked = item.values
      .slice(0, 2)
      .map(value => maskSensitiveValue(item.type, value));

    li.appendChild(
      document.createTextNode(
        masked.join(", ") + (item.values.length > 2 ? " ..." : "")
      )
    );

    list.appendChild(li);
  }

  const warning = document.createElement("p");
  warning.className = "warning-text";
  warning.textContent =
    "Are you sure you want to share this information?";

  const buttons = document.createElement("div");
  buttons.className = "modal-buttons";

  const rememberLabel = document.createElement("label");
  rememberLabel.className = "remember-choice";

  const rememberCheckbox = document.createElement("input");
  rememberCheckbox.type = "checkbox";
  rememberCheckbox.id = "remember-choice";

  rememberLabel.append(
    rememberCheckbox,
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

  const loading = document.createElement("div");
  loading.className = "loading-indicator";
  loading.textContent = "Processing...";
  loading.style.display = "none";

  buttonGroup.append(cancelButton, proceedButton);
  buttons.append(rememberLabel, buttonGroup);
  modal.append(title, intro, list, warning, buttons, loading);
  overlay.appendChild(modal);

  (document.body || document.documentElement).appendChild(overlay);

  return {
    overlay,
    cancelButton,
    proceedButton,
    rememberCheckbox,
    loading
  };
}

// Resume submission while allowing the browser's validation to run.
function resubmitForm(form, submitter) {
  // If the form is invalid, do not bypass the next user submission.
  if (!form.checkValidity()) {
    form.reportValidity();
    return;
  }

  bypassForms.add(form);

  try {
    if (
      submitter &&
      submitter.form === form &&
      typeof form.requestSubmit === "function"
    ) {
      form.requestSubmit(submitter);
    } else {
      form.requestSubmit();
    }
  } catch (error) {
    bypassForms.delete(form);
    console.warn("Privacy Guard: Could not resume form submission.", error);
  }
}

// Display the warning and wait for the user's choice.
function showPrivacyWarning(form, submitter, detected, domain) {
  return new Promise(resolve => {
    const ui = createModal(detected);
    let finished = false;

    function finish(shouldSubmit) {
      if (finished) return;
      finished = true;
      ui.overlay.remove();

      if (shouldSubmit) {
        resubmitForm(form, submitter);
      }

      resolve(shouldSubmit);
    }

    ui.cancelButton.addEventListener("click", () => {
      finish(false);
    });

    ui.proceedButton.addEventListener("click", async () => {
      ui.proceedButton.disabled = true;
      ui.cancelButton.disabled = true;
      ui.loading.style.display = "block";

      if (ui.rememberCheckbox.checked) {
        await saveTrustedDomain(domain);
      }

      finish(true);
    });

    ui.overlay.addEventListener("click", event => {
      if (event.target === ui.overlay) {
        finish(false);
      }
    });
  });
}

// Main form-submission handler.
async function handleFormSubmission(event) {
  const form = event.target;

  if (!(form instanceof HTMLFormElement)) return;

  // This submission has already been approved.
  if (bypassForms.has(form)) {
    bypassForms.delete(form);
    return;
  }

  event.preventDefault();
  const submitter = event.submitter;

  try {
    const settings = await getStorageSettings();

    // If storage is unavailable, fail open so the site can still work.
    if (!settings) {
      resubmitForm(form, submitter);
      return;
    }

    // Respect the main protection switch.
    if (settings.enabled === false) {
      resubmitForm(form, submitter);
      return;
    }

    const domain = window.location.hostname || "localhost";
    const trustedDomains = settings.trustedDomains || [];

    // Trusted sites must be allowed to submit.
    if (trustedDomains.includes(domain)) {
      resubmitForm(form, submitter);
      return;
    }

    const enabledTypes = getEnabledTypes(settings);
    const detected = detectSensitiveData(
      new FormData(form),
      enabledTypes
    );

    if (detected.length === 0) {
      resubmitForm(form, submitter);
      return;
    }

    await showPrivacyWarning(form, submitter, detected, domain);
  } catch (error) {
    console.error("Privacy Guard: Form check failed.", error);
    resubmitForm(form, submitter);
  }
}

// Capture submit events before most page-level handlers.
document.addEventListener("submit", handleFormSubmission, true);

// Warning dialog styles.
const styles = `
  .privacy-guard-overlay {
    position: fixed;
    inset: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.55);
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 2147483647;
    font-family: Arial, sans-serif;
  }

  .privacy-modal {
    box-sizing: border-box;
    background: #fff;
    color: #222;
    padding: 24px;
    border-radius: 12px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.25);
    max-width: 500px;
    width: calc(100% - 32px);
    max-height: 90vh;
    overflow-y: auto;
    animation: privacyGuardSlideIn 0.2s ease-out;
  }

  .privacy-modal h3 {
    color: #dc3545;
    margin: 0 0 14px;
    font-size: 1.4em;
  }

  .privacy-modal ul {
    margin: 14px 0;
    padding-left: 22px;
  }

  .privacy-modal li {
    overflow-wrap: anywhere;
    margin: 8px 0;
    padding: 10px;
    background: #f5f6f8;
    border-radius: 6px;
  }

  .warning-text {
    color: #b42332;
    font-weight: bold;
    padding: 12px;
    border-left: 4px solid #dc3545;
    background: #fff4f4;
    margin: 16px 0;
  }

  .modal-buttons {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 14px;
    margin-top: 20px;
  }

  .button-group {
    display: flex;
    gap: 10px;
  }

  .privacy-modal button {
    padding: 10px 16px;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    font-weight: 600;
  }

  .privacy-modal button:disabled {
    opacity: 0.6;
    cursor: wait;
  }

  .cancel-btn {
    background: #dc3545;
    color: white;
  }

  .proceed-btn {
    background: #198754;
    color: white;
  }

  .remember-choice {
    display: flex;
    align-items: center;
    gap: 7px;
    font-size: 0.9em;
    color: #555;
  }

  .loading-indicator {
    text-align: center;
    margin-top: 12px;
    color: #666;
  }

  @keyframes privacyGuardSlideIn {
    from {
      transform: translateY(-12px);
      opacity: 0;
    }
    to {
      transform: translateY(0);
      opacity: 1;
    }
  }
`;

const styleSheet = document.createElement("style");
styleSheet.textContent = styles;
(document.head || document.documentElement).appendChild(styleSheet);
