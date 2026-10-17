
(() => {
  "use strict";

  // Prevent duplicate listeners if the script is injected more than once.
  if (window.__privacyGuardInitialized) return;
  window.__privacyGuardInitialized = true;

  const indianPatterns = {
    pan: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g,

    aadhaar:
      /\b(?!0000\s?0000\s?0000\b)(?:[2-9]\d{3}[\s-]?){2}\d{4}\b/g,

    phone:
      /(?<!\d)(?:(?:\+91|91|0)[\s-]?)?[6-9]\d{9}(?!\d)/g,

    account: /\b\d{9,18}\b/g,

    ifsc: /\b[A-Z]{4}0[A-Z0-9]{6}\b/gi,

    upi:
      /\b[\w.-]+@(?:oksbi|okaxis|okicici|okhdfc|ybl|ibl|upi|paytm|apl)\b/gi,

    card: /\b(?:\d{4}[\s-]?){3}\d{4}\b/g
  };

  const DEFAULT_SETTINGS = {
    enabled: true,
    detectAadhaar: true,
    detectPAN: true,
    detectBank: true,
    detectPhone: true,
    trustedDomains: []
  };

  let modalOpen = false;
  const bypassForms = new WeakSet();

  // Safely read extension settings.
  async function getStorageSettings() {
    try {
      if (
        typeof chrome === "undefined" ||
        !chrome.storage ||
        !chrome.storage.local
      ) {
        console.warn(
          "Privacy Guard: Storage unavailable. Check extension context and permissions."
        );
        return null;
      }

      const stored = await chrome.storage.local.get([
        "enabled",
        "detectAadhaar",
        "detectPAN",
        "detectBank",
        "detectPhone",
        "trustedDomains"
      ]);

      return {
        ...DEFAULT_SETTINGS,
        ...stored,
        trustedDomains: Array.isArray(stored.trustedDomains)
          ? stored.trustedDomains
          : []
      };
    } catch (error) {
      console.error(
        "Privacy Guard: Could not access extension storage:",
        error
      );
      return null;
    }
  }

  // Store a trusted domain.
  async function saveTrustedDomain(domain) {
    try {
      if (
        typeof chrome === "undefined" ||
        !chrome.storage ||
        !chrome.storage.local
      ) {
        return false;
      }

      const result = await chrome.storage.local.get("trustedDomains");
      const domains = Array.isArray(result.trustedDomains)
        ? result.trustedDomains
        : [];

      if (!domains.includes(domain)) {
        domains.push(domain);
        await chrome.storage.local.set({ trustedDomains: domains });
      }

      return true;
    } catch (error) {
      console.error("Privacy Guard: Could not save trusted domain:", error);
      return false;
    }
  }

  function getDomain() {
    try {
      return window.location.hostname.toLowerCase();
    } catch {
      return "";
    }
  }

  function getEnabledTypes(settings) {
    const types = [];

    if (settings.detectAadhaar) {
      types.push({ name: "Aadhaar Number", regex: indianPatterns.aadhaar });
    }

    if (settings.detectPAN) {
      types.push({ name: "PAN Card", regex: indianPatterns.pan });
    }

    if (settings.detectPhone) {
      types.push({ name: "Phone Number", regex: indianPatterns.phone });
    }

    if (settings.detectBank) {
      types.push(
        { name: "Bank Account Number", regex: indianPatterns.account },
        { name: "IFSC Code", regex: indianPatterns.ifsc },
        { name: "UPI ID", regex: indianPatterns.upi },
        { name: "Card Number", regex: indianPatterns.card }
      );
    }

    return types;
  }

  function detectSensitiveData(text, settings) {
    if (!text || typeof text !== "string") return [];

    const matches = [];
    const seen = new Set();
    const types = getEnabledTypes(settings);

    for (const type of types) {
      // Reset regex state before every scan.
      type.regex.lastIndex = 0;

      const found = text.match(type.regex) || [];

      for (const value of found) {
        const key = `${type.name}:${value}`;

        if (!seen.has(key)) {
          seen.add(key);
          matches.push({
            type: type.name,
            value
          });
        }
      }
    }

    return matches;
  }

  function maskSensitiveValue(value) {
    const clean = String(value);

    if (clean.length <= 4) {
      return "*".repeat(clean.length);
    }

    return "*".repeat(Math.max(4, clean.length - 4)) +
      clean.slice(-4);
  }

  function getFormSensitiveData(form, settings) {
    const values = [];

    try {
      const formData = new FormData(form);

      for (const [name, value] of formData.entries()) {
        if (typeof value === "string" && value.trim()) {
          values.push({ name, value });
        }
      }
    } catch (error) {
      console.warn("Privacy Guard: Could not read form data:", error);
    }

    const matches = [];
    const seen = new Set();

    for (const item of values) {
      const found = detectSensitiveData(item.value, settings);

      for (const match of found) {
        const key = `${match.type}:${match.value}`;

        if (!seen.has(key)) {
          seen.add(key);
          matches.push(match);
        }
      }
    }

    return matches;
  }

  function injectStyles() {
    if (document.getElementById("privacy-guard-styles")) return;

    const style = document.createElement("style");
    style.id = "privacy-guard-styles";

    style.textContent = `
      #privacy-guard-overlay {
        position: fixed;
        inset: 0;
        z-index: 2147483647;
        background: rgba(15, 23, 42, 0.65);
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 18px;
        font-family: Arial, sans-serif;
      }

      #privacy-guard-modal {
        width: 100%;
        max-width: 440px;
        box-sizing: border-box;
        background: #ffffff;
        color: #172033;
        border-radius: 18px;
        padding: 24px;
        box-shadow: 0 20px 70px rgba(0, 0, 0, 0.3);
      }

      #privacy-guard-modal * {
        box-sizing: border-box;
      }

      #privacy-guard-modal .pg-icon {
        font-size: 34px;
        margin-bottom: 10px;
      }

      #privacy-guard-modal h2 {
        margin: 0 0 10px;
        font-size: 22px;
        line-height: 1.3;
      }

      #privacy-guard-modal p {
        font-size: 14px;
        line-height: 1.6;
        margin: 8px 0 14px;
      }

      #privacy-guard-modal .pg-list {
        padding: 12px;
        background: #fff7ed;
        border: 1px solid #fed7aa;
        border-radius: 10px;
        margin: 14px 0;
        max-height: 180px;
        overflow-y: auto;
      }

      #privacy-guard-modal .pg-item {
        font-size: 13px;
        line-height: 1.6;
        overflow-wrap: anywhere;
        margin: 5px 0;
      }

      #privacy-guard-modal .pg-actions {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        margin-top: 20px;
      }

      #privacy-guard-modal button {
        flex: 1;
        min-width: 120px;
        border: 0;
        border-radius: 9px;
        padding: 12px 14px;
        font-size: 14px;
        font-weight: 700;
        cursor: pointer;
      }

      #privacy-guard-modal .pg-cancel {
        background: #e5e7eb;
        color: #111827;
      }

      #privacy-guard-modal .pg-proceed {
        background: #dc2626;
        color: #ffffff;
      }

      #privacy-guard-modal .pg-trust {
        display: flex;
        gap: 8px;
        align-items: flex-start;
        font-size: 13px;
        margin-top: 14px;
        line-height: 1.5;
      }

      #privacy-guard-modal .pg-trust input {
        margin-top: 3px;
      }
    `;

    (document.head || document.documentElement).appendChild(style);
  }

  function removeModal() {
    const overlay = document.getElementById("privacy-guard-overlay");

    if (overlay) overlay.remove();

    modalOpen = false;
  }

  function resumeFormSubmission(form, submitter) {
    if (!form || !form.isConnected) return;

    // Respect built-in HTML validation.
    if (!form.checkValidity()) {
      form.reportValidity();
      return;
    }

    // Prevent our submit listener from intercepting the resumed submission.
    bypassForms.add(form);

    try {
      if (typeof form.requestSubmit === "function") {
        if (submitter && submitter.form === form) {
          form.requestSubmit(submitter);
        } else {
          form.requestSubmit();
        }
      } else {
        bypassForms.delete(form);
        console.warn(
          "Privacy Guard: This browser does not support requestSubmit()."
        );
        return;
      }
    } catch (error) {
      console.error("Privacy Guard: Could not resume form submission:", error);
    } finally {
      // requestSubmit dispatches the submit event synchronously.
      bypassForms.delete(form);
    }
  }

  function showPrivacyWarning(form, submitter, matches, domain) {
    if (modalOpen) return;

    injectStyles();
    modalOpen = true;

    const overlay = document.createElement("div");
    overlay.id = "privacy-guard-overlay";

    const modal = document.createElement("div");
    modal.id = "privacy-guard-modal";
    modal.setAttribute("role", "dialog");
    modal.setAttribute("aria-modal", "true");
    modal.setAttribute("aria-labelledby", "pg-title");

    const icon = document.createElement("div");
    icon.className = "pg-icon";
    icon.textContent = "⚠️";

    const title = document.createElement("h2");
    title.id = "pg-title";
    title.textContent = "Sensitive Information Detected";

    const message = document.createElement("p");
    message.textContent =
      "Privacy Guard found information that may be sensitive in this form. Please review it before continuing.";

    const list = document.createElement("div");
    list.className = "pg-list";

    for (const match of matches) {
      const item = document.createElement("div");
      item.className = "pg-item";

      const type = document.createElement("strong");
      type.textContent = `${match.type}: `;

      const value = document.createElement("span");
      value.textContent = maskSensitiveValue(match.value);

      item.append(type, value);
      list.appendChild(item);
    }

    const siteMessage = document.createElement("p");
    siteMessage.textContent = domain
      ? `Website: ${domain}`
      : "Website domain could not be identified.";

    const trustLabel = document.createElement("label");
    trustLabel.className = "pg-trust";

    const trustCheckbox = document.createElement("input");
    trustCheckbox.type = "checkbox";

    const trustText = document.createElement("span");
    trustText.textContent =
      "Trust this website in future and don't show this warning here.";

    trustLabel.append(trustCheckbox, trustText);

    const actions = document.createElement("div");
    actions.className = "pg-actions";

    const cancelButton = document.createElement("button");
    cancelButton.className = "pg-cancel";
    cancelButton.type = "button";
    cancelButton.textContent = "Cancel Submission";

    const proceedButton = document.createElement("button");
    proceedButton.className = "pg-proceed";
    proceedButton.type = "button";
    proceedButton.textContent = "Proceed Anyway";

    actions.append(cancelButton, proceedButton);

    modal.append(
      icon,
      title,
      message,
      list,
      siteMessage,
      trustLabel,
      actions
    );

    overlay.appendChild(modal);
    (document.body || document.documentElement).appendChild(overlay);

    cancelButton.addEventListener("click", () => {
      removeModal();
    });

    proceedButton.addEventListener("click", async () => {
      proceedButton.disabled = true;
      cancelButton.disabled = true;
      proceedButton.textContent = "Continuing...";

      if (trustCheckbox.checked && domain) {
        await saveTrustedDomain(domain);
      }

      removeModal();
      resumeFormSubmission(form, submitter);
    });

    // Clicking outside the dialog cancels the submission.
    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) {
        removeModal();
      }
    });

    // Escape closes the warning and leaves the form unsubmitted.
    function handleEscape(event) {
      if (event.key === "Escape") {
        removeModal();
        document.removeEventListener("keydown", handleEscape);
      }
    }

    document.addEventListener("keydown", handleEscape);
    cancelButton.focus();
  }

  async function handleFormSubmission(event) {
    const form = event.target;

    if (!(form instanceof HTMLFormElement)) return;

    // This is the intentional second submit after the user proceeds.
    if (bypassForms.has(form)) {
      bypassForms.delete(form);
      return;
    }

    if (modalOpen) {
      event.preventDefault();
      event.stopImmediatePropagation();
      return;
    }

    // Stop the first submission while settings and form data are checked.
    event.preventDefault();

    const submitter = event.submitter || null;

    let settings = await getStorageSettings();

    // If extension storage is unavailable, do not leave the form stuck.
    // The warning cannot be guaranteed in this case.
    if (!settings) {
      console.warn(
        "Privacy Guard: Could not load settings; allowing form submission."
      );
      resumeFormSubmission(form, submitter);
      return;
    }

    if (!settings.enabled) {
      resumeFormSubmission(form, submitter);
      return;
    }

    const domain = getDomain();

    if (
      domain &&
      settings.trustedDomains.includes(domain)
    ) {
      resumeFormSubmission(form, submitter);
      return;
    }

    const matches = getFormSensitiveData(form, settings);

    if (matches.length === 0) {
      resumeFormSubmission(form, submitter);
      return;
    }

    showPrivacyWarning(form, submitter, matches, domain);
  }

  injectStyles();

  document.addEventListener(
    "submit",
    handleFormSubmission,
    true
  );

  console.info("Privacy Guard: Content script initialized.");
})();
