# Privacy Guard 🛡️

Privacy Guard is a Chrome extension designed to help users think twice before submitting forms containing potentially sensitive Indian personal information.

## 💡 Why Privacy Guard?

Online fraud and scams are increasing. Privacy Guard aims to make people more aware of the sensitive information they share online. Instead of automatically blocking users, it displays a warning so they can review the information and decide whether to continue.

## ✨ Features

- Detects patterns resembling Aadhaar numbers and PAN cards.
- Detects Indian phone numbers and potentially sensitive banking information.
- Identifies patterns resembling bank account numbers, IFSC codes, UPI IDs, and card numbers.
- Warns users before submitting forms containing detected information.
- Lets users cancel submission or proceed anyway.
- Provides configurable detection settings.
- Supports trusted sites to suppress repeated warnings.
- Built using Chrome Extension Manifest V3.

## 📁 Project Structure

```text
privacy-guard/
├── manifest.json
├── content.js
├── popup.html
├── popup.js
├── styles.css
├── guide_hi.html
└── icons/
    └── icon48.png
```

## 🚀 Installation

1. Download or clone the project.
2. Open Google Chrome and navigate to `chrome://extensions/`.
3. Enable **Developer mode**.
4. Click **Load unpacked**.
5. Select the Privacy Guard project folder.
6. For local HTML testing, open the extension's Details page and enable **Allow access to file URLs**.
7. Reload the extension and refresh your test page whenever you change the code.

## 🧭 How to Use

1. Click the Privacy Guard icon in the Chrome toolbar.
2. Enable **Protection Active**.
3. Choose the information categories you want to detect.
4. Fill in a form using dummy test data.
5. Review the warning if potentially sensitive information is detected.
6. Select **Cancel Submission** to stop or **Proceed Anyway** to continue.
7. Add a website to trusted sites only if you understand the implications of suppressing future warnings there.

## 🧪 Testing

Use dummy data only. Never use real Aadhaar, PAN, bank account, or payment details for testing.

- Verify that a warning appears when detection is enabled.
- Disable an individual detection category and test again.
- Verify that Cancel prevents the form submission.
- Verify that Proceed Anyway resumes the submission.
- Test the protection toggle.
- Test the trusted-sites functionality.
- Check the browser console if errors occur.

## 🔐 Permissions

- **storage:** Stores extension settings and trusted-site preferences.
- **activeTab:** Supports workflows requiring access to the active tab.
- **file URL access:** Allows testing on local HTML files when enabled in Chrome's extension settings.

## 🛡️ Privacy and Security

Privacy Guard is an awareness tool, not a complete data-loss prevention system.

- Pattern matching can produce false positives and false negatives.
- It cannot guarantee detection of every sensitive value or submission method.
- The current approach focuses on standard HTML form submissions and may not cover every website, iframe, script, or network request.
- Users can choose to proceed after receiving a warning.
- Trusted sites may bypass warnings, so use that setting carefully.
- Test using dummy information and review the code before using the extension in sensitive environments.

## 🛠️ Troubleshooting

### Corrupted symbols in the popup

Ensure `popup.html` includes:

```html
<meta charset="UTF-8">
```

Save the file using UTF-8 encoding. If an emoji remains corrupted, replace it with plain text or a local icon image.

### Chrome storage errors

1. Open `chrome://extensions/`.
2. Reload Privacy Guard.
3. Refresh the page being tested.
4. Confirm that `manifest.json` includes the `storage` permission.
5. For local files, enable **Allow access to file URLs**.

### Changes are not visible

Save your changes, reload the extension, refresh the test page, and reopen the popup.

## 🧰 Technologies Used

- HTML
- CSS
- JavaScript
- Chrome Extensions Manifest V3

## ⚠️ Disclaimer

Privacy Guard is an educational and awareness-focused project. It is provided as-is and does not guarantee complete protection against accidental disclosure, scams, or online fraud.
