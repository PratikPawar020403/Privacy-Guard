# Privacy Guard - Indian Document Protection

A Chrome extension to protect sensitive Indian documents and information from accidental sharing.

## Features

- Detects and protects sensitive Indian documents:
  - Aadhaar Number
  - PAN Card
  - Bank Account Details
  - UPI IDs
  - Phone Numbers
  - Credit/Debit Cards
  - GST Numbers
  - Voter ID
  - Indian Passport
  - Driving License

- Smart Detection:
  - Context-aware validation
  - Bilingual support (English/Hindi)
  - Form context detection
  - Image text scanning

## Installation

### For Development
1. Clone this repository
2. Open Chrome and go to `chrome://extensions/`
3. Enable "Developer mode" (toggle in top right)
4. Click "Load unpacked"
5. Select the extension directory

### For Testing
1. Open `test.html` in Chrome after installing the extension
2. Try submitting the test forms with sample data:
   - Aadhaar: 1234 5678 9012
   - PAN: ABCDE1234F
   - Phone: +91 9876543210
   - UPI: name@okaxis
   - Bank Account: 123456789
   - IFSC: SBIN0123456

## Development

### Project Structure
```
privacy-guard/
├── manifest.json      # Extension configuration
├── content.js         # Main detection logic
├── popup.html         # Settings popup
├── popup.js          # Settings management
├── styles.css        # UI styles
├── guide_hi.html     # Hindi guide
└── icons/            # Extension icons
```

### Testing Checklist
- [ ] Form Detection
  - Submit forms with sensitive data
  - Check alert popups
  - Verify Hindi translations
- [ ] Context Detection
  - Test banking forms
  - Test government forms
  - Test personal information forms
- [ ] Settings
  - Enable/disable extension
  - Add trusted websites
  - Configure detection types

## Contributing
1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License
MIT License - See LICENSE file for details