// Indian-specific detection patterns
const indianPatterns = {
  pan: /[A-Z]{5}[0-9]{4}[A-Z]\b/g,
  aadhaar: /\b(?!0000\s?0000\s?0000\b)(?:[2-9](?:\d{3}[\s-]?){2}\d{4})\b/g,
  phone: /(?:(?:\+91|0)?[\s-]?)?[6789]\d{9}\b/g,
  account: /\b\d{9,18}\b/g,
  ifsc: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g,
  upi: /[\w.-]+@(?:oksbi|okaxis|okicici|okhdfc|ybl|ibl|upi|paytm|apl)\b/gi,
  card: /\b(?:\d{4}[\s-]?){4}\b/g
};

// Function to safely access chrome storage
async function getTrustedDomains() {
  try {
    const result = await chrome.storage.local.get('trustedDomains');
    return result.trustedDomains || [];
  } catch (error) {
    console.warn('Could not access chrome storage:', error);
    return [];
  }
}

async function saveTrustedDomain(domain) {
  try {
    const currentDomains = await getTrustedDomains();
    if (!currentDomains.includes(domain)) {
      await chrome.storage.local.set({
        trustedDomains: [...currentDomains, domain]
      });
    }
    return true;
  } catch (error) {
    console.warn('Could not save to chrome storage:', error);
    return false;
  }
}

function createModal(detected) {
  const overlay = document.createElement('div');
  overlay.className = 'privacy-guard-overlay';
  
  const modal = document.createElement('div');
  modal.className = 'privacy-modal';
  
  const sanitizedDetected = detected.map(d => ({
    type: d.type,
    values: d.values.map(v => {
      if (d.type === 'aadhaar') {
        return v.replace(/(\d{4})\s*(\d{4})\s*(\d{4})/, 'XXXX XXXX $3');
      } else if (d.type === 'pan') {
        return v.replace(/([A-Z]{5})(\d{4})([A-Z])/, '$1 XXXX $3');
      } else if (d.type === 'card') {
        return v.replace(/(\d{4})\s*(\d{4})\s*(\d{4})\s*(\d{4})/, 'XXXX XXXX XXXX $4');
      }
      return v;
    })
  }));

  modal.innerHTML = `
    <div class="modal-content">
      <h3>🛡️ Privacy Alert!</h3>
      <p>We detected the following sensitive information:</p>
      <ul>
        ${sanitizedDetected.map(d => `
          <li>
            <strong>${getLocalizedType(d.type)}:</strong>
            ${d.values.slice(0, 2).join(', ')}
            ${d.values.length > 2 ? '...' : ''}
          </li>
        `).join('')}
      </ul>
      <p class="warning-text">Are you sure you want to share this information?</p>
      <div class="modal-buttons">
        <label class="remember-choice">
          <input type="checkbox" id="remember-choice"> Remember this site
        </label>
        <div class="button-group">
          <button class="cancel-btn">Cancel</button>
          <button class="proceed-btn">Proceed</button>
        </div>
      </div>
      <div class="loading-indicator">Processing...</div>
    </div>
  `;

  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  return { overlay, modal };
}

function getLocalizedType(type) {
  const typeMap = {
    'aadhaar': 'Aadhaar Number',
    'pan': 'PAN Card',
    'phone': 'Phone Number',
    'card': 'Card Number',
    'account': 'Account Number',
    'ifsc': 'IFSC Code',
    'upi': 'UPI ID'
  };
  return typeMap[type] || type.toUpperCase();
}

// Main form submission handler
async function handleFormSubmission(e) {
  const form = e.target;
  const formData = new FormData(form);
  const detected = [];

  // Check for sensitive data
  for (let [name, value] of formData.entries()) {
    if (typeof value === 'string') {
      for (let [type, pattern] of Object.entries(indianPatterns)) {
        const matches = value.match(pattern);
        if (matches) {
          detected.push({
            type,
            values: matches
          });
        }
      }
    }
  }

  if (detected.length > 0) {
    e.preventDefault();
    
    try {
      // Check if domain is trusted
      const domain = window.location.hostname || 'localhost';
      const trustedDomains = await getTrustedDomains();
      
      if (trustedDomains.includes(domain)) {
        return; // Allow submission for trusted domains
      }

      const { overlay, modal } = createModal(detected);
      
      return new Promise((resolve) => {
        const cancelBtn = modal.querySelector('.cancel-btn');
        const proceedBtn = modal.querySelector('.proceed-btn');
        const rememberChoice = modal.querySelector('#remember-choice');
        const loadingIndicator = modal.querySelector('.loading-indicator');

        cancelBtn.addEventListener('click', () => {
          overlay.remove();
          resolve(false);
        });

        proceedBtn.addEventListener('click', async () => {
          loadingIndicator.style.display = 'block';
          
          try {
            // Only save to trusted domains if checkbox is checked
            if (rememberChoice.checked) {
              await saveTrustedDomain(domain);
            }

            // Remove the overlay before submitting
            overlay.remove();
            
            // Create a clone of the form
            const clonedForm = form.cloneNode(true);
            
            // Copy over form data
            for (let [name, value] of formData.entries()) {
              const input = clonedForm.querySelector(`[name="${name}"]`);
              if (input) {
                input.value = value;
              }
            }
            
            // Submit the form directly
            clonedForm.style.display = 'none';
            document.body.appendChild(clonedForm);
            clonedForm.submit();
            
            // Clean up
            setTimeout(() => {
              document.body.removeChild(clonedForm);
            }, 100);
            
            resolve(true);
          } catch (error) {
            console.warn('Error during form submission:', error);
            // Still allow form submission even if storage fails
            form.submit();
            resolve(true);
          }
        });
      });
    } catch (error) {
      console.warn('Error in form handler:', error);
      return true; // Allow form submission if something goes wrong
    }
  }
}

// Add form submission listener
document.addEventListener('submit', handleFormSubmission);

// Inject styles
const styles = `
  .privacy-guard-overlay {
    position: fixed;
    top: 0;
    left: 0;
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
    from {
      transform: translateY(-20px);
      opacity: 0;
    }
    to {
      transform: translateY(0);
      opacity: 1;
    }
  }

  .privacy-modal h3 {
    color: #dc3545;
    margin: 0 0 15px 0;
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
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
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

const styleSheet = document.createElement('style');
styleSheet.textContent = styles;
document.head.appendChild(styleSheet);