// Initialize settings
document.addEventListener('DOMContentLoaded', async () => {
    // Get elements
    const enableProtection = document.getElementById('enableProtection');
    const detectAadhaar = document.getElementById('detectAadhaar');
    const detectPAN = document.getElementById('detectPAN');
    const detectBank = document.getElementById('detectBank');
    const detectPhone = document.getElementById('detectPhone');
    const trustedList = document.getElementById('trustedList');
    const clearTrusted = document.getElementById('clearTrusted');
    const statusDot = document.querySelector('.status-dot');
    const statusText = document.querySelector('.status-text');

    // Load saved settings
    try {
        const settings = await chrome.storage.local.get([
            'enabled',
            'detectAadhaar',
            'detectPAN',
            'detectBank',
            'detectPhone',
            'trustedDomains'
        ]);

        // Set checkbox states
        enableProtection.checked = settings.enabled !== false;
        detectAadhaar.checked = settings.detectAadhaar !== false;
        detectPAN.checked = settings.detectPAN !== false;
        detectBank.checked = settings.detectBank !== false;
        detectPhone.checked = settings.detectPhone !== false;

        // Update status indicator
        updateStatus(enableProtection.checked);

        // Display trusted sites
        if (settings.trustedDomains && settings.trustedDomains.length > 0) {
            displayTrustedSites(settings.trustedDomains);
        } else {
            trustedList.innerHTML = '<p class="no-sites">No trusted sites added</p>';
        }
    } catch (error) {
        console.error('Error loading settings:', error);
    }

    // Save settings when changed
    enableProtection.addEventListener('change', async (e) => {
        await saveSetting('enabled', e.target.checked);
        updateStatus(e.target.checked);
    });

    detectAadhaar.addEventListener('change', (e) => 
        saveSetting('detectAadhaar', e.target.checked));
    
    detectPAN.addEventListener('change', (e) => 
        saveSetting('detectPAN', e.target.checked));
    
    detectBank.addEventListener('change', (e) => 
        saveSetting('detectBank', e.target.checked));
    
    detectPhone.addEventListener('change', (e) => 
        saveSetting('detectPhone', e.target.checked));

    // Clear trusted sites
    clearTrusted.addEventListener('click', async () => {
        try {
            await chrome.storage.local.set({ trustedDomains: [] });
            trustedList.innerHTML = '<p class="no-sites">No trusted sites added</p>';
        } catch (error) {
            console.error('Error clearing trusted sites:', error);
        }
    });
});

// Helper functions
function updateStatus(enabled) {
    const statusDot = document.querySelector('.status-dot');
    const statusText = document.querySelector('.status-text');
    
    if (enabled) {
        statusDot.classList.add('active');
        statusText.textContent = 'Protection Active';
    } else {
        statusDot.classList.remove('active');
        statusText.textContent = 'Protection Disabled';
    }
}

function displayTrustedSites(domains) {
    const trustedList = document.getElementById('trustedList');
    trustedList.innerHTML = domains.map(domain => `
        <div class="trusted-item">
            <span>${domain}</span>
            <button class="remove-site" data-domain="${domain}">×</button>
        </div>
    `).join('');

    // Add remove button handlers
    document.querySelectorAll('.remove-site').forEach(button => {
        button.addEventListener('click', async () => {
            const domain = button.dataset.domain;
            const settings = await chrome.storage.local.get('trustedDomains');
            const updatedDomains = settings.trustedDomains.filter(d => d !== domain);
            await chrome.storage.local.set({ trustedDomains: updatedDomains });
            displayTrustedSites(updatedDomains);
        });
    });
}

async function saveSetting(key, value) {
    try {
        await chrome.storage.local.set({ [key]: value });
    } catch (error) {
        console.error(`Error saving ${key}:`, error);
    }
}