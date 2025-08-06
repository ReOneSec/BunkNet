document.addEventListener('DOMContentLoaded', () => {
    // --- CONFIGURATION ---
    const API_ENDPOINT = '/faucet/drip';
    const EXPLORER_URL = 'https://explorer.bunknet.online';
    const COOLDOWN_HOURS = 24;

    // --- DOM ELEMENTS ---
    const addressInput = document.getElementById('addressInput');
    const dripButton = document.getElementById('dripButton');
    const buttonText = document.getElementById('buttonText');
    const buttonSpinner = document.getElementById('buttonSpinner');
    const subtitle = document.getElementById('subtitle');
    const actionPanel = document.getElementById('action-panel');
    const successPanel = document.getElementById('success-panel');
    const txLink = document.getElementById('tx-link');
    const toastContainer = document.getElementById('toastContainer');
    const activityFeed = document.getElementById('activity-feed');

    const faucetIcon = document.getElementById('faucet-icon');
    const cooldownProgress = document.getElementById('cooldown-progress');
    const cooldownText = document.getElementById('cooldown-text');
    const progressCircleRadius = 52;
    const circumference = 2 * Math.PI * progressCircleRadius;

    let cooldownInterval;

    // --- INITIALIZATION ---
    function init() {
        cooldownProgress.style.strokeDasharray = circumference;
        checkCooldown();
        dripButton.addEventListener('click', handleDripRequest);
        addressInput.addEventListener('input', validateAddressInput);
        startSimulatedActivity();
    }

    // --- LIVE ACTIVITY FEED (SIMULATED) ---
    function startSimulatedActivity() {
        // In a real app, this would be a WebSocket or SSE connection
        setInterval(() => {
            const mockAddress = `0x${[...Array(40)].map(() => Math.floor(Math.random() * 16).toString(16)).join('')}`;
            addActivityItem(mockAddress, 10);
        }, 4000);
    }
    function addActivityItem(address, amount) { /* ... (no changes) ... */ }

    // --- ADDRESS VALIDATION ---
    function validateAddress(address) { return /^0x[a-fA-F0-9]{40}$/.test(address); }
    function validateAddressInput() { /* ... (no changes) ... */ }

    // --- COOLDOWN LOGIC ---
    function checkCooldown() {
        const lastDripTimestamp = localStorage.getItem('lastDripTimestamp');
        if (!lastDripTimestamp) return;

        const cooldownEndTime = parseInt(lastDripTimestamp) + (COOLDOWN_HOURS * 60 * 60 * 1000);
        if (new Date().getTime() < cooldownEndTime) {
            actionPanel.classList.add('hidden');
            successPanel.classList.add('hidden');
            startCountdown(cooldownEndTime);
        } else {
            localStorage.removeItem('lastDripTimestamp');
        }
    }
    
    // UPDATED: Changed timer format to HH:MM:SS
    function startCountdown(endTime) {
        setLoading(true, true);
        faucetIcon.classList.add('hidden');
        cooldownText.classList.remove('hidden');
        subtitle.textContent = "You've received your tokens for today!";

        cooldownInterval = setInterval(() => {
            const now = new Date().getTime();
            const distance = endTime - now;
            if (distance < 0) {
                clearInterval(cooldownInterval);
                resetUI();
                return;
            }
            
            const progress = (COOLDOWN_HOURS * 3600000 - distance) / (COOLDOWN_HOURS * 3600000);
            cooldownProgress.style.strokeDashoffset = circumference * (1 - progress);
            
            const hours = String(Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60))).padStart(2, '0');
            const minutes = String(Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60))).padStart(2, '0');
            const seconds = String(Math.floor((distance % (1000 * 60)) / 1000)).padStart(2, '0');
            
            cooldownText.textContent = `${hours}:${minutes}:${seconds}`;
        }, 1000);
    }

    // UPDATED: Ensures success panel is hidden on reset
    function resetUI() {
        setLoading(false);
        faucetIcon.classList.remove('hidden');
        cooldownText.classList.add('hidden');
        cooldownProgress.style.strokeDashoffset = circumference;
        subtitle.textContent = "Get testnet tokens instantly for the BunkNet ecosystem.";
        actionPanel.classList.remove('hidden');
        successPanel.classList.add('hidden');
        localStorage.removeItem('lastDripTimestamp');
    }

    // --- API & UI LOGIC ---
    // UPDATED: Now shows success panel before starting cooldown
    async function handleDripRequest() {
        const address = addressInput.value.trim();
        if (!validateAddress(address)) {
            showToast('Please enter a valid 0x... address.', 'error');
            return;
        }

        setLoading(true);

        try {
            const response = await fetch(API_ENDPOINT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ recipient: address }),
            });
            const data = await response.json();

            if (response.ok && data.transactionId) {
                localStorage.setItem('lastDripTimestamp', new Date().getTime());
                showSuccessState(data.transactionId);
                addActivityItem(address, 10);
            } else {
                showToast(data.error || 'An unknown error occurred.', 'error');
                setLoading(false);
            }
        } catch (error) {
            showToast('Network error. Please try again later.', 'error');
            setLoading(false);
        }
    }

    // NEW: Function to handle the success UI state
    function showSuccessState(txId) {
        setLoading(false); // Re-enable button visually but panel is hidden
        actionPanel.classList.add('hidden');
        
        const url = `${EXPLORER_URL}/#/transaction/${txId}`;
        txLink.href = url;
        txLink.textContent = url;
        successPanel.classList.remove('hidden');

        confetti({ particleCount: 200, spread: 120, origin: { y: 0.6 } });
        
        // After 15 seconds, transition to the long-term cooldown timer view
        setTimeout(() => {
            // Check if user is still on the success screen before switching
            if (!successPanel.classList.contains('hidden')) {
                successPanel.classList.add('hidden');
                checkCooldown();
            }
        }, 15000);
    }

    function setLoading(isLoading, isCooldown = false) { /* ... (no changes) ... */ }
    function showToast(message, type = 'success') { /* ... (no changes, only used for errors now) ... */ }
    function validateAddressInput() { /* ... (no changes) ... */ }
    function addActivityItem(address, amount) { /* ... (no changes) ... */ }


    init();
});
