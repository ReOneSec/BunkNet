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
        setInterval(() => {
            const mockAddress = `0x${[...Array(40)].map(() => Math.floor(Math.random() * 16).toString(16)).join('')}`;
            addActivityItem(mockAddress, 10);
        }, 4000);
    }

    function addActivityItem(address, amount) {
        const item = document.createElement('li');
        item.innerHTML = `<i class="fa-solid fa-check-circle text-green-400 mr-2"></i><strong>${address.substring(0, 8)}...${address.substring(34)}</strong> received ${amount} $BUNK`;
        activityFeed.prepend(item);
        if (activityFeed.children.length > 4) {
            activityFeed.lastChild.remove();
        }
    }

    // --- ADDRESS VALIDATION ---
    function validateAddress(address) {
        return /^0x[a-fA-F0-9]{40}$/.test(address);
    }

    function validateAddressInput() {
        const address = addressInput.value.trim();
        // Reset styles if input is empty
        if (!address) {
            addressInput.className = 'w-full p-3 pl-12 bg-gray-800 border-2 border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-gray-600 transition text-white font-bold';
            return;
        }
        // Apply valid/invalid class based on validation
        if (validateAddress(address)) {
            addressInput.classList.add('valid');
            addressInput.classList.remove('invalid');
        } else {
            addressInput.classList.add('invalid');
            addressInput.classList.remove('valid');
        }
    }

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

    function showSuccessState(txId) {
        setLoading(false);
        actionPanel.classList.add('hidden');
        
        const url = `${EXPLORER_URL}/#/transaction/${txId}`;
        txLink.href = url;
        txLink.textContent = url;
        successPanel.classList.remove('hidden');

        confetti({ particleCount: 200, spread: 120, origin: { y: 0.6 } });
        
        setTimeout(() => {
            if (!successPanel.classList.contains('hidden')) {
                successPanel.classList.add('hidden');
                checkCooldown();
            }
        }, 15000);
    }

    function setLoading(isLoading, isCooldown = false) {
        dripButton.disabled = isLoading;
        buttonSpinner.classList.toggle('hidden', !isLoading || isCooldown);
        buttonText.textContent = isLoading ? (isCooldown ? 'On Cooldown' : 'Requesting...') : 'Request Tokens';
    }

    function showToast(message, type = 'success') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        toastContainer.appendChild(toast);

        setTimeout(() => toast.classList.add('show'), 100);
        setTimeout(() => {
            toast.classList.remove('show');
            toast.addEventListener('transitionend', () => toast.remove());
        }, 5000);
    }
    
    init();
});
