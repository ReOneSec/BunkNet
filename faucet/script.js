document.addEventListener('DOMContentLoaded', () => {
    // --- CONFIGURATION ---
    const API_ENDPOINT = '/faucet/drip';
    const COOLDOWN_HOURS = 24;

    // --- DOM ELEMENTS ---
    const addressInput = document.getElementById('addressInput');
    const dripButton = document.getElementById('dripButton');
    const buttonText = document.getElementById('buttonText');
    const buttonSpinner = document.getElementById('buttonSpinner');
    const cooldownTimerDiv = document.getElementById('cooldownTimer');
    const toastContainer = document.getElementById('toastContainer');

    let cooldownInterval;

    // --- INITIALIZATION ---
    function init() {
        checkCooldown();
        dripButton.addEventListener('click', handleDripRequest);
    }

    // --- COOLDOWN LOGIC ---
    function checkCooldown() {
        const lastDripTimestamp = localStorage.getItem('lastDripTimestamp');
        if (!lastDripTimestamp) {
            return;
        }

        const cooldownEndTime = parseInt(lastDripTimestamp) + (COOLDOWN_HOURS * 60 * 60 * 1000);
        const now = new Date().getTime();

        if (now < cooldownEndTime) {
            setLoading(true, true); // Lock the button
            startCountdown(cooldownEndTime);
        } else {
            localStorage.removeItem('lastDripTimestamp');
        }
    }
    
    function startCountdown(endTime) {
        cooldownTimerDiv.classList.remove('hidden');
        
        cooldownInterval = setInterval(() => {
            const now = new Date().getTime();
            const distance = endTime - now;

            if (distance < 0) {
                clearInterval(cooldownInterval);
                cooldownTimerDiv.classList.add('hidden');
                setLoading(false);
                localStorage.removeItem('lastDripTimestamp');
                return;
            }

            const hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
            const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
            const seconds = Math.floor((distance % (1000 * 60)) / 1000);

            cooldownTimerDiv.textContent = `You can request again in ${hours}h ${minutes}m ${seconds}s`;
        }, 1000);
    }

    // --- API & UI LOGIC ---
    async function handleDripRequest() {
        const address = addressInput.value.trim();
        if (!address) {
            showToast('Please enter a BunkNet address.', 'error');
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

            if (response.ok) {
                showToast('Success! Tokens are on their way.', 'success');
                confetti({ particleCount: 150, spread: 90, origin: { y: 0.6 } });
                const timestamp = new Date().getTime();
                localStorage.setItem('lastDripTimestamp', timestamp);
                checkCooldown(); // Start the cooldown immediately
                addressInput.value = '';
            } else {
                showToast(data.error || 'An unknown error occurred.', 'error');
                setLoading(false);
            }
        } catch (error) {
            showToast('Network error. Please try again later.', 'error');
            setLoading(false);
        }
    }

    function setLoading(isLoading, isCooldown = false) {
        dripButton.disabled = isLoading;
        if (isLoading) {
            buttonText.textContent = isCooldown ? 'On Cooldown' : 'Requesting...';
            buttonSpinner.classList.remove('hidden');
        } else {
            buttonText.textContent = 'Request Tokens';
            buttonSpinner.classList.add('hidden');
        }
    }

    function showToast(message, type = 'success') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        toastContainer.appendChild(toast);

        // Trigger the animation
        setTimeout(() => toast.classList.add('show'), 100);

        // Remove the toast after 5 seconds
        setTimeout(() => {
            toast.classList.remove('show');
            toast.addEventListener('transitionend', () => toast.remove());
        }, 5000);
    }

    init();
});
