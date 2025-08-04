// --- CONFIGURATION ---
const API_BASE_URL = "/api"; // Your explorer backend API
const POLLING_RATE_MS = 5000; // Refresh dashboard data every 5 seconds

// --- DOM ELEMENTS ---
const appRoot = document.getElementById('app-root');
const searchInput = document.getElementById('searchInput');

// --- APP STATE ---
let dashboardPollId = null; // To store the interval ID for polling
let addressLabels = new Map();

// =============================================================================
// UTILS & HELPERS
// =============================================================================
const utils = {
    async fetchAPI(endpoint) {
        try {
            const response = await fetch(`${API_BASE_URL}${endpoint}`);
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || `API Error: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error(`Failed to fetch from ${endpoint}:`, error);
            templates.renderError(error.message);
            return null;
        }
    },
    copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => utils.showToast("Copied to clipboard!"));
    },
    showToast(message) {
        const container = document.getElementById('toast-container');
        if (!container) return;
        const toast = document.createElement('div');
        toast.className = 'toast show';
        toast.textContent = message;
        container.appendChild(toast);
        setTimeout(() => {
            toast.classList.remove('show');
            toast.addEventListener('transitionend', () => toast.remove());
        }, 3000);
    },
    formatTimeAgo(timestamp) {
        const now = new Date();
        const secondsPast = (now.getTime() - new Date(timestamp * 1000).getTime()) / 1000;
        if (secondsPast < 2) return `Just now`;
        if (secondsPast < 60) return `${Math.round(secondsPast)}s ago`;
        if (secondsPast < 3600) return `${Math.round(secondsPast / 60)}m ago`;
        if (secondsPast <= 86400) return `${Math.round(secondsPast / 3600)}h ago`;
        const date = new Date(timestamp * 1000);
        return date.toLocaleDateString('en-US', { day: 'numeric', month: 'short', year: 'numeric' });
    },
    getDisplayName(address, truncate = true) {
        if (addressLabels.has(address)) {
            return `<span class="text-yellow-400 font-bold">${addressLabels.get(address)}</span>`;
        }
        if (address === '0') {
            return `<span class="text-gray-500">Network Mint / Reward</span>`;
        }
        const linkAddress = truncate ? `${address.substring(0, 8)}...${address.substring(address.length - 8)}` : address;
        return `<a href="#/address/${address}" class="hash-link font-mono">${linkAddress}</a>`;
    }
};

// =============================================================================
// HTML TEMPLATES / VIEWS
// =============================================================================
const templates = {
    renderLoading() {
        appRoot.innerHTML = `<div class="space-y-8"><div class="card p-6 h-32 skeleton"></div><div class="card p-6 h-96 skeleton"></div></div>`;
    },
    renderError(message) {
        appRoot.innerHTML = `<div class="card text-center p-8"><i class="fa-solid fa-triangle-exclamation text-red-500 text-4xl mb-4"></i><h2 class="text-2xl font-bold">An Error Occurred</h2><p class="text-gray-400 mt-2">${message}</p><a href="#" class="mt-6 inline-block bg-cyan-500 text-white font-bold py-2 px-4 rounded hover:bg-cyan-600 transition">Back to Home</a></div>`;
    },
    async renderDashboard() {
        appRoot.innerHTML = `
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
                <div class="card p-6"><p class="text-gray-400 text-sm font-bold">LATEST BLOCK</p><p id="stats-latest-block" class="text-3xl font-light skeleton h-9 w-24 rounded"></p></div>
                <div class="card p-6"><p class="text-gray-400 text-sm font-bold">PENDING TXs</p><p id="stats-pending-txs" class="text-3xl font-light skeleton h-9 w-16 rounded"></p></div>
                <div class="card p-6"><p class="text-gray-400 text-sm font-bold">LAST BLOCK HASH</p><p id="stats-last-hash" class="text-lg font-mono font-light truncate skeleton h-7 w-full rounded"></p></div>
            </div>
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <div><h2 class="text-2xl font-semibold mb-4">Latest Blocks</h2><div id="latest-blocks-list" class="card h-96 custom-scrollbar overflow-y-auto"><div class="p-6 skeleton h-full"></div></div></div>
                <div><h2 class="text-2xl font-semibold mb-4">Latest Transactions</h2><div id="latest-txs-list" class="card h-96 custom-scrollbar overflow-y-auto"><div class="p-6 skeleton h-full"></div></div></div>
            </div>`;
        this.updateDashboard(); // Initial data load
    },
    async updateDashboard() {
        const [status, blocksData] = await Promise.all([
            utils.fetchAPI('/status'),
            utils.fetchAPI('/blocks?limit=10')
        ]);
        if (!status || !blocksData) return;

        // Update stats cards
        const statsLatestBlock = document.getElementById('stats-latest-block');
        const statsPendingTxs = document.getElementById('stats-pending-txs');
        const statsLastHash = document.getElementById('stats-last-hash');
        
        if (statsLatestBlock) {
            statsLatestBlock.textContent = status.chain_length;
            statsLatestBlock.classList.remove('skeleton', 'h-9', 'w-24');
        }
        if (statsPendingTxs) {
            statsPendingTxs.textContent = status.pending_transactions;
            statsPendingTxs.classList.remove('skeleton', 'h-9', 'w-16');
        }
        if (statsLastHash) {
            statsLastHash.textContent = status.last_block_hash;
            statsLastHash.classList.remove('skeleton', 'h-7', 'w-full');
        }

        // Update latest blocks list
        const latestBlocksList = document.getElementById('latest-blocks-list');
        if (latestBlocksList) {
            latestBlocksList.innerHTML = blocksData.chain.map(b => `
                <div class="p-4 flex justify-between items-center border-b border-gray-800 last:border-b-0 list-item-fade-in"><div class="flex items-center gap-4"><i class="fa-solid fa-cube text-gray-500 text-2xl"></i><div><a href="#/block/${b.index}" class="hash-link font-bold">Block #${b.index}</a><p class="text-sm text-gray-400" title="${new Date(b.timestamp * 1000).toLocaleString()}">${utils.formatTimeAgo(b.timestamp)}</p></div></div><div class="text-right"><p class="text-sm">${b.transactions.length} Txs</p><a href="#/block/${b.hash}" class="hash-link text-xs">${b.hash.substring(0,12)}...</a></div></div>`).join('');
        }

        // Update latest transactions list
        const latestTxsList = document.getElementById('latest-txs-list');
        if (latestTxsList) {
            const latestTxs = blocksData.chain.flatMap(b => b.transactions).sort((a, b) => b.timestamp - a.timestamp).slice(0, 10);
            if(latestTxs.length > 0) {
                latestTxsList.innerHTML = latestTxs.map(tx => `
                <div class="p-4 border-b border-gray-800 last:border-b-0 list-item-fade-in"><div class="flex justify-between items-center"><span title="${tx.transaction_id}" class="hash-link text-xs">${tx.transaction_id.substring(0,12)}...</span><p class="text-cyan-400 font-mono">${tx.amount.toFixed(2)} $BUNK</p></div><div class="flex justify-between items-center mt-2 text-sm"><p><span class="text-gray-500">From:</span> ${utils.getDisplayName(tx.sender)}</p><p><span class="text-gray-500">To:</span> ${utils.getDisplayName(tx.recipient)}</p></div></div>`).join('');
            } else {
                latestTxsList.innerHTML = '<p class="p-4 text-gray-500">No recent transactions.</p>';
            }
        }
    },
    async renderBlockView(identifier) {
        templates.renderLoading();
        const block = await utils.fetchAPI(`/block/${identifier}`);
        if (!block) return;
        
        const detailItem = (label, content) => `<div class="py-3 px-4 grid grid-cols-1 md:grid-cols-4 gap-2 border-b border-gray-800 last:border-b-0"><dt class="font-semibold text-gray-400">${label}</dt><dd class="md:col-span-3">${content}</dd></div>`;
        
        appRoot.innerHTML = `
            <h2 class="text-3xl font-semibold mb-6">Block #${block.index}</h2>
            <div class="card"><dl>
                ${detailItem('Block Hash', `<div class="flex items-center gap-2 font-mono break-all">${block.hash} <i class="fa-solid fa-copy copy-icon" onclick="utils.copyToClipboard('${block.hash}')"></i></div>`)}
                ${detailItem('Timestamp', `<span title="${new Date(block.timestamp * 1000).toLocaleString()}">${utils.formatTimeAgo(block.timestamp)} (${new Date(block.timestamp * 1000).toUTCString()})</span>`)}
                ${detailItem('Previous Hash', `<a href="#/block/${block.previous_hash}" class="hash-link font-mono break-all">${block.previous_hash}</a>`)}
                ${detailItem('Proof', `<span class="font-mono">${block.proof}</span>`)}
                ${detailItem('Transactions', `<strong>${block.transactions.length}</strong> transaction(s) in this block`)}
            </dl></div>
            <h3 class="text-2xl font-semibold mt-8 mb-4">Transactions</h3>
            <div class="card custom-scrollbar overflow-y-auto" style="max-height: 50vh;">${block.transactions.map(tx => `
                <div class="p-4 border-b border-gray-800 last:border-b-0"><div class="flex justify-between items-center"><span title="${tx.transaction_id}" class="hash-link text-xs">${tx.transaction_id}</span><p class="text-cyan-400 font-mono">${tx.amount.toFixed(2)} $BUNK</p></div><div class="flex justify-between items-center mt-2 text-sm"><p><span class="text-gray-500">From:</span> ${utils.getDisplayName(tx.sender)}</p><p><span class="text-gray-500">To:</span> ${utils.getDisplayName(tx.recipient)}</p></div></div>`).join('')}
            </div>`;
    },
    async renderAddressView(address) {
        templates.renderLoading();
        const data = await utils.fetchAPI(`/address/${address}`);
        if (!data) return;

        appRoot.innerHTML = `
            <h2 class="text-3xl font-semibold mb-1 truncate">${data.label || 'Address Details'}</h2>
            <div class="flex items-center gap-2"><p class="font-mono text-gray-400 break-all">${address}</p><i class="fa-solid fa-copy copy-icon" onclick="utils.copyToClipboard('${address}')"></i></div>
            <div class="card p-6 my-8"><p class="text-gray-400 text-sm font-bold">BALANCE</p><p class="text-4xl font-light text-cyan-400">${data.balance.toFixed(4)} $BUNK</p></div>
            <h3 class="text-2xl font-semibold mt-8 mb-4">Transaction History (${data.transactions.length})</h3>
            <div class="card custom-scrollbar overflow-y-auto" style="max-height: 60vh;">${data.transactions.length > 0 ? data.transactions.slice().reverse().map(tx => `
                <div class="p-4 border-b border-gray-800 last:border-b-0"><div class="flex justify-between items-center flex-wrap gap-2"><span title="${tx.transaction_id}" class="hash-link text-xs">${tx.transaction_id}</span><span class="text-sm text-gray-400" title="${new Date(tx.timestamp * 1000).toLocaleString()}">${utils.formatTimeAgo(tx.timestamp)}</span></div><div class="flex justify-between items-center mt-2 text-sm"><div><span class="text-gray-500">From:</span> ${utils.getDisplayName(tx.sender)}</div><div><span class="text-gray-500">To:</span> ${utils.getDisplayName(tx.recipient)}</div><span class="${tx.recipient === address ? 'text-green-400' : 'text-red-400'} font-mono">${tx.recipient === address ? '+' : '-'}${tx.amount.toFixed(2)}</span></div></div>`).join('') : '<p class="p-4 text-gray-500">No transactions for this address.</p>'}
            </div>`;
    }
};

// =============================================================================
// ROUTER & APP INITIALIZATION
// =============================================================================
function clearDashboardPoll() {
    if (dashboardPollId) {
        clearInterval(dashboardPollId);
        dashboardPollId = null;
    }
}

async function router() {
    clearDashboardPoll(); // Stop polling when we navigate away
    const path = window.location.hash.substring(2);
    const [view, param] = path.split('/');

    switch (view) {
        case 'block':
            await templates.renderBlockView(param);
            break;
        case 'address':
            await templates.renderAddressView(param);
            break;
        default:
            await templates.renderDashboard();
            // Start polling for dashboard updates
            dashboardPollId = setInterval(templates.updateDashboard, POLLING_RATE_MS);
            break;
    }
}

async function handleSearch(event) {
    if (event.key === 'Enter') {
        const query = searchInput.value.trim();
        if (!query) return;

        searchInput.disabled = true;
        templates.renderLoading(); // Show loading state
        const result = await utils.fetchAPI(`/search/${query}`);
        searchInput.disabled = false;
        searchInput.value = '';

        if (result && result.type) {
            // The data structure from search is nested under 'data'
            const resultData = result.data;
            window.location.hash = `/${result.type}/${resultData.hash || resultData.address}`;
        } else {
            utils.showToast("Search returned no results.");
            // If search fails, go back to dashboard
            window.location.hash = '/';
        }
    }
}

async function init() {
    const labelsData = await utils.fetchAPI('/labels');
    if (labelsData) {
        addressLabels = new Map(Object.entries(labelsData));
    }
    
    window.addEventListener('hashchange', router);
    window.addEventListener('load', router);
    searchInput.addEventListener('keypress', handleSearch);
}

// Start the application
init();
            
