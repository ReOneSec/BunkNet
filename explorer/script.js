// --- CONFIGURATION ---
const API_BASE_URL = "/api"; // Connect to the explorer.py BFF

// --- DOM ELEMENTS ---
const appRoot = document.getElementById('app-root');
const searchInput = document.getElementById('searchInput');

// --- APP STATE CACHE ---
let addressLabels = new Map();

// =============================================================================
// UTILS & HELPERS
// =============================================================================
const utils = {
    // Fetches data from the BFF API
    async fetchAPI(endpoint) {
        try {
            const response = await fetch(`${API_BASE_URL}${endpoint}`);
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'API request failed');
            }
            return await response.json();
        } catch (error) {
            console.error(`Failed to fetch from ${endpoint}:`, error);
            templates.renderError(error.message);
            return null;
        }
    },
    // Copies text to clipboard and shows a toast notification
    copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            utils.showToast("Copied to clipboard!");
        });
    },
    // Displays a short-lived notification
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
    // Formats UNIX timestamps into a human-readable relative time
    formatTimeAgo(timestamp) {
        const now = new Date();
        const secondsPast = (now.getTime() - new Date(timestamp * 1000).getTime()) / 1000;
        if (secondsPast < 60) return `${Math.round(secondsPast)}s ago`;
        if (secondsPast < 3600) return `${Math.round(secondsPast / 60)}m ago`;
        if (secondsPast <= 86400) return `${Math.round(secondsPast / 3600)}h ago`;
        return new Date(timestamp * 1000).toLocaleDateString();
    },
    // ## NEW ## - Gets the display name for an address (label or truncated address)
    getDisplayName(address) {
        if (addressLabels.has(address)) {
            // Return a styled label if it exists in our cache
            return `<span class="text-yellow-400 font-bold">${addressLabels.get(address)}</span>`;
        }
        if (address === '0') {
            return `<span class="text-gray-500">Network Mint / Reward</span>`;
        }
        // Return a truncated address link if no label is found
        return `<a href="#/address/${address}" class="hash-link">${address.substring(0, 8)}...${address.substring(address.length - 8)}</a>`;
    }
};

// =============================================================================
// HTML TEMPLATES / VIEWS
// =============================================================================
const templates = {
    renderLoading() {
        appRoot.innerHTML = `<div class="space-y-8"><div class="card p-6 h-32 skeleton"></div><div class="card p-6 h-64 skeleton"></div></div>`;
    },
    renderError(message) {
        appRoot.innerHTML = `<div class="card text-center p-8"><i class="fa-solid fa-exclamation-triangle text-red-500 text-4xl mb-4"></i><h2 class="text-2xl font-bold">An Error Occurred</h2><p class="text-gray-400 mt-2">${message}</p><a href="#" class="mt-6 inline-block bg-cyan-500 text-white font-bold py-2 px-4 rounded hover:bg-cyan-600 transition">Back to Home</a></div>`;
    },
    async renderDashboard() {
        templates.renderLoading();
        // Fetch status and the 5 most recent blocks
        const [status, blocks] = await Promise.all([
            utils.fetchAPI('/status'),
            utils.fetchAPI('/blocks?limit=5')
        ]);
        if (!status || !blocks) return;

        const latestTxs = blocks.chain.flatMap(b => b.transactions).slice(-5).reverse();

        appRoot.innerHTML = `
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
                <div class="card p-6"><p class="text-gray-400 text-sm font-bold">LATEST BLOCK</p><p class="text-3xl font-light">${status.chain_length}</p></div>
                <div class="card p-6"><p class="text-gray-400 text-sm font-bold">PENDING TRANSACTIONS</p><p class="text-3xl font-light">${status.pending_transactions}</p></div>
                <div class="card p-6"><p class="text-gray-400 text-sm font-bold">LAST BLOCK HASH</p><p class="text-lg font-mono font-light truncate">${status.last_block_hash}</p></div>
            </div>
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <div><h2 class="text-2xl font-semibold mb-4">Latest Blocks</h2><div class="card">${blocks.chain.map(b => `
                    <div class="p-4 flex justify-between items-center border-b border-gray-800 last:border-b-0"><div class="flex items-center gap-4"><i class="fa-solid fa-cube text-gray-500 text-2xl"></i><div><a href="#/block/${b.index}" class="hash-link font-bold">Block #${b.index}</a><p class="text-sm text-gray-400" title="${new Date(b.timestamp * 1000).toLocaleString()}">${utils.formatTimeAgo(b.timestamp)}</p></div></div><div class="text-right"><p class="text-sm">${b.transactions.length} Txs</p><a href="#/block/${b.hash}" class="hash-link text-xs">${b.hash.substring(0,12)}...</a></div></div>`).join('')}</div></div>
                <div><h2 class="text-2xl font-semibold mb-4">Latest Transactions</h2><div class="card">${latestTxs.length > 0 ? latestTxs.map(tx => `
                    <div class="p-4 border-b border-gray-800 last:border-b-0"><div class="flex justify-between items-center"><span class="hash-link text-xs">${tx.transaction_id.substring(0,12)}...</span><p class="text-cyan-400 font-mono">${tx.amount.toFixed(2)} $BUNK</p></div><div class="flex justify-between items-center mt-2 text-sm"><p>From: ${utils.getDisplayName(tx.sender)}</p><p>To: ${utils.getDisplayName(tx.recipient)}</p></div></div>`).join('') : '<p class="p-4 text-gray-500">No recent transactions.</p>'}</div></div>
            </div>`;
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
                ${detailItem('Timestamp', `<span title="${new Date(block.timestamp * 1000).toLocaleString()}">${utils.formatTimeAgo(block.timestamp)}</span>`)}
                ${detailItem('Previous Hash', `<a href="#/block/${block.previous_hash}" class="hash-link font-mono break-all">${block.previous_hash}</a>`)}
                ${detailItem('Proof', `<span class="font-mono">${block.proof}</span>`)}
                ${detailItem('Transactions', `<strong>${block.transactions.length}</strong> transaction(s)`)}
            </dl></div>
            <h3 class="text-2xl font-semibold mt-8 mb-4">Transactions</h3>
            <div class="card">${block.transactions.map(tx => `
                <div class="p-4 border-b border-gray-800 last:border-b-0"><div class="flex justify-between items-center"><span class="hash-link text-xs">${tx.transaction_id}</span><p class="text-cyan-400 font-mono">${tx.amount.toFixed(2)} $BUNK</p></div><div class="flex justify-between items-center mt-2 text-sm"><p>From: ${utils.getDisplayName(tx.sender)}</p><p>To: ${utils.getDisplayName(tx.recipient)}</p></div></div>`).join('')}
            </div>`;
    },
    async renderAddressView(address) {
        templates.renderLoading();
        const data = await utils.fetchAPI(`/address/${address}`);
        if (!data) return;

        appRoot.innerHTML = `
            <h2 class="text-3xl font-semibold mb-1 truncate">${data.label || 'Address Details'}</h2>
            <p class="font-mono text-gray-400 mb-6 break-all">${address}</p>
            <div class="card p-6 mb-8"><p class="text-gray-400 text-sm font-bold">BALANCE</p><p class="text-4xl font-light text-cyan-400">${data.balance.toFixed(4)} $BUNK</p></div>
            <h3 class="text-2xl font-semibold mt-8 mb-4">Transaction History (${data.transactions.length})</h3>
            <div class="card">${data.transactions.length > 0 ? data.transactions.slice().reverse().map(tx => `
                <div class="p-4 border-b border-gray-800 last:border-b-0"><div class="flex justify-between items-center flex-wrap gap-2"><span class="hash-link text-xs">${tx.transaction_id}</span><span class="text-sm text-gray-400" title="${new Date(tx.timestamp * 1000).toLocaleString()}">${utils.formatTimeAgo(tx.timestamp)}</span></div><div class="flex justify-between items-center mt-2 text-sm"><div><span class="text-gray-500">From:</span> ${utils.getDisplayName(tx.sender)}</div><div><span class="text-gray-500">To:</span> ${utils.getDisplayName(tx.recipient)}</div><span class="${tx.recipient === address ? 'text-green-400' : 'text-red-400'} font-mono">${tx.recipient === address ? '+' : '-'}${tx.amount.toFixed(2)}</span></div></div>`).join('') : '<p class="p-4 text-gray-500">No transactions for this address.</p>'}
            </div>`;
    }
};

// =============================================================================
// ROUTER & APP INITIALIZATION
// =============================================================================
async function router() {
    const path = window.location.hash.substring(2); // Remove #/
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
            break;
    }
}

async function handleSearch(event) {
    if (event.key === 'Enter') {
        const query = searchInput.value.trim();
        if (!query) return;

        searchInput.disabled = true;
        const result = await utils.fetchAPI(`/search/${query}`);
        searchInput.disabled = false;
        searchInput.value = '';

        if (result && result.type) {
            window.location.hash = `/${result.type}/${result.data.hash || result.data.address}`;
        } else {
            utils.showToast("Search returned no results.");
        }
    }
}

async function init() {
    // ## NEW ## - Fetch and cache address labels on startup
    const labelsData = await utils.fetchAPI('/labels');
    if (labelsData) {
        addressLabels = new Map(Object.entries(labelsData));
    }
    
    // Set up router and event listeners
    window.addEventListener('hashchange', router);
    window.addEventListener('load', router);
    searchInput.addEventListener('keypress', handleSearch);
}

// Start the application
init();
                                                                                
