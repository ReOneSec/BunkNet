// --- CONFIGURATION ---
const API_BASE_URL = "http://localhost:7000/api"; // Connect to the BFF explorer API

// --- DOM ELEMENTS ---
const appRoot = document.getElementById('app-root');
const searchInput = document.getElementById('searchInput');

// --- UTILS & HELPERS ---
const utils = {
    // Fetches data from the BFF API
    fetchAPI: async (endpoint) => {
        try {
            const response = await fetch(`${API_BASE_URL}${endpoint}`);
            if (!response.ok) {
                throw new Error(`API Error: ${response.statusText} (${response.status})`);
            }
            return await response.json();
        } catch (error) {
            console.error(`Failed to fetch from ${endpoint}:`, error);
            templates.renderError(error.message);
            return null;
        }
    },
    // Copies text to clipboard and shows a toast notification
    copyToClipboard: (text) => {
        navigator.clipboard.writeText(text).then(() => {
            utils.showToast("Copied to clipboard!");
        });
    },
    // Displays a short-lived notification
    showToast: (message) => {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.textContent = message;
        container.appendChild(toast);
        setTimeout(() => toast.classList.add('show'), 10); // Fade in
        setTimeout(() => {
            toast.classList.remove('show');
            toast.addEventListener('transitionend', () => toast.remove());
        }, 3000); // Fade out and remove
    },
    // Formats UNIX timestamps into a human-readable relative time
    formatTimeAgo: (timestamp) => {
        const now = new Date();
        const secondsPast = (now.getTime() - new Date(timestamp * 1000).getTime()) / 1000;
        if (secondsPast < 60) return `${Math.round(secondsPast)}s ago`;
        if (secondsPast < 3600) return `${Math.round(secondsPast / 60)}m ago`;
        if (secondsPast <= 86400) return `${Math.round(secondsPast / 3600)}h ago`;
        const date = new Date(timestamp * 1000);
        return date.toLocaleDateString('en-US', { day: 'numeric', month: 'short' });
    },
    // Creates a clickable hash with a copy icon
    createHashLink: (type, hash, truncate = true) => {
        const displayText = truncate ? `${hash.substring(0, 8)}...${hash.substring(hash.length - 8)}` : hash;
        return `
            <div class="flex items-center gap-2">
                <a href="#/${type}/${hash}" class="hash-link">${displayText}</a>
                <i class="fa-solid fa-copy copy-icon" onclick="utils.copyToClipboard('${hash}')"></i>
            </div>
        `;
    }
};

// --- HTML TEMPLATES ---
const templates = {
    // Loading state skeleton
    renderLoading: () => {
        appRoot.innerHTML = `
            <div class="space-y-8">
                <div class="card p-6 h-32 skeleton"></div>
                <div class="card p-6 h-64 skeleton"></div>
            </div>
        `;
    },
    // Error display
    renderError: (message) => {
        appRoot.innerHTML = `
            <div class="card text-center p-8">
                <i class="fa-solid fa-exclamation-triangle text-red-500 text-4xl mb-4"></i>
                <h2 class="text-2xl font-bold">An Error Occurred</h2>
                <p class="text-gray-400 mt-2">${message}</p>
                <a href="#" class="mt-6 inline-block bg-cyan-500 text-white font-bold py-2 px-4 rounded hover:bg-cyan-600 transition">Back to Home</a>
            </div>
        `;
    },
    // Main dashboard view
    renderDashboard: async () => {
        templates.renderLoading();
        const [status, blocks] = await Promise.all([
            utils.fetchAPI('/status'),
            utils.fetchAPI('/blocks')
        ]);
        if (!status || !blocks) return;

        // Extract latest transactions from the last 5 blocks
        const latestTxs = blocks.slice(-5).reverse().flatMap(b => b.transactions).slice(0, 5);

        appRoot.innerHTML = `
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
                <div class="card p-6">
                    <p class="text-gray-400 text-sm font-bold">LATEST BLOCK</p>
                    <p class="text-3xl font-light">${status.chain_length}</p>
                </div>
                <div class="card p-6">
                    <p class="text-gray-400 text-sm font-bold">PENDING TRANSACTIONS</p>
                    <p class="text-3xl font-light">${status.pending_transactions}</p>
                </div>
                <div class="card p-6">
                    <p class="text-gray-400 text-sm font-bold">LAST BLOCK HASH</p>
                    <p class="text-lg font-mono font-light truncate">${status.last_block_hash}</p>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <div>
                    <h2 class="text-2xl font-semibold mb-4">Latest Blocks</h2>
                    <div class="card">
                        ${blocks.slice(-5).reverse().map(b => `
                            <div class="p-4 flex justify-between items-center border-b border-gray-800 last:border-b-0">
                                <div class="flex items-center gap-4">
                                    <i class="fa-solid fa-cube text-gray-500 text-2xl"></i>
                                    <div>
                                        <a href="#/block/${b.hash}" class="hash-link font-bold">Block #${b.index}</a>
                                        <p class="text-sm text-gray-400" title="${new Date(b.timestamp * 1000).toLocaleString()}">${utils.formatTimeAgo(b.timestamp)}</p>
                                    </div>
                                </div>
                                <div class="text-right">
                                    <p class="text-sm">${b.transactions.length} Txs</p>
                                    ${utils.createHashLink('block', b.hash)}
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
                <div>
                    <h2 class="text-2xl font-semibold mb-4">Latest Transactions</h2>
                    <div class="card">
                        ${latestTxs.length > 0 ? latestTxs.map(tx => `
                             <div class="p-4 border-b border-gray-800 last:border-b-0">
                                <div class="flex justify-between items-center">
                                    ${utils.createHashLink('tx', tx.transaction_id)}
                                    <p class="text-cyan-400 font-mono">${tx.amount} $BUNK</p>
                                </div>
                                <div class="flex justify-between items-center mt-2 text-sm">
                                    <p>From: ${utils.createHashLink('address', tx.sender)}</p>
                                    <p>To: ${utils.createHashLink('address', tx.recipient)}</p>
                                </div>
                            </div>
                        `).join('') : '<p class="p-4 text-gray-500">No recent transactions.</p>'}
                    </div>
                </div>
            </div>
        `;
    },
    // Detailed view for a single block
    renderBlockView: async (hash) => {
        templates.renderLoading();
        const block = await utils.fetchAPI(`/block/${hash}`);
        if (!block) return;
        
        const detailItem = (label, content) => `
            <div class="py-3 px-4 grid grid-cols-1 md:grid-cols-4 gap-2 border-b border-gray-800 last:border-b-0">
                <dt class="font-semibold text-gray-400">${label}</dt>
                <dd class="md:col-span-3">${content}</dd>
            </div>`;
        
        appRoot.innerHTML = `
            <h2 class="text-3xl font-semibold mb-6">Block #${block.index}</h2>
            <div class="card">
                <dl>
                    ${detailItem('Block Hash', utils.createHashLink('block', block.hash, false))}
                    ${detailItem('Timestamp', `<span title="${new Date(block.timestamp * 1000).toLocaleString()}">${utils.formatTimeAgo(block.timestamp)}</span>`)}
                    ${detailItem('Previous Hash', utils.createHashLink('block', block.previous_hash, false))}
                    ${detailItem('Proof', `<span class="font-mono">${block.proof}</span>`)}
                    ${detailItem('Transactions', `<span class="font-bold">${block.transactions.length}</span> transaction(s) in this block`)}
                </dl>
            </div>
            
            <h3 class="text-2xl font-semibold mt-8 mb-4">Transactions</h3>
            <div class="card">
                ${block.transactions.map(tx => `
                     <div class="p-4 border-b border-gray-800 last:border-b-0">
                        <div class="flex justify-between items-center">
                            ${utils.createHashLink('tx', tx.transaction_id)}
                            <p class="text-cyan-400 font-mono">${tx.amount} $BUNK</p>
                        </div>
                        <div class="flex justify-between items-center mt-2 text-sm">
                            <p>From: ${utils.createHashLink('address', tx.sender)}</p>
                            <p>To: ${utils.createHashLink('address', tx.recipient)}</p>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    },
    // Detailed view for an address
    renderAddressView: async (address) => {
        templates.renderLoading();
        const data = await utils.fetchAPI(`/address/${address}`);
        if (!data) return;

        appRoot.innerHTML = `
            <h2 class="text-3xl font-semibold mb-1 truncate" title="${address}">Address Details</h2>
            <p class="font-mono text-gray-400 mb-6 break-all">${address}</p>
            <div class="card p-6 mb-8">
                <p class="text-gray-400 text-sm font-bold">BALANCE</p>
                <p class="text-4xl font-light text-cyan-400">${data.balance.toFixed(4)} $BUNK</p>
            </div>

            <h3 class="text-2xl font-semibold mt-8 mb-4">Transaction History (${data.transactions.length})</h3>
            <div class="card">
                ${data.transactions.length > 0 ? data.transactions.slice().reverse().map(tx => `
                     <div class="p-4 border-b border-gray-800 last:border-b-0">
                        <div class="flex justify-between items-center flex-wrap gap-2">
                            ${utils.createHashLink('tx', tx.transaction_id)}
                            <span class="text-sm text-gray-400" title="${new Date(tx.timestamp * 1000).toLocaleString()}">${utils.formatTimeAgo(tx.timestamp)}</span>
                        </div>
                        <div class="flex justify-between items-center mt-2 text-sm">
                            <div>
                                <span class="text-gray-500">From:</span> ${utils.createHashLink('address', tx.sender)}
                            </div>
                             <div>
                                <span class="text-gray-500">To:</span> ${utils.createHashLink('address', tx.recipient)}
                            </div>
                            <span class="${tx.recipient === address ? 'text-green-400' : 'text-red-400'} font-mono">
                                ${tx.recipient === address ? '+' : '-'}${tx.amount.toFixed(2)}
                            </span>
                        </div>
                    </div>
                `).join('') : '<p class="p-4 text-gray-500">No transactions found for this address.</p>'}
            </div>
        `;
    },
    // Detailed view for a transaction
    renderTxView: async (txid) => {
        templates.renderLoading();
        const data = await utils.fetchAPI(`/tx/${txid}`);
        if (!data) return;

        const tx = data.transaction || data; // API response might be nested
        const detailItem = (label, content) => `
            <div class="py-3 px-4 grid grid-cols-1 md:grid-cols-4 gap-2 border-b border-gray-800 last:border-b-0">
                <dt class="font-semibold text-gray-400">${label}</dt>
                <dd class="md:col-span-3">${content}</dd>
            </div>`;

        appRoot.innerHTML = `
            <h2 class="text-3xl font-semibold mb-6">Transaction Details</h2>
            <div class="card">
                <dl>
                    ${detailItem('Transaction ID', `<span class="font-mono">${tx.transaction_id}</span>`)}
                    ${detailItem('Timestamp', `<span title="${new Date(tx.timestamp * 1000).toLocaleString()}">${utils.formatTimeAgo(tx.timestamp)}</span>`)}
                    ${detailItem('Type', `<span class="bg-gray-700 text-gray-200 px-2 py-1 rounded-full text-xs font-bold">${tx.type.toUpperCase()}</span>`)}
                    ${detailItem('Amount', `<span class="font-mono text-cyan-400 text-lg">${tx.amount} $BUNK</span>`)}
                    ${detailItem('Sender', utils.createHashLink('address', tx.sender, false))}
                    ${detailItem('Recipient', utils.createHashLink('address', tx.recipient, false))}
                </dl>
            </div>
        `;
    }
};


// --- ROUTER ---
const router = async () => {
    const path = window.location.hash.substring(1); // Remove #
    const parts = path.split('/').filter(p => p); // E.g., ['block', 'somehash']

    const route = parts[0] || '';
    const param = parts[1] || '';

    switch (route) {
        case 'block':
            await templates.renderBlockView(param);
            break;
        case 'address':
            await templates.renderAddressView(param);
            break;
        case 'tx':
            await templates.renderTxView(param);
            break;
        default:
            await templates.renderDashboard();
            break;
    }
};


// --- EVENT LISTENERS ---
const handleSearch = async (event) => {
    if (event.key === 'Enter') {
        const query = searchInput.value.trim();
        if (!query) return;

        searchInput.disabled = true;
        const result = await utils.fetchAPI(`/search/${query}`);
        searchInput.disabled = false;

        if (result && result.type) {
            window.location.hash = `/${result.type}/${result.data.hash || result.data.transaction_id || result.data.address}`;
        } else {
            utils.showToast("Search returned no results.");
        }
        searchInput.value = '';
    }
};

// Initial page load and hash changes
window.addEventListener('hashchange', router);
window.addEventListener('load', router);

// Search input listener
searchInput.addEventListener('keypress', handleSearch);

// Auto-refresh dashboard every 10 seconds if on the homepage
setInterval(() => {
    if (window.location.hash === '' || window.location.hash === '#/') {
        console.log("Auto-refreshing dashboard...");
        templates.renderDashboard();
    }
}, 10000);
                                                                         
