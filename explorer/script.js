// --- CONFIGURATION ---
const API_BASE_URL = "/api";
const POLLING_RATE_MS = 10000;

// --- DOM ELEMENTS & STATE ---
const appRoot = document.getElementById('app-root');
const searchInput = document.getElementById('searchInput');
let dashboardPollId = null;
let addressLabels = new Map();
let transactionChart = null;

// =============================================================================
// UTILS & HELPERS
// =============================================================================
const utils = {
    async fetchAPI(endpoint) {
        try {
            const response = await fetch(`${API_BASE_URL}${endpoint}`);
            if (!response.ok) {
                let errorMessage = `API Error: ${response.status}`;
                try { errorMessage = (await response.json()).error || errorMessage; } catch (e) {}
                throw new Error(errorMessage);
            }
            return await response.json();
        } catch (error) {
            console.error(`Fetch error from ${endpoint}:`, error);
            templates.renderError(error.message || "Could not connect to the BunkNet network.");
            return null;
        }
    },
    copyToClipboard(text) { navigator.clipboard.writeText(text).then(() => alert("Copied to clipboard!")); },
    formatTimeAgo(timestamp) {
        const seconds = (Date.now() - timestamp * 1000) / 1000;
        if (seconds < 60) return `${Math.round(seconds)}s ago`;
        if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
        if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
        return `${Math.round(seconds / 86400)}d ago`;
    },
    getDisplayName(address) {
        const label = addressLabels.get(address);
        if (label) return `<span class="font-bold text-indigo-600">${label}</span>`;
        if (address === '0') return `<span class="text-text-secondary">Network Reward</span>`;
        return `<a href="#/address/${address}" class="hash-link">${address.substring(0, 8)}...${address.substring(address.length - 8)}</a>`;
    },
    formatHashRate(hashes) {
        if (!hashes || hashes < 1000) return `${(hashes || 0).toFixed(0)} H/s`;
        if (hashes < 1000000) return `${(hashes / 1000).toFixed(2)} kH/s`;
        return `${(hashes / 1000000).toFixed(2)} MH/s`;
    }
};

// =============================================================================
// TEMPLATES / VIEWS
// =============================================================================
const templates = {
    renderLoading() { appRoot.innerHTML = `<div class="text-center p-8 text-text-secondary"><i class="fa-solid fa-spinner fa-spin text-4xl text-accent-primary"></i></div>`; },
    renderError(message) { appRoot.innerHTML = `<div class="content-card text-center p-8"><i class="fa-solid fa-triangle-exclamation text-red-500 text-4xl mb-4"></i><h2 class="text-2xl font-bold">An Error Occurred</h2><p class="text-text-secondary mt-2">${message}</p><a href="#" class="mt-6 inline-block bg-accent-primary text-white font-bold py-2 px-4 rounded-lg">Back to Home</a></div>`; },
    renderTransactionChart(blocks) {
        const canvas = document.getElementById('txChart');
        if (!canvas) return;
        if (transactionChart) transactionChart.destroy();
        transactionChart = new Chart(canvas.getContext('2d'), {
            type: 'line',
            data: {
                labels: blocks.map(b => `#${b.index}`).reverse(),
                datasets: [{
                    label: 'Transactions per Block',
                    data: blocks.map(b => b.transactions.length).reverse(),
                    borderColor: 'var(--accent-primary)',
                    backgroundColor: 'rgba(0, 123, 255, 0.1)',
                    fill: true, tension: 0.4, borderWidth: 2,
                    pointBackgroundColor: 'var(--accent-primary)',
                }]
            },
            options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, ticks: { color: 'var(--text-secondary)', stepSize: 1 } }, x: { ticks: { color: 'var(--text-secondary)' } } }, plugins: { legend: { display: false } } }
        });
    },

    async renderDashboard() {
        appRoot.innerHTML = `
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div class="content-card p-4"><p class="text-sm font-bold text-text-secondary">LATEST BLOCK</p><p id="stats-latest-block" class="text-2xl font-bold text-accent-primary skeleton h-8 w-24 rounded mt-1"></p></div>
                <div class="content-card p-4"><p class="text-sm font-bold text-text-secondary">AVG BLOCK TIME</p><p id="stats-avg-block-time" class="text-2xl font-bold text-accent-primary skeleton h-8 w-20 rounded mt-1"></p></div>
                <div class="content-card p-4"><p class="text-sm font-bold text-text-secondary">PENDING TXs</p><p id="stats-pending-txs" class="text-2xl font-bold text-accent-primary skeleton h-8 w-16 rounded mt-1"></p></div>
                <div class="content-card p-4"><p class="text-sm font-bold text-text-secondary">HASH RATE</p><p id="stats-hash-rate" class="text-2xl font-bold text-accent-primary skeleton h-8 w-28 rounded mt-1"></p></div>
            </div>
            
            <div class="content-card p-4 h-72 flex flex-col mb-6">
                <p class="text-sm font-bold text-text-secondary mb-2">TRANSACTION ACTIVITY</p>
                <div class="flex-grow relative"><canvas id="txChart"></canvas></div>
            </div>
            
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div class="content-card">
                    <h2 class="text-xl font-bold p-4 border-b border-border-color">Latest Blocks</h2>
                    <div id="latest-blocks-list" class="data-table-container"></div>
                </div>
                <div class="content-card">
                    <h2 class="text-xl font-bold p-4 border-b border-border-color">Latest Confirmed Transactions</h2>
                    <div id="latest-txs-list" class="data-table-container"></div>
                </div>
            </div>
        `;
        this.updateDashboard();
    },

    async updateDashboard() {
        const [status, blocksData] = await Promise.all([
            utils.fetchAPI('/status'), 
            utils.fetchAPI('/blocks?limit=50')
        ]);
        if (!status || !blocksData) return;

        const updateElement = (id, value) => { const el = document.getElementById(id); if (el) { el.textContent = value; el.classList.remove('skeleton','h-8','w-28','w-24','w-20','w-16','mt-1'); } };
        updateElement('stats-latest-block', `#${status.chain_length || 0}`);
        updateElement('stats-avg-block-time', `${(status.average_block_time || 0).toFixed(2)}s`);
        updateElement('stats-pending-txs', status.pending_transactions || 0);
        updateElement('stats-hash-rate', utils.formatHashRate(status.hash_rate || 0));
        
        this.renderTransactionChart(blocksData.chain.slice(0, 10));

        document.getElementById('latest-blocks-list').innerHTML = `<table class="data-table"><thead><tr><th>Block</th><th>Hash</th><th>TXs</th><th class="text-right">Time</th></tr></thead><tbody>${blocksData.chain.map(b => `
            <tr><td><a href="#/block/${b.index}" class="hash-link">#${b.index}</a></td><td><a href="#/block/${b.hash}" class="hash-link font-mono text-xs">${b.hash.substring(0, 10)}...</a></td><td>${b.transactions.length}</td><td class="text-right text-xs text-text-secondary">${utils.formatTimeAgo(b.timestamp)}</td></tr>`).join('')}</tbody></table>`;
        
        const latestTxs = blocksData.chain.flatMap(b => b.transactions).sort((a, b) => b.timestamp - a.timestamp).slice(0, 50);
        document.getElementById('latest-txs-list').innerHTML = `<table class="data-table"><thead><tr><th>Hash</th><th>From</th><th>To</th><th class="text-right">Amount</th></tr></thead><tbody>${latestTxs.map(tx => `
            <tr><td><a href="#/transaction/${tx.transaction_id}" class="hash-link font-mono text-xs">${tx.transaction_id.substring(0, 10)}...</a></td><td>${utils.getDisplayName(tx.sender)}</td><td>${utils.getDisplayName(tx.recipient)}</td><td class="text-right font-mono font-bold text-accent-primary">${parseFloat(tx.amount).toFixed(2)} $BUNK</td></tr>`).join('')}</tbody></table>`;
    },

    async renderDetailView(fetchData, renderContent) {
        this.renderLoading();
        const data = await fetchData();
        if (!data) return;
        appRoot.innerHTML = renderContent(data);
    },

    async renderBlockView(identifier) {
        await this.renderDetailView(() => utils.fetchAPI(`/block/${identifier}`), block => {
            const detailItem = (label, content) => `<div class="py-4 px-6 grid grid-cols-3 gap-4 border-b border-border-color last:border-b-0"><dt class="font-semibold text-text-secondary">${label}</dt><dd class="col-span-2 break-all">${content}</dd></div>`;
            return `
                <h2 class="text-3xl font-bold mb-6">Block #${block.index}</h2>
                <div class="content-card">
                    <dl>${detailItem('Block Hash', `<div class="flex items-center gap-2 font-mono">${block.hash}</div>`)} ${detailItem('Timestamp', `${new Date(block.timestamp * 1000).toLocaleString()}`)} ${detailItem('Previous Hash', `<a href="#/block/${block.previous_hash}" class="hash-link font-mono">${block.previous_hash}</a>`)}</dl>
                </div>
                <h3 class="text-2xl font-bold mt-8 mb-4">Transactions</h3>
                <div class="content-card data-table-container">
                    <table class="data-table">
                        <thead><tr><th>Hash</th><th>From</th><th>To</th><th class="text-right">Amount</th></tr></thead>
                        <tbody>${block.transactions.map(tx => `
                            <tr><td><a href="#/transaction/${tx.transaction_id}" class="hash-link font-mono text-xs">${tx.transaction_id.substring(0, 10)}...</a></td><td>${utils.getDisplayName(tx.sender)}</td><td>${utils.getDisplayName(tx.recipient)}</td><td class="text-right font-mono font-bold text-accent-primary">${parseFloat(tx.amount).toFixed(2)} $BUNK</td></tr>`).join('')}</tbody>
                    </table>
                </div>`;
        });
    },

    async renderAddressView(address) {
        await this.renderDetailView(() => utils.fetchAPI(`/address/${address}`), data => `
            <h2 class="text-2xl font-semibold mb-1 truncate">${data.label || 'Address Details'}</h2>
            <div class="flex items-center gap-2 mb-8"><p class="font-mono text-text-secondary break-all">${address}</p></div>
            <div class="content-card p-6 text-center"><p class="text-text-secondary text-sm font-bold">BALANCE</p><p class="text-4xl font-black text-accent-primary">${data.balance.toFixed(4)} $BUNK</p></div>
            <h3 class="text-2xl font-semibold mt-8 mb-4">Transaction History (${data.transactions.length})</h3>
            <div class="content-card data-table-container">
                <table class="data-table">
                    <thead><tr><th>Hash</th><th>From</th><th>To</th><th class="text-right">Amount & Time</th></tr></thead>
                    <tbody>${data.transactions.length ? data.transactions.slice().reverse().map(tx => `
                        <tr><td><a href="#/transaction/${tx.transaction_id}" class="hash-link font-mono text-xs">${tx.transaction_id.substring(0, 12)}...</a></td><td>${utils.getDisplayName(tx.sender)}</td><td>${utils.getDisplayName(tx.recipient)}</td><td class="text-right"><span class="${tx.recipient === address ? 'text-green-500' : 'text-red-500'} font-mono">${tx.recipient === address ? '+' : '-'}${parseFloat(tx.amount).toFixed(2)}</span><br><span class="text-xs text-text-secondary">${utils.formatTimeAgo(tx.timestamp)}</span></td></tr>`).join('') : ''}</tbody>
                </table>
                ${!data.transactions.length ? '<p class="p-4 text-text-secondary">No transactions for this address.</p>' : ''}
            </div>`);
    },

    async renderTransactionView(txId) {
        await this.renderDetailView(() => utils.fetchAPI(`/transaction/${txId}`), tx => {
            const detailItem = (label, content) => `<div class="py-4 px-6 grid grid-cols-3 gap-4 border-b border-border-color last:border-b-0"><dt class="font-semibold text-text-secondary">${label}</dt><dd class="col-span-2 break-all">${content}</dd></div>`;
            return `
                <h2 class="text-3xl font-bold mb-6">Transaction Details</h2>
                <div class="content-card">
                    <dl>${detailItem('Tx Hash', `<div class="flex items-center gap-2 font-mono">${tx.transaction_id}</div>`)} ${detailItem('Block', `<a href="#/block/${tx.block_index}" class="hash-link">#${tx.block_index}</a>`)} ${detailItem('From', utils.getDisplayName(tx.sender, false))} ${detailItem('To', utils.getDisplayName(tx.recipient, false))} ${detailItem('Amount', `<span class="font-mono text-lg font-bold text-accent-primary">${parseFloat(tx.amount).toFixed(4)} $BUNK</span>`)}</dl>
                </div>`;
        });
    }
};

// =============================================================================
// ROUTER & APP INITIALIZATION
// =============================================================================
async function router() {
    if (dashboardPollId) clearInterval(dashboardPollId);
    const [view, param] = (window.location.hash.substring(2) || 'dashboard').split('/');
    const routes = {
        block: templates.renderBlockView,
        address: templates.renderAddressView,
        transaction: templates.renderTransactionView,
        dashboard: templates.renderDashboard
    };
    const action = routes[view] || routes.dashboard;
    await action.call(templates, param);
    if (!view || view === 'dashboard') {
        dashboardPollId = setInterval(() => templates.updateDashboard(), POLLING_RATE_MS);
    }
}

async function handleSearch(event) {
    if (event.key !== 'Enter') return;
    const query = searchInput.value.trim();
    if (!query) return;
    window.location.hash = (query.startsWith('0x') && query.length === 42) ? `/address/${query}` : (query.length === 64) ? `/block/${query}` : !isNaN(parseInt(query)) ? `/block/${query}` : `/transaction/${query}`;
    searchInput.value = '';
}

async function init() {
    const labelsData = await utils.fetchAPI('/labels');
    if (labelsData) addressLabels = new Map(Object.entries(labelsData));
    
    // --- NAVBAR CODE ---
    const navToggleBtn = document.getElementById('nav-toggle');
    const mobileMenu = document.getElementById('mobile-menu');

    if (navToggleBtn && mobileMenu) {
        navToggleBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            mobileMenu.classList.toggle('hidden');
        });

        window.addEventListener('click', (e) => {
            if (!mobileMenu.classList.contains('hidden') && !mobileMenu.contains(e.target) && !navToggleBtn.contains(e.target)) {
                mobileMenu.classList.add('hidden');
            }
        });
    }
    // --- END NAVBAR CODE ---

    window.addEventListener('hashchange', router);
    searchInput.addEventListener('keypress', handleSearch);
    await router();
}

document.addEventListener('DOMContentLoaded', init);
    
