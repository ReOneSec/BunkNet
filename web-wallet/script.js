// --- APPLICATION SETUP ---
const App = {
    // Application State
    state: {
        keyPair: null,
        address: null,
        balance: 0,
        history: [],
        contacts: [],
        activeView: 'dashboard',
        apiStatus: 'disconnected',
        apiEndpoint: localStorage.getItem('bunknet_api_endpoint') || 'http://localhost:7000/api'
    },

    // Initialization: Check for an existing encrypted wallet
    init() {
        const encryptedWallet = localStorage.getItem('bunknet_wallet');
        if (encryptedWallet) {
            this.ui.renderView('unlock');
        } else {
            this.ui.renderView('welcome');
        }
    },

    // Main login/unlock function using a password
    unlockWallet(password) {
        try {
            const encryptedWallet = localStorage.getItem('bunknet_wallet');
            const mnemonic = this.crypto.decrypt(encryptedWallet, password);
            if (!mnemonic || !bip39.validateMnemonic(mnemonic)) {
                throw new Error("Decryption failed or invalid mnemonic.");
            }
            this.state.keyPair = this.crypto.getKeysFromMnemonic(mnemonic);
            this.state.address = this.state.keyPair.getPublic('hex');
            this.state.contacts = JSON.parse(localStorage.getItem('bunknet_contacts') || '[]');
            
            this.ui.renderAppLayout(); // Render the main app shell
            this.ui.renderView('dashboard'); // Go to the dashboard
            this.startSync();
            this.ui.showToast("Wallet Unlocked!");
        } catch (e) {
            console.error(e);
            this.ui.showToast("Incorrect password or corrupted wallet.", true);
        }
    },
    
    // Create and encrypt a new wallet
    createWallet(mnemonic, password) {
        const encrypted = this.crypto.encrypt(mnemonic, password);
        localStorage.setItem('bunknet_wallet', encrypted);
        localStorage.setItem('bunknet_contacts', '[]');
        this.unlockWallet(password);
    },

    // Logout and clear sensitive in-memory data
    logout() {
        this.state.keyPair = null;
        this.state.address = null;
        this.state.balance = 0;
        this.state.history = [];
        this.stopSync();
        window.location.reload(); // Easiest way to reset the UI state to login
    },

    // Sync data with the backend API
    async syncData() {
        if (!this.state.address) return;
        try {
            const data = await this.api.getAddressInfo(this.state.address);
            this.state.balance = data.balance;
            this.state.history = data.transactions;
            this.state.apiStatus = 'connected';
        } catch (e) {
            this.state.apiStatus = 'disconnected';
            console.error("Sync failed:", e);
        }
        // Re-render the current view to update data without a full reload
        this.ui.renderView(this.state.activeView, true); 
    },

    // Start periodic data synchronization
    startSync() {
        this.stopSync();
        this.syncData();
        this._syncInterval = setInterval(() => this.syncData(), 15000);
    },

    // Stop periodic data synchronization
    stopSync() {
        if (this._syncInterval) clearInterval(this._syncInterval);
    },
    
    // Address Book Management
    saveContacts() {
        localStorage.setItem('bunknet_contacts', JSON.stringify(this.state.contacts));
    },
    addContact(name, address) {
        if (name && address) {
            this.state.contacts.push({ name, address });
            this.saveContacts();
            this.ui.renderView('addressBook');
            this.ui.showToast("Contact Added!");
        } else {
            this.ui.showToast("Name and address are required.", true);
        }
    },
    deleteContact(index) {
        this.ui.showModal(
            'Delete Contact',
            `<p>Are you sure you want to delete this contact?</p>`,
            [{ text: 'Cancel', class: 'btn-secondary', action: 'close' },
             { text: 'Delete', class: 'btn-danger', action: () => {
                this.state.contacts.splice(index, 1);
                this.saveContacts();
                this.ui.renderView('addressBook');
                this.ui.showToast("Contact Deleted!", true);
             }}]
        );
    }
};

// --- CRYPTOGRAPHY MODULE ---
App.crypto = {
    ec: new elliptic.ec('secp256k1'),
    generateMnemonic: () => bip39.generateMnemonic(),
    getKeysFromMnemonic: (m) => App.crypto.ec.keyFromPrivate(bip39.mnemonicToSeedSync(m).slice(0, 32)),
    encrypt: (text, pass) => CryptoJS.AES.encrypt(text, pass).toString(),
    decrypt: (cipher, pass) => CryptoJS.AES.decrypt(cipher, pass).toString(CryptoJS.enc.Utf8),
    signTransaction(transaction) {
        const key = App.state.keyPair;
        const txData = { sender: transaction.sender, recipient: transaction.recipient, amount: transaction.amount };
        const txDataStr = JSON.stringify(txData, Object.keys(txData).sort());
        const txHash = sha256(txDataStr);
        const signature = key.sign(txHash, 'hex', { canonical: true });
        return signature.toDER('hex');
    }
};

// --- API MODULE ---
App.api = {
    async _fetch(endpoint, options = {}) {
        try {
            const response = await fetch(`${App.state.apiEndpoint}${endpoint}`, options);
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || `API Error: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            App.state.apiStatus = 'disconnected';
            App.ui.renderView(App.state.activeView, true);
            throw error;
        }
    },
    getAddressInfo: (addr) => App.api._fetch(`/address/${addr}`),
    sendTransaction: (tx) => App.api._fetch('/new_transaction', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(tx)
    })
};

// --- UI MODULE ---
App.ui = {
    renderAppLayout() {
        document.getElementById('app-container').innerHTML = `
            <div id="wallet-layout" class="flex h-screen">
                <aside id="sidebar" class="sidebar w-20 lg:w-64 flex-shrink-0 flex flex-col hidden"></aside>
                <main id="main-content" class="flex-1 overflow-y-auto p-6 sm:p-8"></main>
            </div>`;
    },
    renderView(viewName, isUpdate = false) {
        App.state.activeView = viewName;
        const mainContent = document.getElementById('main-content') || document.getElementById('app-container');
        if (!isUpdate) {
            mainContent.innerHTML = `<div class="flex justify-center items-center h-full"><i class="fa-solid fa-spinner fa-spin fa-3x text-gray-500"></i></div>`;
        }
        
        document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
        const activeLink = document.getElementById(`nav-${viewName}`);
        if(activeLink) activeLink.classList.add('active');

        const renderers = {
            welcome: this.renderWelcomeView.bind(this), unlock: this.renderUnlockView.bind(this), create: this.renderCreateView.bind(this),
            import: this.renderImportView.bind(this), dashboard: this.renderDashboardView.bind(this), send: this.renderSendView.bind(this),
            receive: this.renderReceiveView.bind(this), addressBook: this.renderAddressBookView.bind(this), settings: this.renderSettingsView.bind(this),
        };
        if(renderers[viewName]) renderers[viewName]();
    },

    // --- ONBOARDING VIEWS ---
    renderWelcomeView() {
        const target = document.getElementById('app-container');
        target.innerHTML = `
            <div class="flex items-center justify-center min-h-screen">
                <div class="w-full max-w-md mx-auto card p-8 text-center">
                    <h1 class="text-3xl font-bold mb-2">Welcome to BunkNet</h1>
                    <p class="text-gray-400 mb-8">Your secure portal to the BunkNet network.</p>
                    <div class="space-y-4">
                        <button id="create-btn" class="btn btn-primary w-full">Create New Wallet</button>
                        <button id="import-btn" class="btn btn-secondary w-full">Import Wallet</button>
                    </div>
                </div>
            </div>`;
        document.getElementById('create-btn').onclick = () => this.renderView('create');
        document.getElementById('import-btn').onclick = () => this.renderView('import');
    },
    renderUnlockView() {
        const target = document.getElementById('app-container');
        target.innerHTML = `
            <div class="flex items-center justify-center min-h-screen">
                <form id="unlock-form" class="w-full max-w-md mx-auto card p-8 text-center">
                    <h1 class="text-3xl font-bold mb-2">Unlock Wallet</h1>
                    <p class="text-gray-400 mb-8">Enter your password to continue.</p>
                    <input id="password-input" type="password" class="input-field mb-4" placeholder="Password" required>
                    <button type="submit" class="btn btn-primary w-full">Unlock</button>
                    <button id="reset-wallet-btn" type="button" class="mt-4 text-xs text-red-500 hover:underline">Forgot password? Reset Wallet</button>
                </form>
            </div>`;
        document.getElementById('unlock-form').onsubmit = (e) => {
            e.preventDefault();
            App.unlockWallet(document.getElementById('password-input').value);
        };
        document.getElementById('reset-wallet-btn').onclick = () => {
            this.showModal('Reset Wallet', `<p class="text-yellow-300">Are you absolutely sure? This will delete your encrypted wallet from this browser. You will need your seed phrase to recover it.</p>`,
                [{text: 'Cancel', class: 'btn-secondary', action: 'close'},
                 {text: 'Yes, Reset', class: 'btn-danger', action: () => {
                    localStorage.removeItem('bunknet_wallet');
                    localStorage.removeItem('bunknet_contacts');
                    window.location.reload();
                 }}]
            );
        };
    },
    renderCreateView() {
        const mnemonic = App.crypto.generateMnemonic();
        const target = document.getElementById('main-content') || document.getElementById('app-container');
        target.innerHTML = `
            <div class="max-w-xl mx-auto">
                <h1 class="text-3xl font-bold mb-4">Create New Wallet</h1>
                <div class="card p-6">
                    <h2 class="text-xl font-bold mb-4">1. Save Your Seed Phrase</h2>
                    <p class="text-yellow-400 bg-yellow-900/50 p-3 rounded-lg mb-6 text-sm"><i class="fa-solid fa-triangle-exclamation"></i> This is the ONLY way to recover your wallet. Keep it safe and secret!</p>
                    <div class="seed-phrase-grid mb-6">${mnemonic.split(' ').map((w, i) => `<div class="seed-word"><b>${i+1}.</b> ${w}</div>`).join('')}</div>
                    <form id="create-wallet-form">
                        <h2 class="text-xl font-bold mb-4 mt-8">2. Set a Strong Password</h2>
                        <p class="text-gray-400 mb-4 text-sm">This password encrypts your wallet for this device. You will need it to unlock your wallet on future visits.</p>
                        <div class="space-y-4">
                            <input id="password-set" type="password" class="input-field" placeholder="Enter password (min 8 chars)" required minlength="8">
                            <input id="password-confirm" type="password" class="input-field" placeholder="Confirm password" required>
                            <button type="submit" class="btn btn-primary w-full">Create & Encrypt Wallet</button>
                        </div>
                    </form>
                </div>
            </div>`;

        document.getElementById('create-wallet-form').onsubmit = (e) => {
            e.preventDefault();
            const pass = document.getElementById('password-set').value;
            const confirm = document.getElementById('password-confirm').value;
            if(pass !== confirm) {
                this.showToast("Passwords do not match.", true);
                return;
            }
            App.createWallet(mnemonic, pass);
        };
    },
    renderImportView() {
        const target = document.getElementById('main-content') || document.getElementById('app-container');
        target.innerHTML = `
            <div class="max-w-xl mx-auto">
                <h1 class="text-3xl font-bold mb-4">Import Wallet</h1>
                <form id="import-wallet-form" class="card p-6">
                    <div class="space-y-4">
                        <div>
                            <label class="text-sm font-bold text-gray-400 block mb-2">Seed Phrase</label>
                            <textarea id="seed-input" class="input-field h-24" placeholder="Enter your 12-word seed phrase..." required></textarea>
                        </div>
                        <div>
                            <label class="text-sm font-bold text-gray-400 block mb-2">New Password</label>
                            <input id="password-set" type="password" class="input-field" placeholder="Set a password for this device" required minlength="8">
                        </div>
                        <div>
                            <label class="text-sm font-bold text-gray-400 block mb-2">Confirm Password</label>
                            <input id="password-confirm" type="password" class="input-field" placeholder="Confirm your new password" required>
                        </div>
                        <button type="submit" class="btn btn-primary w-full">Import & Encrypt</button>
                        <button type="button" id="back-btn" class="btn btn-secondary w-full mt-2">Cancel</button>
                    </div>
                </form>
            </div>`;

        document.getElementById('back-btn').onclick = () => App.init();
        document.getElementById('import-wallet-form').onsubmit = (e) => {
            e.preventDefault();
            const mnemonic = document.getElementById('seed-input').value.trim();
            const pass = document.getElementById('password-set').value;
            const confirm = document.getElementById('password-confirm').value;
            if(pass !== confirm) {
                this.showToast("Passwords do not match.", true);
                return;
            }
            if (!bip39.validateMnemonic(mnemonic)) {
                this.showToast("Invalid seed phrase.", true);
                return;
            }
            App.createWallet(mnemonic, pass);
        };
    },

    // --- MAIN APP VIEWS ---
    renderDashboardView() {
        const history = App.state.history.slice().reverse().slice(0, 5);
        document.getElementById('main-content').innerHTML = `
            <h1 class="text-3xl font-bold mb-8">Dashboard</h1>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div class="card p-6">
                    <p class="text-sm font-semibold text-gray-400">TOTAL BALANCE</p>
                    <p class="text-4xl font-light text-cyan-400">${App.state.balance.toFixed(4)} <span class="text-2xl">$BUNK</span></p>
                </div>
                <div class="card p-6">
                    <p class="text-sm font-semibold text-gray-400">NETWORK STATUS</p>
                    <div class="flex items-center gap-3 mt-2">
                        <span class="h-3 w-3 rounded-full ${App.state.apiStatus === 'connected' ? 'bg-green-500 animate-pulse' : 'bg-red-500'}"></span>
                        <p class="text-lg capitalize">${App.state.apiStatus}</p>
                    </div>
                    <p class="text-xs text-gray-500 mt-2 break-all">${App.state.apiEndpoint}</p>
                </div>
            </div>
            <div class="mt-8">
                <div class="flex justify-between items-center mb-4"><h2 class="text-xl font-semibold">Recent Activity</h2><button id="refresh-btn" class="text-gray-400 hover:text-white"><i class="fa-solid fa-arrows-rotate"></i></button></div>
                <div class="card p-4 space-y-3">${history.length > 0 ? history.map(tx => `
                    <div class="flex justify-between items-center text-sm p-2">
                        <div class="flex items-center gap-3"><i class="fa-solid ${tx.sender === App.state.address ? 'fa-arrow-up text-red-400' : 'fa-arrow-down text-green-400'}"></i><div><p class="font-semibold">${tx.sender === App.state.address ? 'Sent' : 'Received'}</p><p class="text-xs text-gray-400">${new Date(tx.timestamp * 1000).toLocaleString()}</p></div></div>
                        <span class="font-bold font-mono">${tx.sender === App.state.address ? '-' : '+'}${tx.amount.toFixed(2)} $BUNK</span>
                    </div>`).join('') : '<p class="text-gray-500 text-center py-4">No transactions yet.</p>'}
                </div>
            </div>`;
        document.getElementById('refresh-btn').onclick = () => { App.syncData(); this.showToast("Data refreshed!"); };
        const sidebar = document.getElementById('sidebar');
        if (sidebar && sidebar.classList.contains('hidden')) { this.renderSidebar(); sidebar.classList.remove('hidden'); }
    },
    renderSendView() {
        const contactOptions = App.state.contacts.map(c => `<option value="${c.address}">${c.name} (${c.address.substring(0,6)}...)</option>`).join('');
        document.getElementById('main-content').innerHTML = `
            <h1 class="text-3xl font-bold mb-8">Send $BUNK</h1>
            <div class="max-w-lg mx-auto card p-8">
                <form id="send-form" class="space-y-6">
                    <div>
                        <label class="text-sm font-bold text-gray-400 block mb-2">Recipient</label>
                        <input id="recipient-addr" class="input-field" type="text" placeholder="Enter recipient address" required list="contact-datalist">
                        <datalist id="contact-datalist">${contactOptions}</datalist>
                        <p class="text-xs text-gray-500 mt-1">Or select from your contacts.</p>
                    </div>
                    <div>
                        <label class="text-sm font-bold text-gray-400 block mb-2">Amount</label>
                        <div class="relative"><input id="amount" class="input-field" type="number" step="0.01" placeholder="0.00" required><span class="absolute right-4 top-1/2 -translate-y-1/2 text-gray-400">$BUNK</span></div>
                        <p class="text-xs text-gray-500 mt-1">Your balance: ${App.state.balance.toFixed(4)} $BUNK</p>
                    </div>
                    <button type="submit" class="btn btn-primary w-full !mt-8">Review Transaction</button>
                </form>
            </div>`;

        document.getElementById('send-form').onsubmit = (e) => {
            e.preventDefault();
            const recipient = document.getElementById('recipient-addr').value;
            const amount = parseFloat(document.getElementById('amount').value);
            if (!recipient || !amount || amount <= 0) { return this.showToast("Please fill all fields.", true); }
            if (amount > App.state.balance) { return this.showToast("Insufficient balance.", true); }

            this.showModal('Confirm Transaction',
                `<div class="space-y-2 text-sm">
                    <p><strong>To:</strong> <span class="font-mono break-all">${recipient}</span></p>
                    <p><strong>Amount:</strong> <span class="font-bold text-cyan-400">${amount.toFixed(4)} $BUNK</span></p>
                </div>`,
                [{text: 'Cancel', class: 'btn-secondary', action: 'close'},
                 {text: 'Confirm & Send', class: 'btn-primary', action: async () => {
                    const transaction = { sender: App.state.address, recipient, amount };
                    const signature = App.crypto.signTransaction(transaction);
                    try {
                        await App.api.sendTransaction({ ...transaction, signature, public_key: App.state.address });
                        this.showToast("Transaction sent successfully!");
                        App.syncData();
                        this.renderView('dashboard');
                    } catch (e) { this.showToast(e.message, true); }
                 }}]
            );
        };
    },
    renderReceiveView() {
        document.getElementById('main-content').innerHTML = `
            <h1 class="text-3xl font-bold mb-8">Receive $BUNK</h1>
            <div class="max-w-md mx-auto card p-8 text-center">
                <p class="text-gray-400 mb-4">Share your public address or QR code below.</p>
                <div class="flex justify-center mb-4 bg-white p-4 rounded-lg"><canvas id="qr-code"></canvas></div>
                <div class="bg-gray-800 p-3 rounded-lg text-center font-mono text-sm break-all mb-4 cursor-pointer" onclick="App.ui.copyToClipboard('${App.state.address}')">${App.state.address}</div>
            </div>`;
        QRCode.toCanvas(document.getElementById('qr-code'), App.state.address, { width: 220, margin: 2 });
    },
    renderAddressBookView() {
        document.getElementById('main-content').innerHTML = `
            <h1 class="text-3xl font-bold mb-8">Address Book</h1>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                <div class="card p-6">
                    <h2 class="text-xl font-semibold mb-4">Add New Contact</h2>
                    <form id="add-contact-form" class="space-y-4">
                        <input id="contact-name" class="input-field" placeholder="Name / Label" required>
                        <input id="contact-address" class="input-field" placeholder="BunkNet Address" required>
                        <button type="submit" class="btn btn-primary w-full">Save Contact</button>
                    </form>
                </div>
                <div class="card p-6">
                    <h2 class="text-xl font-semibold mb-4">Saved Contacts (${App.state.contacts.length})</h2>
                    <div class="space-y-2 max-h-96 overflow-y-auto">${App.state.contacts.length > 0 ? App.state.contacts.map((c, i) => `
                        <div class="flex justify-between items-center bg-gray-800/50 p-3 rounded">
                            <div><p class="font-bold">${c.name}</p><p class="text-xs font-mono text-gray-400">${c.address.substring(0,12)}...</p></div>
                            <button class="text-red-500 hover:text-red-400" onclick="App.deleteContact(${i})"><i class="fa-solid fa-trash"></i></button>
                        </div>`).join('') : '<p class="text-gray-500 text-center py-4">No contacts saved.</p>'}
                    </div>
                </div>
            </div>`;
        document.getElementById('add-contact-form').onsubmit = (e) => {
            e.preventDefault();
            App.addContact(document.getElementById('contact-name').value, document.getElementById('contact-address').value);
        };
    },
    renderSettingsView() {
        document.getElementById('main-content').innerHTML = `
            <h1 class="text-3xl font-bold mb-8">Settings</h1>
            <div class="max-w-xl mx-auto space-y-8">
                <div class="card p-6">
                    <h2 class="text-xl font-semibold mb-4">API Configuration</h2>
                    <label class="text-sm font-bold text-gray-400 block mb-2">BFF API Endpoint</label>
                    <input id="api-endpoint-input" class="input-field" value="${App.state.apiEndpoint}">
                    <button id="save-api-btn" class="btn btn-primary mt-4">Save</button>
                </div>
                <div class="card p-6 border-red-500/50">
                    <h2 class="text-xl font-semibold mb-2 text-red-400">Danger Zone</h2>
                    <p class="text-gray-400 text-sm mb-4">Viewing your private key is risky. Never share it with anyone.</p>
                    <button id="view-pk-btn" class="btn btn-danger">View Private Key</button>
                </div>
            </div>`;
        document.getElementById('save-api-btn').onclick = () => {
            const newEndpoint = document.getElementById('api-endpoint-input').value;
            App.state.apiEndpoint = newEndpoint;
            localStorage.setItem('bunknet_api_endpoint', newEndpoint);
            this.showToast("API endpoint updated!");
            App.syncData();
        };
        document.getElementById('view-pk-btn').onclick = () => {
            this.showModal('Your Private Key',
                `<p class="text-yellow-300 mb-4">This is highly sensitive information. Do not share it!</p>
                 <div class="bg-gray-900 p-3 rounded font-mono break-all text-sm">${App.state.keyPair.getPrivate('hex')}</div>`,
                [{text: 'Close', class: 'btn-secondary', action: 'close'}]
            );
        };
    },

    // --- SIDEBAR, MODALS AND TOASTS ---
    renderSidebar() {
        document.getElementById('sidebar').innerHTML = `
            <div class="p-4 text-center border-b border-gray-800"><h2 class="text-xl font-bold text-white"><span class="lg:hidden"><i class="fa-solid fa-cubes"></i></span><span class="hidden lg:inline">BunkNet Wallet</span></h2></div>
            <nav class="mt-6 flex-1">
                <a href="#" id="nav-dashboard" class="nav-link"><i class="fa-solid fa-wallet"></i><span class="hidden lg:inline ml-4">Dashboard</span></a>
                <a href="#" id="nav-send" class="nav-link"><i class="fa-solid fa-paper-plane"></i><span class="hidden lg:inline ml-4">Send</span></a>
                <a href="#" id="nav-receive" class="nav-link"><i class="fa-solid fa-qrcode"></i><span class="hidden lg:inline ml-4">Receive</span></a>
                <a href="#" id="nav-addressBook" class="nav-link"><i class="fa-solid fa-address-book"></i><span class="hidden lg:inline ml-4">Contacts</span></a>
                <a href="#" id="nav-settings" class="nav-link"><i class="fa-solid fa-cog"></i><span class="hidden lg:inline ml-4">Settings</span></a>
            </nav>
            <div class="p-4 mt-auto border-t border-gray-800"><button id="logout-btn" class="btn btn-secondary w-full"><i class="fa-solid fa-sign-out-alt"></i><span class="hidden lg:inline ml-2">Logout</span></button></div>`;
        document.getElementById('logout-btn').onclick = () => App.logout();
        document.querySelectorAll('.nav-link').forEach(link => {
            link.onclick = (e) => { e.preventDefault(); this.renderView(link.id.replace('nav-', '')); };
        });
    },
    showToast(message, isError = false) {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${isError ? 'bg-red-800' : 'bg-green-800'} text-white shadow-lg`;
        toast.textContent = message;
        container.appendChild(toast);
        setTimeout(() => toast.classList.add('show'), 10);
        setTimeout(() => { toast.classList.remove('show'); toast.addEventListener('transitionend', () => toast.remove()); }, 3000);
    },
    showModal(title, content, actions = []) {
        const modalContainer = document.getElementById('modal-container');
        const actionButtons = actions.map(a => `<button class="btn ${a.class}" id="modal-action-${a.text}">${a.text}</button>`).join('');
        modalContainer.innerHTML = `
            <div class="modal-content card p-6"><h2 class="text-xl font-bold mb-4">${title}</h2><div class="text-gray-300 mb-6">${content}</div><div class="flex justify-end gap-4">${actionButtons}</div></div>`;
        actions.forEach(a => {
            document.getElementById(`modal-action-${a.text}`).onclick = () => {
                if (typeof a.action === 'function') a.action();
                this.hideModal();
            };
        });
        modalContainer.classList.remove('hidden');
    },
    hideModal() {
        document.getElementById('modal-container').classList.add('hidden');
    }
};

// --- INITIALIZE THE APP ---
document.addEventListener('DOMContentLoaded', () => App.init());
