**The Education Layer for the Decentralized Web**

</div>

<p align="center">
  <img alt="GitHub License" src="https://img.shields.io/github/license/ReOneSec/BunkNet?style=for-the-badge&color=007CF0">
  <img alt="Python Version" src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white&color=007CF0">
  <img alt="Contributions Welcome" src="https://img.shields.io/badge/Contributions-Welcome-brightgreen?style=for-the-badge">
  <img alt="Maintenance" src="https://img.shields.io/badge/Maintained%3F-Yes-brightgreen?style=for-the-badge">
  <img alt="GitHub Stars" src="https://img.shields.io/github/stars/ReOneSec/BunkNet?style=for-the-badge&color=00DFD8">
</p>

---

### 🎯 Our Mission
> To systematically dismantle the barriers to Web3 development by providing a comprehensive, zero-cost, and integrated "flight simulator" for blockchain. We are building a public utility to empower the next million developers from India and across the globe.

---

### 📚 Table of Contents
- [💡 **Why BunkNet?**](#-why-bunknet-solving-the-web3-learning-trilemma)
- [🌍 **The Ecosystem**](#-the-bunknet-ecosystem-a-deep-dive)
- [🏗️ **System Architecture**](#-system-architecture)
- [🚀 **Getting Started**](#-getting-started-your-first-5-minutes)
- [🛠️ **Technology Stack**](#-technology-stack--design-rationale)
- [🗺️ **Project Roadmap**](#-project-roadmap)
- [🤝 **Contributing & Community**](#-contributing--community)

---

### 💡 Why BunkNet? Solving the Web3 Learning Trilemma

An aspiring developer today faces a difficult choice between platforms that are either too expensive, too isolated, or too unstable. BunkNet is architected to provide a solution that offers the best of all worlds.

| Feature                      | **Public Testnets (e.g., Sepolia)** | **Local Chains (e.g., Hardhat)** | **✅ BunkNet (The Solution)** |
| ---------------------------- | ----------------------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| **Cost** | ❌ **Costly/Inconvenient:** Requires real ETH for bridging or unreliable faucets. | ✅ **Free:** No real funds needed.                                  | ✅ **Truly Free & Accessible:** No bridging required. Our high-throughput faucet is reliable and easy to use.           |
| **Realism & Collaboration** | ✅ **Realistic:** A shared, persistent state for collaborative building. | ❌ **Isolated:** Runs only on your machine. Cannot collaborate with others. | ✅ **Shared & Realistic:** A persistent, public state where you can build and interact with dApps from other learners. |
| **Stability & User Experience** | ❌ **Unstable:** Prone to reorganizations, spam, and deprecation. | ✅ **Stable:** Fully controlled by you.                           | ✅ **Highly Stable:** Professionally managed PoA network with predictable uptime and performance, optimized for learning. |
| **Focus** | ❌ **Speculative:** Often treated as a "pre-mainnet," attracting bots and airdrop hunters. | ✅ **Focused:** Purely for development.                             | ✅ **Purely Educational:** Our `$BUNK` token has zero monetary value, ensuring the entire ecosystem remains focused on building skills. |

---

### 🌍 The BunkNet Ecosystem: A Deep Dive
BunkNet provides a complete suite of integrated tools designed for a seamless, end-to-end learning journey.

| Component                 | Description                                                                                                                                                                                            |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **⛓️ BunkChain** | A high-speed, EVM-compatible blockchain running a stable Proof-of-Authority (PoA) consensus. It's built for instant feedback, a crucial element for effective learning and debugging.                     |
| **🔎 BunkScan Explorer** | A didactic block explorer that translates raw blockchain data into human-readable insights. It decodes transaction data, explains gas fees, and visualizes contract interactions to demystify Web3. |
| **💰 The `$BUNK` Token** | The native utility token of the BunkChain, obtainable for free from our faucet. Its **zero-value** design is a core feature, ensuring a purely educational, speculation-free environment.             |
| **💻 Wallets (CLI & Bot)** | We offer a powerful **CLI Wallet** for developers and a user-friendly **Telegram Bot** (`BunkPay_Bot`) for beginners, ensuring everyone can access and interact with the BunkNet ecosystem easily.     |
| **💧 The Faucet** | A simple, reliable web service that dispenses free `$BUNK` tokens. This ensures any developer can start building immediately, removing all financial friction from the learning process.                  |

---

### 🏗️ System Architecture
Our infrastructure is designed for reliability and clarity. User interactions flow from the wallet clients to our backend services, which are kept running 24/7 by a process manager.

mermaid
graph LR
    subgraph User
        A[👨‍💻 You]
    end

    subgraph Wallets
        B[💻 CLI Wallet]
        C[🤖 Telegram Bot]
    end

    subgraph "Server Infrastructure (Hosted on VPS)"
        D[🌐 Nginx Reverse Proxy]
        E[⚙️ BFF API Service (PM2)]
        F[⛓️ BunkChain Node (PM2)]
    end
    
    A --> B & C
    B & C --> D
    D --> E
    E --> F

    linkStyle 0 stroke:#007CF0,stroke-width:2px;
    linkStyle 1 stroke:#00DFD8,stroke-width:2px;
    linkStyle 2 stroke:#9C27B0,stroke-width:2px;

🚀 Getting Started: Your First 5 Minutes
Get the BunkNet CLI Wallet running on your local machine and start building.
1️⃣ Prerequisites
 * Git installed on your system.
 * Python 3.8+ and pip installed.
2️⃣ Clone the Repository
Open your terminal and clone the project:
git clone [https://github.com/ReOneSec/BunkNet.git](https://github.com/ReOneSec/BunkNet.git)
cd BunkNet

3️⃣ Set Up Environment & Install Dependencies
Using a virtual environment is highly recommended to avoid conflicts.
# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate

# Install all required Python packages
pip install -r requirements.txt

> Note: The requirements.txt file contains all necessary packages, including requests, mnemonic, ecdsa, and pycryptodome.
> 
4️⃣ Launch the Wallet!
You're all set. Run the interactive application:
python3 wallet.py

> IMPORTANT: On your first run, select option 1 to create a new wallet. Immediately write down your 12-word seed phrase on paper and store it in a secure, offline location. This is your master key!
> 
🛠️ Technology Stack & Design Rationale
Every technology in our stack was deliberately chosen to maximize educational value, stability, and ease of use.
<details>
<summary><strong>Expand to see the detailed Technology Stack and our reasoning...</strong></summary>
<br>
| Category | Technology | Rationale |
|---|---|---|
| Blockchain Core | Python | Chosen for its exceptional readability and extensive libraries, making the core logic approachable and easy for learners to study and understand. |
| Consensus | Proof-of-Authority (PoA) | Provides stable, predictable block times and high throughput with zero energy cost, creating a reliable platform ideal for an educational setting. |
| Cryptography | ecdsa, pycryptodome | Implements industry-standard cryptography (SECP256k1, AES-256, PBKDF2) to teach and enforce best practices for key management and on-device security. |
| Web Frontend | HTML, Tailwind CSS, JS | Tailwind CSS allows for the rapid development of a modern, responsive, and highly customizable user interface without writing extensive custom CSS. |
| Web Server | Nginx | A high-performance, battle-tested web server used as a reverse proxy to securely manage and route traffic to our various backend services. |
| Process Manager | PM2 | A robust process manager that keeps our backend API and blockchain node running 24/7 and simplifies logging, monitoring, and deployments. |
</details>
### 🗺️ Project Roadmap

We are committed to the long-term growth and evolution of BunkNet. Our roadmap is transparent, and we are excited to build this future with our community.

> ### ✅ Phase 1: Foundation (Completed)
>
> - [x] **Launch BunkChain Testnet v1.0:** The core educational ledger is live and stable.
> - [x] **Deploy Core Tools:** The Faucet and BunkScan Explorer are publicly accessible.
> - [x] **Release Wallets:** The interactive CLI Wallet and BunkPay Telegram Bot are available for all users.
> - [x] **First Community Event:** Successfully hosted our first virtual hackathon with leading tech institutes in India.

> ### ⏳ Phase 2: Enrichment & Adoption (In Progress)
>
> - [ ] **Interactive Learning Platform:** Developing web-based tutorials with an integrated, in-browser code editor.
> - [ ] **University Partnership Program:** Establishing official partnerships with top universities to integrate BunkNet into their curricula.
> - [ ] **BunkNet Builders Grant:** Finalizing the framework for a grant program to fund innovative educational dApps.

> ### 🚀 Phase 3: Future Vision
>
> - [ ] **Mock DAO Governance:** Implement a mock DAO framework to teach the principles of Web3 governance.
> - [ ] **Cross-Chain Bridge:** Develop a secure testnet bridge to Sepolia for learning about interoperability.
> - [ ] **Global Expansion:** Scale our hackathon and workshop initiatives to a global audience.

---

### 🤝 How to Contribute

BunkNet is built by the community, for the community. We are grateful for any contributions, from reporting a bug to submitting new features.

1.  **Fork the repository** on GitHub.
2.  **Create a new branch** for your feature or bug fix (`git checkout -b your-feature-name`).
3.  **Make your changes** and commit them with a clear, descriptive message.
4.  **Push your branch** to your fork (`git push origin your-feature-name`).
5.  **Open a Pull Request** back to our main repository.

> Please read our `CONTRIBUTING.md` file for more detailed guidelines and best practices.

### 💬 Join Our Community

Ask questions, share your projects, and connect with thousands of other learners and developers in the BunkNet community.

<p>
  <a href="https://discord.gg/your-invite-link">
    <img alt="Discord" src="https://img.shields.io/badge/Discord-Join%20Chat-7289DA?style=for-the-badge&logo=discord&logoColor=white">
  </a>
  <a href="https://twitter.com/your-twitter-handle">
    <img alt="Twitter" src="https://img.shields.io/badge/Twitter-Follow%20Us-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white">
  </a>
</p>

---

### 📜 License

This project is proudly open-source and available under the Apache 2.0 License.

<a href="LICENSE">
  <img alt="GitHub License" src="https://img.shields.io/github/license/ReOneSec/BunkNet?style=for-the-badge&color=007CF0">
</a>

---

<div align="center">
<h3>Built with ❤️ for the next generation of developers.</h3>
</div>
