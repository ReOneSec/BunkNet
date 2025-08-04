<div align="center">
   
**A Functional Proof-of-Work Blockchain Ecosystem for Education**

</div>

<p align="center">
  <img alt="GitHub License" src="https://img.shields.io/github/license/ReOneSec/BunkNet?style=for-the-badge&color=007CF0&label=license&message=Apache%202.0">
  <img alt="Python Version" src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white&color=007CF0">
  <img alt="Contributions Welcome" src="https://img.shields.io/badge/Contributions-Welcome-brightgreen?style=for-the-badge">
  <img alt="Maintenance" src="https://img.shields.io/badge/Maintained%3F-Yes-brightgreen?style=for-the-badge">
  <img alt="GitHub Stars" src="https://img.shields.io/github/stars/ReOneSec/BunkNet?style=for-the-badge&color=00DFD8">
</p>

> BunkNet is a complete blockchain ecosystem built from the ground up as a practical and educational implementation of the core principles that power cryptocurrencies. Our mission is to provide a hands-on "flight simulator" for Web3, empowering the next million developers from India and across the globe.

---

### 📚 Table of Contents
- [🎯 **Live Ecosystem**](#-live-ecosystem)
- [💡 **Why BunkNet?**](#-why-bunknet-the-educational-advantage)
- [🌍 **Ecosystem Components**](#-ecosystem-components-a-deep-dive)
- [🏗️ **System Architecture**](#-system-architecture)
- [🚀 **Getting Started**](#-getting-started-your-first-5-minutes)
- [🛠️ **Technology Stack**](#-technology-stack--design-rationale)
- [🗺️ **Project Roadmap**](#-project-roadmap)
- [🤝 **Contributing & Community**](#-contributing--community)

---

### 🎯 Live Ecosystem

| Service          | Link                                                                                             | Status                                                                                                   |
| ---------------- | ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------- |
| 🌐 **Explorer** | [**explorer.bunknet.online**](http://explorer.bunknet.online)                                   | <img src="https://img.shields.io/website?url=http%3A%2F%2Fexplorer.bunknet.online&up_message=Online&down_message=Online&style=for-the-badge"> |
| 💧 **Faucet** | [**faucet.bunknet.online**](http://faucet.bunknet.online)                                       | <img src="https://img.shields.io/website?url=http%3A%2F%2Ffaucet.bunknet.online&up_message=Online&down_message=Offline&style=for-the-badge"> |
| 💼 **Web Wallet** | [**wallet.bunknet.online**](http://wallet.bunknet.online)                                       | <img src="https://img.shields.io/website?url=http%3A%2F%2Fwallet.bunknet.online&up_message=Online&down_message=Offline&style=for-the-badge"> |
| 💻 **CLI Wallet** | [**github.com/ReOneSec/BunkNet**](https://github.com/ReOneSec/BunkNet)                           | <img src="https://img.shields.io/badge/Status-Available-brightgreen?style=for-the-badge">                |

---

### 💡 Why BunkNet? The Educational Advantage

Learning blockchain is difficult. BunkNet is architected to provide the most authentic and comprehensive learning experience possible by focusing on foundational concepts like Proof-of-Work.

| Feature                      | **Public Testnets (e.g., Sepolia)** | **Local Chains (e.g., Hardhat)** | **✅ BunkNet (The Solution)** |
| ---------------------------- | ----------------------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| **Consensus Model** | Proof-of-Stake (Abstracted)                                       | Instant (Not a real consensus)                                        | ✅ **Tangible Proof-of-Work:** Experience a real, low-difficulty PoW environment. See mining and consensus in action.   |
| **Cost** | ❌ **Costly/Inconvenient:** Requires real ETH for bridging or unreliable faucets. | ✅ **Free:** No real funds needed.                                  | ✅ **Truly Free & Accessible:** Our high-throughput faucet provides all the test `$BUNK` you need to experiment.        |
| **Realism & Collaboration** | ✅ **Realistic:** A shared, persistent state for collaboration.       | ❌ **Isolated:** Runs only on your machine. Cannot build with others.     | ✅ **Shared & Realistic:** A persistent, public network where you can deploy dApps and interact with other learners.     |
| **Focus** | ❌ **Speculative:** Often treated as a "pre-mainnet" for airdrops and bots. | ✅ **Focused:** Purely for development.                             | ✅ **Purely Educational:** Our `$BUNK` token has zero monetary value, ensuring the entire ecosystem remains focused on building skills. |

---

### 🌍 Ecosystem Components: A Deep Dive

BunkNet provides a complete suite of integrated tools designed for a seamless, end-to-end learning journey.

| Component                 | Description                                                                                                                                                                                                                           |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **⛓️ Proof-of-Work Blockchain** | A fully functional blockchain built from scratch that uses a simple but effective PoW algorithm to secure the network. It's the perfect environment to understand mining, consensus, and decentralization. |
| **🔎 BunkScan Explorer** | A responsive Single-Page Application to view all on-chain activity in real-time. It translates raw blockchain data into human-readable insights, helping you trace transactions and understand block creation. |
| **💰 The `$BUNK` Token** | The native cryptocurrency of the BunkChain, featuring transaction fees and a **block reward halving schedule** to simulate real-world tokenomics. Its zero-value design keeps the focus on learning. |
| **💼 Web Wallet** | A full-featured, client-side web wallet with secure, encrypted login. It allows users to easily create wallets, save their seed phrase, and send/receive `$BUNK` through a user-friendly interface. |
| **💻 CLI Wallet** | A powerful interactive command-line interface for developers and power users. Perfect for scripting, automation, and understanding how wallets work under the hood. |
| **💧 The Faucet** | An automated web service that dispenses free test `$BUNK` to new users, providing a frictionless onboarding experience for anyone wanting to try out the ecosystem. |

---

### 🏗️ System Architecture

BunkNet operates on a three-tiered architecture to separate concerns and improve scalability. This is a common pattern for production-grade blockchain applications.

`User ↔️ [Frontend Apps] ↔️ [Explorer BFF API] ↔️ [Core Blockchain Node] ↔️ [MongoDB]`

* **Frontend Apps:** The static Web Wallet, Explorer, and Faucet files (HTML, CSS, JS).
* **Explorer BFF API (`explorer.py`):** A smart middle-layer (Backend-for-Frontend) that simplifies API calls and provides aggregated data to the frontends.
* **Core Blockchain Node (`blockchain.py`):** The main server that handles all blockchain logic, including the Proof-of-Work algorithm, P2P communication, and consensus rules.
* **MongoDB:** A robust NoSQL database that provides persistent, indexed storage for all blockchain data (blocks, transactions, etc.), ensuring data integrity and fast queries.

---

### 🚀 Getting Started: Your First 5 Minutes

Get the BunkNet CLI Wallet running on your local machine and start building.

#### 1️⃣ **Prerequisites**
- **Git** installed on your system.
- **Python 3.8+** and `pip` installed.

#### 2️⃣ **Clone the Repository**
Open your terminal and clone the project:

```git clone [https://github.com/ReOneSec/BunkNet.git](https://github.com/ReOneSec/BunkNet.git)```

```cd BunkNet```

3️⃣ Set Up Environment & Install Dependencies
Using a virtual environment is highly recommended to avoid conflicts.
### Create and activate a virtual environment
```python3 -m venv venv```
```source venv/bin/activate  # On Windows, use: venv\Scripts\activate```

### Install all required Python packages
```pip install -r requirements.txt```

> Note: The requirements.txt file contains all necessary packages, including requests, mnemonic, ecdsa, and pycryptodome.
> 
4️⃣ Launch the Wallet!
You're all set. Run the interactive application:
python3 wallet.py

> IMPORTANT: On your first run, select option 1 to create a new wallet. Immediately write down your 12-word seed phrase on paper and store it in a secure, offline location. This is your master key!
> 
🛠️ Technology Stack & Design Rationale
Every technology in our stack was deliberately chosen to provide a realistic and educational development experience.
<details>
<summary><strong>Expand to see the detailed Technology Stack and our reasoning...</strong></summary>
<br>
| Category | Technology | Rationale |
|---|---|---|
| Blockchain Core | Python | Chosen for its exceptional readability and extensive libraries, making the core logic approachable for learners to study and understand. |
| Consensus | Proof-of-Work (PoW) | Implemented to provide a hands-on understanding of the foundational consensus mechanism that powers Bitcoin and early Ethereum. It makes concepts like mining and difficulty tangible. |
| Database | MongoDB | A scalable NoSQL database used for persistent blockchain storage. It allows for fast, indexed queries, which is essential for a functional block explorer. |
| Cryptography | ecdsa, pycryptodome | Implements industry-standard cryptography (SECP256k1, AES-256) to teach and enforce best practices for transaction signing and wallet security. |
| Web Frontend | HTML, Tailwind CSS, JS | Tailwind CSS allows for the rapid development of a modern, responsive, and highly customizable user interface without writing extensive custom CSS. |
| Web Server | Nginx | A high-performance, battle-tested web server used as a reverse proxy to securely manage and route traffic to our various backend services. |
</details>
🗺️ Project Roadmap
We are committed to the long-term growth and evolution of BunkNet.
| Phase | Status | Key Objectives |
|---|---|---|
| One | ✅ Completed | <ul><li>Launch BunkChain PoW Testnet v1.0</li><li>Deploy Faucet, Explorer & Web Wallet</li><li>Release interactive CLI Wallet</li><li>Host first virtual hackathon with Indian tech institutes</li></ul> |
| Two | ⏳ In Progress | <ul><li>Develop interactive web-based learning platform</li><li>Establish partnerships with top universities</li><li>Initiate the "BunkNet Builders Grant" program</li></ul> |
| Three | 🚀 Future | <ul><li>Enhance PoW algorithm with dynamic difficulty adjustment</li><li>Launch a mock DAO for governance education</li><li>Expand educational initiatives to a global scale</li></ul> |
🤝 Contributing & Community
BunkNet is built by the community, for the community. We welcome contributions with open arms!
 * 🐛 Report a Bug
 * 💡 Suggest a Feature
 * ✍️ Start Contributing
Please read our CONTRIBUTING.md file for detailed guidelines on how to contribute effectively.
Join our community to ask questions, share your projects, and connect with other learners:
<p>
<a href="https://discord.gg/your-invite-link">
<img alt="Discord" src="https://img.shields.io/badge/Discord-Join%20Chat-7289DA?style=for-the-badge&logo=discord&logoColor=white">
</a>
<a href="https://twitter.com/your-twitter-handle">
<img alt="Twitter" src="https://img.shields.io/badge/Twitter-Follow%20Us-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white">
</a>
</p>
📜 License
This project is proudly open source and licensed under the Apache 2.0 License.
<a href="LICENSE">
<img alt="GitHub License" src="https://www.google.com/url?sa=E&source=gmail&q=https://img.shields.io/github/license/ReOneSec/BunkNet?style=for-the-badge%26color=007CF0%26label=license%26message=Apache%202.0">
</a>
<div align="center">
<h3>Built with ❤️ for the next generation of developers.</h3>
</div>

