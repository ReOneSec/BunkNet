# 🤝 Contributing to BunkNet ⛓️

First off, thank you for considering contributing to BunkNet! We are thrilled to have you here. This project is a community-driven effort, and every contribution, no matter how small, helps us build the future of Web3 education.

This document is a guide to help you through the process of contributing. We welcome contributions from our global community, including the vibrant and talented developer ecosystem in India and beyond!

<div align="center">
<img src="https://img.shields.io/badge/Contributions-Welcome-brightgreen?style=for-the-badge">
<img src="https://img.shields.io/badge/PRs-Welcome-brightgreen?style=for-the-badge">
</div>

---

### 📚 Table of Contents
* [📜 Code of Conduct](#-code-of-conduct)
* [🤔 How Can I Contribute?](#-how-can-i-contribute)
* [🚀 Your First Code Contribution](#-your-first-code-contribution)
* [✅ Pull Request Process](#-pull-request-process)
* [🎨 Style Guides](#-style-guides)

---

### 📜 Code of Conduct

This project and everyone participating in it is governed by the [BunkNet Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to `contact@bunknet.online`.

---

### 🤔 How Can I Contribute?

There are many ways to contribute to BunkNet, and many of them don't involve writing a single line of code.

#### 🐛 Reporting Bugs
If you find a bug in the source code, you can help us by [**submitting an issue**](https://github.com/ReOneSec/BunkNet/issues/new?template=bug_report.md) to our GitHub Repository. Please be as detailed as possible, including steps to reproduce, expected behavior, and screenshots if applicable.

#### 💡 Suggesting Enhancements
Have an idea for a new feature or an improvement to an existing one? We'd love to hear it! Feel free to [**submit a feature request**](https://github.com/ReOneSec/BunkNet/issues/new?template=feature_request.md).

#### 📖 Improving Documentation
Great documentation is the soul of an educational project. If you find typos, unclear sentences, or areas that could be explained better in our `README.md`, whitepaper, or code comments, please don't hesitate to open a pull request with your improvements.

#### 🧑‍💻 Submitting Code
If you're a developer, you can help us by fixing bugs or adding new features. This is a great way to get hands-on experience with a full-stack Web3 project. Follow the guide below to get started.

---

### 🚀 Your First Code Contribution

Ready to write some code? Here’s a step-by-step guide to making your first contribution.

#### 1. Find an Issue to Work On
Check our [**Issues tab**](https://github.com/ReOneSec/BunkNet/issues) on GitHub. We label issues that are great for new contributors as `good first issue`. These are a perfect place to start! Feel free to ask questions in the issue comments if you need clarification.

#### 2. Fork the Repository
Click the "Fork" button at the top-right corner of the repository page. This will create a copy of the BunkNet project under your own GitHub account.

#### 3. Clone Your Fork
Now, clone your forked repository to your local machine.

git clone [https://github.com/YOUR_USERNAME/BunkNet.git](https://github.com/YOUR_USERNAME/BunkNet.git)
cd BunkNet

4. Set Up Your Development Environment
We use a Python-based backend and a simple HTML/JS frontend. To work on the CLI wallet or backend services:
# It's highly recommended to use a Python virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate

# Install all required dependencies
pip install -r requirements.txt

5. Create a New Branch
Create a new branch for your changes. Please use a descriptive name.
 * For a new feature: feat/describe-the-feature
 * For a bug fix: fix/describe-the-bug
<!-- end list -->
# Example for a new feature
git checkout -b feat/add-transaction-export

6. Make Your Changes
Now you can open the code in your favorite editor and start making your changes!
7. Commit Your Changes
Once you're happy with your changes, commit them with a clear and descriptive message. We follow the Conventional Commits standard (see our Style Guides below).
git add .
git commit -m "feat(wallet): add csv export for transaction history"

8. Push to Your Fork
Push your committed changes to your forked repository on GitHub.
git push origin feat/add-transaction-export

9. Submit a Pull Request
Go to your forked repository on GitHub. You will see a prompt to create a Pull Request. Fill out the PR template with details about your changes.
✅ Pull Request Process
 * Once you submit your Pull Request, a project maintainer will be assigned to review it.
 * Our automated checks (CI/CD pipeline) will run to ensure the code meets our quality standards.
 * The reviewer may ask for changes or provide feedback. We aim to be friendly and constructive!
 * Once the PR is approved and all checks have passed, a maintainer will merge it into the main project.
 * Congratulations! 🎉 You are now an official contributor to BunkNet!
🎨 Style Guides
Python Code
 * All Python code must adhere to the PEP 8 style guide. We recommend using a linter like flake8 to automatically check your code.
Commit Messages
 * We follow the Conventional Commits specification. This helps keep our commit history clean and makes it easy to generate changelogs.
 * Each commit message should be in the format: type(scope): subject
 * Common types: feat (new feature), fix (bug fix), docs (documentation), style (formatting), refactor, test, chore (build updates).
 * Example: docs(readme): update the getting started guide
Thank you again for your interest in making BunkNet better. We can't wait to see your contributions!

