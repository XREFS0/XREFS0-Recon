# Contributing to XREFS0

Thank you for your interest in contributing to XREFS0. This document outlines the guidelines for contributing to the project — whether through bug reports, feature requests, code contributions, or documentation improvements.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Features](#suggesting-features)
  - [Submitting Code Changes](#submitting-code-changes)
  - [Improving Documentation](#improving-documentation)
- [Development Setup](#development-setup)
- [Pull Request Guidelines](#pull-request-guidelines)
- [Style & Standards](#style--standards)
- [Testing](#testing)
- [License](#license)
- [Contact](#contact)

---

## Code of Conduct

By participating in this project, you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

---

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/XREFS0/xrefs0.git
   cd xrefs0
   ```
3. **Install** dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

---

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue on GitHub with the following information:

- **Clear title** describing the issue
- **Steps to reproduce** the behavior
- **Expected behavior** and **actual behavior**
- **Environment details** (OS, Python version, tool version)
- **Logs or error messages** if applicable
- **Sample domain** (if relevant) that triggers the issue

### Suggesting Features

Feature requests are welcome. Please open an issue with:

- **Use case** — what problem does this solve?
- **Proposed behavior** — how should it work?
- **Alternatives considered** — any other approaches you've thought of
- **Relevance** — is this a general enhancement or specific to your use case?

### Submitting Code Changes

1. Ensure your code follows the [style guidelines](#style--standards).
2. Write or update tests for your changes.
3. Ensure all tests pass.
4. Update documentation where necessary.
5. Submit a pull request with a clear description of the changes.

### Improving Documentation

Documentation improvements — including fixes to typos, clearer explanations, additional examples, and translations — are always appreciated. Simply open a pull request with the proposed changes.

---

## Development Setup

```bash
# Clone and enter directory
git clone https://github.com/XREFS0/xrefs0.git
cd xrefs0

# Install dependencies
pip install -r requirements.txt

# Run a quick test scan
python xrefs0.py example.com --profile quick --no-screenshot --no-graph
```

---

## Pull Request Guidelines

- **One feature per PR** — keep changes focused and atomic.
- **Descriptive title and body** — explain *what* and *why*, not just *how*.
- **Reference related issues** — use `Closes #issue` or `Relates to #issue`.
- **Keep PRs small** — large changes are harder to review. Split into multiple PRs if necessary.
- **Update documentation** — if your change affects usage, update the relevant docs.
- **No unnecessary files** — avoid committing generated files, cache, or IDE configs.
- **Sign your commits** — if possible, use GPG signing.

---

## Style & Standards

- **Python**: Follow [PEP 8](https://peps.python.org/pep-0008/) with 4-space indentation.
- **Imports**: Group standard library, third-party, and local imports with a blank line between groups.
- **Naming**: `snake_case` for functions and variables, `PascalCase` for classes, `UPPER_CASE` for constants.
- **Docstrings**: Use triple double-quotes `"""docstring"""` for modules, classes, and public functions.
- **Error handling**: Use specific exceptions; avoid bare `except:` blocks.
- **Type hints**: Optional but encouraged for new code.
- **Comments**: Explain *why*, not *what*. Let the code speak for itself.

---

## Testing

- Run the tool against a test domain to verify your changes:
  ```bash
  python xrefs0.py example.com --profile quick --html test_report.html
  ```
- Verify HTML output renders correctly:
  ```bash
  python -c "with open('test_report.html') as f: assert 'XREFS0' in f.read()"
  ```
- Check that existing exports still work (JSON, CSV, etc.).
- If adding a new module, ensure it handles empty/missing data gracefully.

---

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

---

## Contact

- **Telegram Channel:** [@XREFS0_CHANNEL](https://t.me/XREFS0_CHANNEL)
- **Telegram Contact:** [@MrMasaOfficial](https://t.me/MrMasaOfficial)
- **Website:** [xrefs0.com](http://xrefs0.com/)
- **YouTube:** [@XREFS0](https://www.youtube.com/@XREFS0)
- **GitHub:** [XREFS0](https://github.com/XREFS0)
- **LinkedIn:** [mrmasaofficial](https://www.linkedin.com/in/mrmasaofficial)
