# ReGuardian

**Reentrancy vulnerability scanner for Solidity smart contracts** — the vulnerability class behind $879M+ in documented losses (The DAO, Euler Finance, Cream Finance, Radiant Capital, and more).

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-12%20passing-green.svg)](tests/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## What it does

ReGuardian statically analyzes Solidity source for the four major reentrancy classes, each with a dedicated detector:

| Detector | Attack class | Real-world example |
|---|---|---|
| Mono-function | External call before state update in one function | The DAO ($60M, 2016) |
| Cross-function | Shared state exploited across functions | Euler Finance ($197M, 2023) |
| Cross-contract | User-controlled addresses & token callbacks (ERC777/ERC721) | Cream Finance ($130M, 2021) |
| Read-only | View-function price manipulation during reentrancy | Sonne Finance ($20M, 2024) |

Each finding includes the vulnerable code location, an attack-vector walkthrough, severity + confidence score, and a concrete fix suggestion (CEI pattern, ReentrancyGuard, pull-over-push).

## Quick start

```bash
pip install -r requirements-minimal.txt

# Web UI (paste/upload a contract, get a visual report)
python3 server.py           # → http://localhost:8000

# CLI — scan a single contract with all detectors
python3 scan.py contracts/examples/vulnerable_wallet.sol

# CLI — full toolkit (analyze / report / project scan)
python3 reguardian.py analyze contracts/examples/vulnerable_wallet.sol --mode standard
python3 reguardian.py report contracts/examples/vulnerable_wallet.sol -o report.html
```

## Example output

Running against the included DAO-style vulnerable wallet:

```
$ python3 scan.py contracts/examples/vulnerable_wallet.sol

[CRITICAL] Reentrancy Vulnerability in withdraw()
  contracts/examples/vulnerable_wallet.sol:14-19
  External call (.call{value:}) precedes state update (balances[msg.sender] = 0)
  Confidence: 0.85
  Fix: apply Checks-Effects-Interactions or OpenZeppelin nonReentrant
```

## How it works

- **Custom detectors** (`src/detectors/reentrancy/`) — brace-aware Solidity function extraction + ordered pattern analysis (external call vs. state write positions, guard detection)
- **Slither integration** (`src/analyzers/slither_analyzer.py`) — cross-checks findings against Slither's reentrancy detectors when installed
- **Mythril integration** (`src/analyzers/mythril_analyzer.py`) — optional symbolic-execution pass
- **ML classifier** (`src/ml/`) — scikit-learn feature-extraction pipeline (random forest / gradient boosting) with a rule-based fallback; training pipeline included, pre-trained model not yet shipped
- **Attack database** (`data/attacks/`) — 39 documented reentrancy attacks (2016–2024) used for pattern reference and shown in the web UI
- **Web UI + JSON API** (`server.py`) — analysis endpoint, severity breakdown, HTML/JSON export

## Testing

```bash
python3 -m pytest tests/ -v    # 12 tests: detection, safe-contract false-positive checks, guard recognition
```

Example contracts for each vulnerability class live in `contracts/examples/`, with a guarded counterpart in `contracts/safe/`.

## Honest limitations

- Detection is **pattern-based, not AST/CFG-based** — it will produce false positives, especially on the cross-function and read-only detectors. Findings are audit *leads*, not verdicts.
- The ML detector ships untrained and falls back to heuristics until you train it on labeled data.
- No automated tool replaces a manual audit. Use ReGuardian as one layer of a defense-in-depth review.

## Roadmap

- [ ] AST-based parsing (solc / tree-sitter) to replace regex extraction
- [ ] Echidna fuzzing integration
- [ ] Ship a trained classifier + labeled dataset
- [ ] False-positive suppression via data-flow analysis

## License

MIT
