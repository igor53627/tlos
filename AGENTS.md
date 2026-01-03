# TLOS Agent Instructions

## Project Overview

TLOS = Topology-Lattice Obfuscation for Smart contracts

Four-layer security model:
1. **Topology layer** - structural mixing (heuristic)
2. **LWE layer** - control function hiding via standard LWE with Gaussian noise (σ=8, n=384, ~2^112 PQ)
3. **Wire binding layer** - full-rank linear hash for inter-gate consistency (algebraic binding, inspired by [MDS25])
4. **Planted LWE puzzle** - forces minimum 3^48 ≈ 2^76 brute-force search space (1.26M gas)

## Key Commands

```bash
# Build contracts
forge build

# Run tests
forge test

# Benchmark on Tenderly
source ~/.zsh_secrets
forge script scripts/BenchmarkTLOS.s.sol --rpc-url "$TENDERLY_RPC" --broadcast --unlocked -vvv

# Build papers (quick - run twice for refs)
cd paper && pdflatex tlos.tex && pdflatex tlos.tex && pdflatex tlos-paper.tex && pdflatex tlos-paper.tex
```

## Repository Structure

- `contracts/` - Solidity contracts
  - `TLOS.sol` - Main contract (Layers 1-3)
  - `TLOSOptimized.sol` - Gas-optimized variant with configurable n
  - `TLOSWithPuzzleV4.sol` - Full 4-layer with correct puzzle integration (PRODUCTION)
  - `TLOSWithPuzzleV3.sol` - Deprecated: puzzle derivable from input (insecure)
  - `TLOSWithPuzzleV2.sol` - Deprecated: uses n=128 LWE
  - `WeakLWEPuzzleV7.sol` - Standalone puzzle (n=48, for testing)
- `src/` - Rust implementation (ported from circuit-mixing-research)
- `test/` - Foundry tests (215 tests)
  - `TLOSWithPuzzleV4.t.sol` - Production contract tests (61 tests)
  - `TLOSWithPuzzleV4Harness.sol` - Test harness for isolated layer testing
  - `PuzzleVariants.t.sol` - All puzzle versions (18 tests)
- `scripts/` - Benchmarks and attack scripts
  - `attacks/` - Attack scripts organized by layer
    - `layer1-topology/` - SAT/oracle-guided attacks (Rust)
    - `layer2-lwe/` - Lattice attacks (Python)
    - `layer3-binding/` - Mix-and-match attacks (Python)
    - `layer4-puzzle/` - Brute-force attacks (Python/GPU)
    - `estimators/` - Security estimation tools
- `docs/` - Documentation
  - `layers/` - Per-layer technical documentation
    - `layer1-topology/` - Circuit mixing (heuristic, `src/circuit.rs`)
    - `layer2-lwe/` - LWE encryption (~2^112 PQ, `src/lwe.rs`)
    - `layer3-binding/` - Wire binding (algebraic, `src/wire_binding.rs`)
    - `layer4-puzzle/` - Planted LWE puzzle (2^76, `WeakLWEPuzzleV7.sol`)
- `examples/` - Usage examples
- `paper/` - LaTeX papers

## Ethereum Block Gas Limit

**60,000,000 gas** (60M) - updated as of 2024

## Current Parameters (n=384 LWE with Gaussian noise)

| Parameter | Value |
|-----------|-------|
| LWE dimension | n=384 |
| Gaussian noise | σ=8 |
| Modulus | q=65521 |
| PQ security | ~2^112 (lattice estimator) |
| Gas | 4.3M-9.6M (7-16% of 60M block) |
| Storage | seed-derived a vectors (11 bytes/gate) |
| Batch size | 128 gates |
| Binding updates | 5 for 640 gates |

## Layer 4 Puzzle Parameters (WeakLWEPuzzleV7)

| Parameter | Value |
|-----------|-------|
| Secret dimension n | 48 |
| Samples m | 72 |
| Modulus q | 2039 |
| Error range | {-2,-1,0,1,2} |
| Threshold | 300 |
| Search space | 3^48 ≈ 2^76 |
| Verification gas | 1.26M |
| GPU brute-force | 436M guesses/sec (GH200) |

## Paper Formatting (CRITICAL)

### Short/Mini Papers (tlos.tex) - Conference Style (Two-Column)

```latex
\documentclass[10pt,a4paper,twocolumn]{article}
\usepackage[T1]{fontenc}
\usepackage{amsmath,amssymb,amsthm}
\usepackage{graphicx}
\usepackage{booktabs}
\usepackage{geometry}
\usepackage{listings}
\usepackage{xcolor}
\usepackage[colorlinks=true,linkcolor=blue,citecolor=blue,urlcolor=blue]{hyperref}
\geometry{a4paper,top=25mm,bottom=25mm,left=19mm,right=19mm,columnsep=8mm}

\input{macros}

\lstset{
  basicstyle=\ttfamily\scriptsize,
  keywordstyle=\color{blue}\bfseries,
  commentstyle=\color{gray}\itshape,
  breaklines=true,
  frame=single,
  columns=fullflexible,
  upquote=true,
}
```

### Long/Full Papers (tlos-paper.tex) - Single Column

```latex
\documentclass[11pt]{article}
\usepackage[T1]{fontenc}
\usepackage{amsmath,amssymb,amsthm}
\usepackage{graphicx}
\usepackage{booktabs}
\usepackage{geometry}
\usepackage{listings}
\usepackage{xcolor}
\usepackage{hyperref}

\geometry{margin=1in}

\input{macros}

\lstset{
  basicstyle=\ttfamily\small,
  keywordstyle=\color{blue}\bfseries,
  commentstyle=\color{gray}\itshape,
  stringstyle=\color{red},
  breaklines=true,
  frame=single,
  xleftmargin=1em,
  xrightmargin=1em,
  columns=fullflexible,
  keepspaces=true,
  upquote=true,
}
```

**DO NOT create .md files for papers** - use LaTeX only.

## Build Commands

```bash
# Build papers (run pdflatex twice for refs, bibtex for citations)
cd paper
pdflatex tlos.tex && pdflatex tlos.tex
pdflatex tlos-paper.tex && bibtex tlos-paper && pdflatex tlos-paper.tex && pdflatex tlos-paper.tex
```

## [CRITICAL] Citation Check

**ALWAYS check for undefined citations after building papers:**
```bash
pdflatex <file>.tex 2>&1 | grep -i "undefined\|Citation"
```

If citations show as "[?]" in PDF:
1. Check refs.bib has the entry
2. Run bibtex then pdflatex twice
3. Add missing entries to refs.bib

## Wire Binding Technical Notes

- Wire binding provides **integrity/binding**, NOT collision resistance
- Full-rank 64x64 matrix over Z_q is bijective (unique preimage)
- Do NOT claim "collision resistance" - the linear system is trivial to solve

## Related Repos

- `igor53627/tlo` - Base TLO (archived)
- `igor53627/circuit-mixing-research` - Research codebase
- `ma-dai-shi-io` - Ma-Dai-Shi implementation reference
