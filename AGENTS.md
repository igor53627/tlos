# TLOS Agent Instructions

## Project Overview

TLOS = TLO + SEH (Subspace-Evasive Hashing from Ma-Dai-Shi 2025)

Adds inter-gate wire binding to TLO for mix-and-match attack prevention.

## Key Commands

```bash
# Build contracts
forge build

# Run tests
forge test

# Benchmark on Tenderly
source ~/.zsh_secrets
forge script scripts/BenchmarkTLOS.s.sol --rpc-url "$TENDERLY_RPC" --broadcast --unlocked -vvv

# Build papers
cd paper && pdflatex tlos.tex && pdflatex tlos-paper.tex
```

## Repository Structure

- `contracts/` - Solidity contracts (TLOSLWE.sol is the main PQ variant)
- `src/` - Rust implementation (ported from circuit-mixing-research)
- `docs/` - Documentation
- `examples/` - Usage examples
- `paper/` - LaTeX papers

## Current Parameters (n=128 LWE)

| Parameter | Value |
|-----------|-------|
| LWE dimension | n=128 |
| PQ security | ~98-bit |
| Classical security | ~203-bit |
| Gas | ~8.5M (28% of block) |
| Storage | 662 KB |
| Batch size | 128 gates |
| SEH updates | 5 for 640 gates |

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

## SEH Technical Notes

- SEH provides **integrity/binding**, NOT collision resistance
- Full-rank 64x64 matrix over Z_q is bijective (unique preimage)
- Do NOT claim "collision resistance" - the linear system is trivial to solve

## Related Repos

- `igor53627/tlo` - Base TLO (archived)
- `igor53627/circuit-mixing-research` - Research codebase
- `ma-dai-shi-io` - Ma-Dai-Shi implementation reference
