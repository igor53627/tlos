# TLO Lattice Attack Scripts

Scripts for empirically breaking the TLO LWE layer to validate security estimates.

## Purpose

The TLO paper claims ~26-bit security for n=64. These scripts:

1. **Validate the estimator** - Does BKZ break at predicted parameters?
2. **Find the break point** - At what n does the attack become infeasible?
3. **Measure post-LWE attacks** - Once CFs are known, how fast does the circuit fall?

## Requirements

```bash
pip install fpylll numpy
```

On macOS, fpylll requires some dependencies:
```bash
brew install gmp mpfr
pip install cython
pip install fpylll
```

## Usage

### Single Attack

```bash
# Easy: n=16, should break in seconds
python break_tlo.py --n 16 --gates 64 --block-size 20

# Medium: n=24, should break in minutes
python break_tlo.py --n 24 --gates 160 --block-size 35

# Hard: n=32, might take hours
python break_tlo.py --n 32 --gates 320 --block-size 45

# Production: n=64, should NOT break (validates security)
python break_tlo.py --n 64 --gates 640 --block-size 50
```

### Parameter Sweep

Run attacks across multiple parameter settings:

```bash
python break_tlo.py --sweep --output results.json
```

## Attack Method

**Primal Attack (uSVP via BKZ)**

1. Build Kannan embedding lattice from LWE samples
2. Run LLL preprocessing
3. Run BKZ-β reduction
4. Extract short vector → reveals secret key
5. Decrypt all CF bits using recovered key

**Conservative Model**

We give the attacker all plaintext bits (μ_i) for free, reducing to standard LWE.
This is strictly easier than the real TLO attack, so results are a lower bound.

## Expected Results

| n | m | Est. Security | Expected Attack Time |
|---|---|---------------|---------------------|
| 16 | 256 | ~19-bit | Seconds |
| 24 | 640 | ~21-bit | Minutes |
| 32 | 1280 | ~21-bit | Hours |
| 64 | 2560 | ~26-bit | Infeasible |

## Output Format

```json
{
  "n": 16,
  "num_gates": 64,
  "m": 256,
  "block_size": 20,
  "success": true,
  "total_time": 2.34,
  "attack_stats": {
    "lll_time": 0.12,
    "bkz_time": 1.89,
    "verified": true
  },
  "cf_accuracy": 1.0,
  "cf_correct": 256,
  "cf_total": 256
}
```

## Interpreting Results

- **success=true, verified=true**: Attack worked, secret recovered
- **success=true, verified=false**: Found a candidate but wrong (try larger block_size)
- **success=false**: Attack failed (security holds at these params)

If n=64 breaks faster than expected, the paper's security claims need revision.
