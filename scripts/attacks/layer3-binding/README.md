# Layer 3: Wire Binding Attacks

Wire binding layer provides algebraic integrity via a full-rank 64x64 linear map over Z_q.

## Security Properties

| Property | Status | Notes |
|----------|--------|-------|
| Collision resistance | NO | Linear system - trivial to solve Ax=b |
| Algebraic binding | YES | Full-rank matrix is bijective (unique preimage) |
| Mix-and-match protection | YES | Any wire modification changes binding |

## Attack Scripts

| Script | Description |
|--------|-------------|
| `mix_and_match_attack.py` | Simulates mix-and-match attacks on intermediate wires |

## Attack Model

The wire binding layer prevents mix-and-match attacks where an attacker:
1. Has valid (input, puzzle_solution) pairs from different executions
2. Tries to swap intermediate wire states between executions
3. Hopes the tampered execution still validates

## Why Collision Resistance Doesn't Matter

The binding is a linear map: `binding = A * wire_state mod q`

Given target binding `b`, solving for `wire_state` is trivial (Gaussian elimination).
But this doesn't help the attacker because:
1. They need a valid (input, puzzle_solution) pair
2. The puzzle binds the secret, not the wire state
3. Forging a wire state that matches binding doesn't give a valid puzzle solution

## Running the Attack

```bash
python mix_and_match_attack.py
```

Expected output: 100% detection rate for mix-and-match attempts.
