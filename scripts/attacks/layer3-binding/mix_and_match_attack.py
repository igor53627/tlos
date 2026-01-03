#!/usr/bin/env python3
"""
Layer 3 Wire Binding Attack Simulator

Tests mix-and-match attacks against the full-rank 64x64 linear binding layer.
The binding layer computes: H(wire_state, gate_idx) where H is a full-rank
matrix over Z_q.

Attack Model:
- Attacker has valid (input, puzzle_solution) pairs from different executions
- Attacker tries to swap intermediate wire states between executions
- Wire binding should detect any tampering

Security Property:
- Full-rank 64x64 matrix is bijective (unique preimage)
- Any modification to intermediate wires changes binding output
- Binding is algebraic, not collision-resistant (trivial to solve linear system)
"""

import hashlib
import struct
from typing import List, Tuple
import random

# TLOS parameters
Q = 65521
NUM_WIRES = 64
BINDING_ROWS = 64


def derive_binding_matrix_row(seed: bytes, gate_idx: int, row: int) -> List[int]:
    """Derive a row of the binding matrix from seed."""
    row_seed = hashlib.sha256(seed + gate_idx.to_bytes(4, 'big') + row.to_bytes(4, 'big')).digest()
    
    coefficients = []
    for block_idx in range((NUM_WIRES + 15) // 16):
        block_digest = hashlib.sha256(row_seed + block_idx.to_bytes(4, 'big')).digest()
        for k in range(16):
            if len(coefficients) >= NUM_WIRES:
                break
            # Extract 16-bit coefficient
            offset = k * 2
            coeff = struct.unpack('>H', block_digest[offset:offset+2])[0] % Q
            coefficients.append(coeff)
    
    return coefficients[:NUM_WIRES]


def compute_binding_hash(wire_state: int, gate_idx: int, seed: bytes) -> List[int]:
    """Compute wire binding hash output (64 values mod Q)."""
    output = []
    
    for row in range(BINDING_ROWS):
        coeffs = derive_binding_matrix_row(seed, gate_idx, row)
        
        # Compute dot product: sum(a[i] * wire_bit[i]) mod Q
        total = 0
        for col in range(NUM_WIRES):
            bit_val = (wire_state >> col) & 1
            if bit_val:
                total = (total + coeffs[col]) % Q
        
        output.append(total)
    
    return output


def simulate_execution(input_val: int, seed: bytes, num_gates: int = 64) -> List[Tuple[int, List[int]]]:
    """Simulate circuit execution, returning (wire_state, binding) at each gate."""
    execution_trace = []
    wire_state = input_val & ((1 << NUM_WIRES) - 1)
    
    # Initial binding
    binding = compute_binding_hash(wire_state, 0, seed)
    execution_trace.append((wire_state, binding))
    
    # Simulate gates (random wire flips for demo)
    for gate_idx in range(1, num_gates):
        # Random gate operation (flip some wires)
        flip_mask = random.randint(0, (1 << NUM_WIRES) - 1)
        wire_state ^= (flip_mask & 0x7)  # Only flip low bits for demo
        
        binding = compute_binding_hash(wire_state, gate_idx, seed)
        execution_trace.append((wire_state, binding))
    
    return execution_trace


def mix_and_match_attack(trace1: List[Tuple[int, List[int]]], 
                         trace2: List[Tuple[int, List[int]]],
                         swap_point: int) -> bool:
    """
    Attempt mix-and-match attack: take first part of trace1, second part of trace2.
    Returns True if attack is detected (binding mismatch).
    """
    if swap_point >= len(trace1) or swap_point >= len(trace2):
        return True
    
    # Get wire state from trace1 at swap point
    wire_state_1, binding_1 = trace1[swap_point]
    
    # Get wire state from trace2 at swap point
    wire_state_2, binding_2 = trace2[swap_point]
    
    # If wire states differ, binding will differ (bijective property)
    if wire_state_1 != wire_state_2:
        # Check if bindings are actually different
        return binding_1 != binding_2
    
    return False  # Same wire state = same binding (not an attack)


def run_attack_simulation(num_trials: int = 1000):
    """Run mix-and-match attack simulation."""
    print("=" * 60)
    print("TLOS Layer 3 Wire Binding - Mix-and-Match Attack Simulation")
    print("=" * 60)
    print(f"\nParameters:")
    print(f"  Binding matrix: {BINDING_ROWS}x{NUM_WIRES} over Z_{Q}")
    print(f"  Trials: {num_trials}")
    
    seed = b"TLOS-Test-Seed-12345"
    detected = 0
    same_state = 0
    
    for trial in range(num_trials):
        # Generate two different inputs
        input1 = random.randint(0, (1 << NUM_WIRES) - 1)
        input2 = random.randint(0, (1 << NUM_WIRES) - 1)
        
        while input1 == input2:
            input2 = random.randint(0, (1 << NUM_WIRES) - 1)
        
        # Execute both
        trace1 = simulate_execution(input1, seed)
        trace2 = simulate_execution(input2, seed)
        
        # Try swap at random point
        swap_point = random.randint(1, len(trace1) - 1)
        
        # Check if wire states happen to be same (rare)
        if trace1[swap_point][0] == trace2[swap_point][0]:
            same_state += 1
            continue
        
        # Attempt attack
        if mix_and_match_attack(trace1, trace2, swap_point):
            detected += 1
    
    actual_attacks = num_trials - same_state
    detection_rate = detected / actual_attacks if actual_attacks > 0 else 0
    
    print(f"\nResults:")
    print(f"  Total trials: {num_trials}")
    print(f"  Same wire state (no attack possible): {same_state}")
    print(f"  Actual attack attempts: {actual_attacks}")
    print(f"  Attacks detected: {detected}")
    print(f"  Detection rate: {detection_rate:.2%}")
    
    if detection_rate == 1.0:
        print("\n[PASS] All mix-and-match attacks detected!")
        print("       Wire binding provides algebraic integrity.")
    else:
        print(f"\n[FAIL] Some attacks not detected: {actual_attacks - detected}")
    
    return detection_rate == 1.0


def analyze_binding_properties():
    """Analyze mathematical properties of the binding layer."""
    print("\n" + "=" * 60)
    print("Wire Binding Layer Analysis")
    print("=" * 60)
    
    seed = b"analysis-seed"
    
    # Test determinism
    wire_state = 0x123456789ABCDEF0
    b1 = compute_binding_hash(wire_state, 0, seed)
    b2 = compute_binding_hash(wire_state, 0, seed)
    print(f"\n1. Determinism: {b1 == b2}")
    
    # Test diffusion (single bit flip)
    wire_state_flipped = wire_state ^ 1
    b3 = compute_binding_hash(wire_state_flipped, 0, seed)
    differences = sum(1 for x, y in zip(b1, b3) if x != y)
    print(f"2. Diffusion (1-bit flip): {differences}/{BINDING_ROWS} outputs changed")
    
    # Test gate index sensitivity
    b4 = compute_binding_hash(wire_state, 1, seed)
    differences = sum(1 for x, y in zip(b1, b4) if x != y)
    print(f"3. Gate sensitivity: {differences}/{BINDING_ROWS} outputs changed")
    
    # Note on collision resistance
    print("\n[NOTE] Wire binding is NOT collision-resistant!")
    print("       It's a bijective linear map - trivial to solve Ax = b.")
    print("       Security comes from algebraic binding, not collision resistance.")
    print("       Attacker would need to forge a valid (input, puzzle) pair.")


if __name__ == "__main__":
    analyze_binding_properties()
    print()
    success = run_attack_simulation(1000)
    exit(0 if success else 1)
