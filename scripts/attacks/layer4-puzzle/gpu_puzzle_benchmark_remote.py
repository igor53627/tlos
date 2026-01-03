#!/usr/bin/env python3
"""GPU benchmark for Weak LWE Puzzle - run on remote GH200"""
import time
import math
import torch

print('=' * 70)
print('TLOS WEAK LWE PUZZLE - GPU BRUTE-FORCE BENCHMARK')
print('=' * 70)
print(f'GPU: {torch.cuda.get_device_name(0)}')
print(f'VRAM: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB')
print()

Q_WEAK = 2039

def benchmark(n, m, n_guesses=20000000, batch_size=131072):
    device = torch.device('cuda')
    A = torch.randint(0, Q_WEAK, (m, n), dtype=torch.float32, device=device)
    b = torch.randint(0, Q_WEAK, (m,), dtype=torch.float32, device=device)
    
    # Warmup
    for _ in range(3):
        secrets = (torch.randint(0, 3, (batch_size, n), device=device).float() - 1)
        As = torch.mm(secrets, A.T) % Q_WEAK
        torch.cuda.synchronize()
    
    start = time.perf_counter()
    for batch_start in range(0, n_guesses, batch_size):
        batch_end = min(batch_start + batch_size, n_guesses)
        actual_batch = batch_end - batch_start
        secrets = (torch.randint(0, 3, (actual_batch, n), device=device).float() - 1)
        As = torch.mm(secrets, A.T).int() % Q_WEAK
        residual = As - b.int()
        residual = torch.where(residual > Q_WEAK // 2, residual - Q_WEAK, residual)
        norm_sq = torch.sum(residual ** 2, dim=1)
    torch.cuda.synchronize()
    elapsed = time.perf_counter() - start
    
    return n_guesses / elapsed

def fmt_time(s):
    if s < 60: return f'{s:.1f} sec'
    if s < 3600: return f'{s/60:.1f} min'
    if s < 86400: return f'{s/3600:.1f} hours'
    if s < 86400*365: return f'{s/86400:.1f} days'
    return f'{s/86400/365:.1f} years'

# Test different parameters
print(f'{"n":<6} {"m":<6} {"Space":<14} {"Guesses/sec":<15} {"1 GPU":<15} {"100 GPUs"}')
print('-' * 80)

for n in [24, 32, 40, 48]:
    for m in [40, 60]:
        gps = benchmark(n, m)
        space_bits = math.log2(3**n)
        total = 3**n
        time_1 = (total/2) / gps
        time_100 = time_1 / 100
        
        space_str = f'2^{space_bits:.0f}'
        print(f'{n:<6} {m:<6} {space_str:<14} {gps:<15,.0f} {fmt_time(time_1):<15} {fmt_time(time_100)}')

print()
print('=' * 70)
print('COMPARISON: Original TLOS Circuit Evaluation')
print('=' * 70)

N_TLOS = 768
GATES = [64, 128, 256]

def benchmark_tlos(n_gates, n_guesses=5000000, batch_size=65536):
    device = torch.device('cuda')
    m = n_gates * 4
    A = torch.randint(0, 65521, (m, N_TLOS), dtype=torch.float32, device=device)
    b = torch.randint(0, 65521, (m,), dtype=torch.float32, device=device)
    secrets = torch.randint(0, 65521, (n_guesses, N_TLOS), dtype=torch.float32, device=device)
    
    # Warmup
    for _ in range(3):
        inner = torch.mm(secrets[:batch_size], A.T).int() % 65521
        torch.cuda.synchronize()
    
    start = time.perf_counter()
    for batch_start in range(0, n_guesses, batch_size):
        batch = secrets[batch_start:batch_start+batch_size]
        inner = torch.mm(batch, A.T).int() % 65521
        diff = (b.int() - inner) % 65521
    torch.cuda.synchronize()
    elapsed = time.perf_counter() - start
    
    return n_guesses / elapsed

print(f'{"Gates":<10} {"Samples":<10} {"Guesses/sec":<15}')
print('-' * 40)
for gates in GATES:
    gps = benchmark_tlos(gates)
    print(f'{gates:<10} {gates*4:<10} {gps:<15,.0f}')

print()
print('=' * 70)
print('SECURITY ANALYSIS')
print('=' * 70)
print()
print('WITHOUT Puzzle (original TLOS):')
print('  - Attacker brute-forces INPUT (user secret)')
print('  - If input has 2^30 entropy: cracked in 43 sec')
print('  - LWE layer only adds ~40x slowdown per guess')
print()
print('WITH Puzzle (n=40):')
print('  - Attacker must brute-force TERNARY SECRET (3^40 = 2^63)')
print('  - Even low-entropy inputs get 2^63 protection')
print('  - 1 GH200: ~1000 years to crack')
print('  - 1000 GPUs: ~1 year to crack')
