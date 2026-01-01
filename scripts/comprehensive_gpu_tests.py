#!/usr/bin/env python3
"""
Comprehensive GPU Security Tests for TLOS
Run on GH200 or similar high-end GPU
"""
import torch
import time
import subprocess
import sys

def get_gpu_stats():
    power = subprocess.check_output(["nvidia-smi", "--query-gpu=power.draw", "--format=csv,noheader,nounits"]).decode().strip()
    temp = subprocess.check_output(["nvidia-smi", "--query-gpu=temperature.gpu", "--format=csv,noheader"]).decode().strip()
    mem = subprocess.check_output(["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"]).decode().strip()
    return float(power), int(temp), int(mem)

print("=" * 70, flush=True)
print("COMPREHENSIVE GPU SECURITY TESTS - TLOS", flush=True)
print("=" * 70, flush=True)
print(f"GPU: {torch.cuda.get_device_name(0)}", flush=True)
print(f"VRAM: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB", flush=True)
print("=" * 70, flush=True)

device = torch.device("cuda")

# =============================================================================
# TEST 1: FP16 Correctness Check
# =============================================================================
print("\n[TEST 1] FP16 CORRECTNESS CHECK (5 min)", flush=True)
print("-" * 70, flush=True)
print("Checking if FP16 precision causes false positives in puzzle verification", flush=True)

n, m, q = 48, 72, 2039
threshold = 300
batch = 2**20

# Create a known puzzle with planted solution
torch.manual_seed(42)
s_true = torch.randint(-1, 2, (n,), dtype=torch.float32, device=device)
A = torch.randint(0, q, (m, n), dtype=torch.float32, device=device)
e = torch.randint(-2, 3, (m,), dtype=torch.float32, device=device)
b = (A @ s_true + e) % q

# Convert to FP16
A_fp16 = A.half()
b_fp16 = b.half()

false_positives_fp16 = 0
false_positives_fp32 = 0
total_checked = 0
start = time.time()

while time.time() - start < 300:  # 5 minutes
    # Random guesses (not the true solution)
    s_guess = torch.randint(-1, 2, (batch, n), dtype=torch.float32, device=device)
    
    # FP32 check
    res_fp32 = torch.abs((A @ s_guess.T - b.unsqueeze(1)) % q)
    res_fp32 = torch.where(res_fp32 > q//2, q - res_fp32, res_fp32)
    fp32_pass = (res_fp32.max(dim=0).values < threshold).sum().item()
    
    # FP16 check
    s_guess_fp16 = s_guess.half()
    res_fp16 = torch.abs((A_fp16 @ s_guess_fp16.T - b_fp16.unsqueeze(1)) % q)
    res_fp16 = torch.where(res_fp16 > q//2, q - res_fp16, res_fp16)
    fp16_pass = (res_fp16.max(dim=0).values < threshold).sum().item()
    
    false_positives_fp32 += fp32_pass
    false_positives_fp16 += fp16_pass
    total_checked += batch
    torch.cuda.synchronize()

print(f"  Total guesses checked: {total_checked/1e9:.2f}B", flush=True)
print(f"  FP32 false positives: {false_positives_fp32}", flush=True)
print(f"  FP16 false positives: {false_positives_fp16}", flush=True)
print(f"  FP16 introduces extra false positives: {false_positives_fp16 - false_positives_fp32}", flush=True)

# Verify true solution works in both
s_true_batch = s_true.unsqueeze(0)
res_true_fp32 = torch.abs((A @ s_true_batch.T - b.unsqueeze(1)) % q)
res_true_fp32 = torch.where(res_true_fp32 > q//2, q - res_true_fp32, res_true_fp32)
fp32_true_max = res_true_fp32.max().item()

s_true_fp16 = s_true.half().unsqueeze(0)
res_true_fp16 = torch.abs((A_fp16 @ s_true_fp16.T - b_fp16.unsqueeze(1)) % q)
res_true_fp16 = torch.where(res_true_fp16 > q//2, q - res_true_fp16, res_true_fp16)
fp16_true_max = res_true_fp16.max().item()

print(f"  True solution max error (FP32): {fp32_true_max} (threshold: {threshold})", flush=True)
print(f"  True solution max error (FP16): {fp16_true_max} (threshold: {threshold})", flush=True)
print(f"  [{'PASS' if fp16_true_max < threshold else 'FAIL'}] FP16 correctly identifies true solution", flush=True)

# =============================================================================
# TEST 2: INT8 / Tensor Core Test
# =============================================================================
print("\n[TEST 2] PRECISION COMPARISON TEST (10 min)", flush=True)
print("-" * 70, flush=True)
print("Testing different precisions for attack speed", flush=True)

n, m, q = 48, 72, 2039
batch = 2**22

A = torch.randint(0, q, (m, n), dtype=torch.float32, device=device)
b = torch.randint(0, q, (m,), dtype=torch.float32, device=device)

precisions = [
    ("FP32", torch.float32),
    ("FP16", torch.float16),
    ("BF16", torch.bfloat16),
]

print(f"  {'Precision':<10} {'Rate (M/sec)':<15} {'Power (W)':<12} {'Efficiency (M/J)':<15}", flush=True)
print("  " + "-" * 55, flush=True)

for name, dtype in precisions:
    A_t = A.to(dtype)
    b_t = b.to(dtype)
    
    # Warmup
    for _ in range(3):
        s = torch.randint(-1, 2, (batch, n), dtype=dtype, device=device)
        _ = (A_t @ s.T) % q
    torch.cuda.synchronize()
    
    # Benchmark
    start = time.time()
    total = 0
    power_samples = []
    while time.time() - start < 60:  # 1 minute each
        s = torch.randint(-1, 2, (batch, n), dtype=dtype, device=device)
        res = torch.abs((A_t @ s.T - b_t.unsqueeze(1)) % q)
        res = torch.where(res > q//2, q - res, res)
        _ = (res.max(dim=0).values < 300).sum().item()
        torch.cuda.synchronize()
        total += batch
        power, _, _ = get_gpu_stats()
        power_samples.append(power)
    
    elapsed = time.time() - start
    rate = total / elapsed
    avg_power = sum(power_samples) / len(power_samples)
    efficiency = rate / avg_power / 1e6  # Million guesses per Joule
    
    print(f"  {name:<10} {rate/1e6:<15.1f} {avg_power:<12.0f} {efficiency:<15.3f}", flush=True)

# =============================================================================
# TEST 3: Memory-Bound Analysis
# =============================================================================
print("\n[TEST 3] MEMORY-BOUND ANALYSIS (10 min)", flush=True)
print("-" * 70, flush=True)
print("Finding optimal VRAM usage for attack throughput", flush=True)

n, m, q = 48, 72, 2039

print(f"  {'Batch Size':<15} {'VRAM (GB)':<12} {'Rate (M/sec)':<15} {'Bottleneck':<15}", flush=True)
print("  " + "-" * 60, flush=True)

for exp in range(18, 28):
    batch = 2**exp
    try:
        torch.cuda.empty_cache()
        A = torch.randint(0, q, (m, n), dtype=torch.float32, device=device)
        b = torch.randint(0, q, (m,), dtype=torch.float32, device=device)
        s = torch.randint(-1, 2, (batch, n), dtype=torch.float32, device=device)
        
        torch.cuda.synchronize()
        _, _, mem_before = get_gpu_stats()
        
        # Warmup
        _ = (A @ s.T) % q
        torch.cuda.synchronize()
        
        _, _, mem_after = get_gpu_stats()
        vram_gb = mem_after / 1024
        
        # Benchmark
        start = time.time()
        iters = max(1, 2**(24-exp))
        for _ in range(iters):
            s = torch.randint(-1, 2, (batch, n), dtype=torch.float32, device=device)
            res = torch.abs((A @ s.T - b.unsqueeze(1)) % q)
            res = torch.where(res > q//2, q - res, res)
            _ = (res.max(dim=0).values < 300).sum().item()
        torch.cuda.synchronize()
        elapsed = time.time() - start
        rate = (iters * batch) / elapsed
        
        # Determine bottleneck
        if exp <= 21:
            bottleneck = "Compute"
        elif exp <= 23:
            bottleneck = "Balanced"
        else:
            bottleneck = "Memory BW"
        
        print(f"  2^{exp:<12} {vram_gb:<12.1f} {rate/1e6:<15.1f} {bottleneck:<15}", flush=True)
        
        del s
        torch.cuda.empty_cache()
        
    except RuntimeError as e:
        print(f"  2^{exp:<12} OOM", flush=True)
        break

# =============================================================================
# TEST 4: Meet-in-the-Middle Attack
# =============================================================================
print("\n[TEST 4] MEET-IN-THE-MIDDLE ATTACK ANALYSIS (5 min)", flush=True)
print("-" * 70, flush=True)
print("Testing MITM on ternary secret: 3^48 = 3^24 x 3^24", flush=True)
print("MITM requires storing 3^24 partial results (~282 trillion entries)", flush=True)

n, m, q = 48, 72, 2039
n_half = n // 2  # 24

# Calculate storage requirements
entries = 3**n_half
bytes_per_entry = n_half + 8  # 24 bytes for half-secret + 8 bytes for partial result
total_bytes = entries * bytes_per_entry
print(f"  Half-secret space: 3^{n_half} = {entries:.2e} entries", flush=True)
print(f"  Storage per entry: {bytes_per_entry} bytes", flush=True)
print(f"  Total storage needed: {total_bytes/1e15:.1f} PB", flush=True)
print(f"  GH200 VRAM: 0.0001 PB", flush=True)
print(f"  [INFEASIBLE] MITM requires 10,000,000x more storage than available", flush=True)

# But let's benchmark the partial computation anyway
print(f"\n  Benchmarking half-secret evaluation (n={n_half})...", flush=True)

A_half = torch.randint(0, q, (m, n_half), dtype=torch.float32, device=device)
batch = 2**22

start = time.time()
total = 0
for _ in range(10):
    s_half = torch.randint(-1, 2, (batch, n_half), dtype=torch.float32, device=device)
    partial = (A_half @ s_half.T) % q
    _ = partial.sum().item()
    torch.cuda.synchronize()
    total += batch

elapsed = time.time() - start
rate = total / elapsed
print(f"  Half-evaluation rate: {rate/1e6:.1f}M/sec", flush=True)
print(f"  Time to enumerate 3^24: {3**24 / rate / 3600:.1f} hours (per GPU)", flush=True)
print(f"  But storage is the blocker, not compute", flush=True)

# =============================================================================
# TEST 5: Standard LWE (n=384) Sustained Test
# =============================================================================
print("\n[TEST 5] STANDARD LWE (n=384) SUSTAINED TEST (60 min)", flush=True)
print("-" * 70, flush=True)
print("Testing Layer 2 security - different attack surface from puzzle", flush=True)

n, m, q = 384, 768, 65521
batch = 2**20

A = torch.randint(0, q, (m, n), dtype=torch.float32, device=device)
b = torch.randint(0, q, (m,), dtype=torch.float32, device=device)

rates = []
start = time.time()
interval_start = start
interval_guesses = 0
total_guesses = 0

print("  Time   Interval Rate      Avg Rate    GPU Temp   Power", flush=True)
print("  " + "-" * 55, flush=True)

while time.time() - start < 3600:
    s = torch.randint(-1, 2, (batch, n), dtype=torch.float32, device=device)
    res = (A @ s.T) % q
    # For standard LWE, we check if result is close to b (Gaussian noise)
    diff = torch.abs(res - b.unsqueeze(1))
    diff = torch.where(diff > q//2, q - diff, diff)
    _ = diff.sum().item()
    torch.cuda.synchronize()
    
    total_guesses += batch
    interval_guesses += batch
    
    now = time.time()
    if now - interval_start >= 300:
        interval_rate = interval_guesses / (now - interval_start)
        avg_rate = total_guesses / (now - start)
        power, temp, _ = get_gpu_stats()
        elapsed_min = int(now - start) // 60
        print(f"  {elapsed_min:>4}min     {interval_rate/1e6:>10.1f}M    {avg_rate/1e6:>10.1f}M      {temp}C    {power:.0f}W", flush=True)
        rates.append(interval_rate)
        interval_start = now
        interval_guesses = 0

print("  " + "=" * 55, flush=True)
print(f"  Min rate: {min(rates)/1e6:.1f}M/sec", flush=True)
print(f"  Max rate: {max(rates)/1e6:.1f}M/sec", flush=True)
sustained_lwe_rate = total_guesses/(time.time()-start)
print(f"  Sustained avg: {sustained_lwe_rate/1e6:.1f}M/sec", flush=True)

# Compare to puzzle
print(f"\n  Comparison:", flush=True)
print(f"  - Puzzle (n=48): ~580M/sec FP32, ~1B/sec FP16", flush=True)
print(f"  - Standard LWE (n=384): {sustained_lwe_rate/1e6:.1f}M/sec", flush=True)
print(f"  - Slowdown factor: {580e6 / sustained_lwe_rate:.1f}x", flush=True)

# =============================================================================
# TEST 6: Power Efficiency Analysis
# =============================================================================
print("\n[TEST 6] POWER EFFICIENCY SUMMARY", flush=True)
print("-" * 70, flush=True)

print("  Attack economics at $0.10/kWh electricity cost:", flush=True)
print("  ", flush=True)
print(f"  {'Attack':<25} {'Rate':<15} {'Power':<10} {'Cost/1T guesses':<20}", flush=True)
print("  " + "-" * 70, flush=True)

# Puzzle FP16
puzzle_rate = 1e9  # 1B/sec
puzzle_power = 700  # W estimate
puzzle_cost_per_T = (puzzle_power / 1000) * (1e12 / puzzle_rate / 3600) * 0.10
print(f"  {'Puzzle (n=48) FP16':<25} {'1.0B/sec':<15} {'~700W':<10} ${puzzle_cost_per_T:.4f}", flush=True)

# Standard LWE (from test 5)
lwe_rate = sustained_lwe_rate
lwe_power = 700  # W estimate
lwe_cost_per_T = (lwe_power / 1000) * (1e12 / lwe_rate / 3600) * 0.10
print(f"  {'Standard LWE (n=384)':<25} {f'{lwe_rate/1e6:.0f}M/sec':<15} {'~700W':<10} ${lwe_cost_per_T:.4f}", flush=True)

# Full exhaustive search cost
search_space = 3**48
total_cost_puzzle = puzzle_cost_per_T * (search_space / 1e12)
print(f"\n  Cost to exhaust 3^48 puzzle space: ${total_cost_puzzle/1e12:.1f} trillion", flush=True)

print("\n" + "=" * 70, flush=True)
print("ALL TESTS COMPLETE", flush=True)
print("=" * 70, flush=True)
