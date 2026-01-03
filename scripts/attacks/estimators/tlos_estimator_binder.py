"""
TLOS Security Estimation - Copy/paste into Binder notebook

Open: https://mybinder.org/v2/gh/malb/lattice-estimator/jupyter-notebooks?labpath=..%2F..%2Ftree%2Fprompt.ipynb

Then paste the code below into a cell and run.
"""

# ============================================================================
# CELL 1: Setup and parameters
# ============================================================================
print("TLOS LWE Security Estimation (Gaussian noise)")
print("=" * 60)

from estimator import *

# TLOS paper parameters
n = 384       # LWE dimension
q = 65521     # Prime modulus  
m = 2560      # Number of samples
sigma = 8     # Gaussian noise stddev

print(f"Parameters: n={n}, q={q}, m={m}, sigma={sigma}")
print(f"Gaussian noise with standard deviation {sigma}\n")

# ============================================================================
# CELL 2: Gaussian error model
# ============================================================================

# Gaussian error with sigma=8
params_gaussian = LWE.Parameters(
    n=n,
    q=q,
    Xs=ND.Uniform(0, q-1),  # Uniform secret
    Xe=ND.DiscreteGaussian(sigma),  # Gaussian error
    m=m,
    tag="TLOS-gaussian"
)
print(params_gaussian)

# ============================================================================
# CELL 3: Quick estimate
# ============================================================================
print("\n--- ROUGH ESTIMATE ---")
LWE.estimate.rough(params_gaussian)

# ============================================================================
# CELL 4: Arora-GB attack
# ============================================================================
print("\n--- ARORA-GB ATTACK ---")
print("(Algebraic attack - less effective against Gaussian noise)")
try:
    LWE.arora_gb(params_gaussian)
except Exception as e:
    print(f"Error: {e}")

# ============================================================================
# CELL 5: Full estimate (slow)
# ============================================================================
print("\n--- FULL ESTIMATE ---")
print("(Takes several minutes...)")
LWE.estimate(params_gaussian)
