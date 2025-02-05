import random
from functools import reduce

# --- Corrected Parameters ---
n = 8                # Polynomial degree
q = 257              # Modulus (prime)
k = 3                # Module rank
noise_magnitude = 1  # Ensures error stays within q//4

class Polynomial:
    def __init__(self, coeffs=None):
        self.coeffs = coeffs if coeffs else [0]*n
        if len(self.coeffs) != n:
            raise ValueError(f"Polynomial must have {n} coefficients")
    
    def add(self, other, mod=q):
        return Polynomial([(a + b) % mod for a, b in zip(self.coeffs, other.coeffs)])
    
    def subtract(self, other, mod=q):
        return Polynomial([(a - b) % mod for a, b in zip(self.coeffs, other.coeffs)])
    
    def multiply(self, other, mod=q):
        result = [0] * (2*n)
        for i in range(n):
            for j in range(n):
                result[i+j] += self.coeffs[i] * other.coeffs[j]
        for i in range(n, 2*n):
            result[i - n] -= result[i]
        return Polynomial([x % mod for x in result[:n]])
    
    def __repr__(self):
        return f"Poly({self.coeffs})"

# --- Helper Functions ---
def random_poly(small=False):
    if small:
        return Polynomial([random.randint(-noise_magnitude, noise_magnitude) for _ in range(n)])
    else:
        return Polynomial([random.randint(0, q-1) for _ in range(n)])

def matrix_mult_vec(A, vec, mod=q):
    result = [Polynomial() for _ in range(k)]
    for i in range(k):
        for j in range(k):
            product = A[i][j].multiply(vec[j], mod)
            result[i] = result[i].add(product, mod)
    return result

# --- Key Generation ---
def keygen():
    A = [[random_poly() for _ in range(k)] for _ in range(k)]
    s = [random_poly(small=True) for _ in range(k)]
    e = [random_poly(small=True) for _ in range(k)]
    t = matrix_mult_vec(A, s)
    t = [t[i].add(e[i]) for i in range(k)]
    return (A, t), s

# --- Encapsulation ---
def encapsulate(pk):
    A, t = pk
    r = [random_poly(small=True) for _ in range(k)]
    e1 = [random_poly(small=True) for _ in range(k)]
    e2 = random_poly(small=True)

    A_transposed = [[A[j][i] for j in range(k)] for i in range(k)]
    u = matrix_mult_vec(A_transposed, r)
    u = [u[i].add(e1[i]) for i in range(k)]

    m_bits = [random.randint(0, 1) for _ in range(n)]
    encoded_m = Polynomial([bit * (q // 2) for bit in m_bits])
    
    tTr = reduce(lambda acc, i: acc.add(t[i].multiply(r[i])), range(k), Polynomial())
    v = tTr.add(e2).add(encoded_m)
    return (u, v), m_bits

# --- Decapsulation (Fixed) ---
def decapsulate(sk, ct):
    s, (u, v) = sk, ct
    sTu = reduce(lambda acc, i: acc.add(s[i].multiply(u[i])), range(k), Polynomial())
    w = v.subtract(sTu)
    lower = q // 4
    upper = 3 * lower
    return [1 if (lower <= c < upper) else 0 for c in w.coeffs]

# --- Testing Suite ---
def test_kyber():
    # Test 1: Deterministic correctness
    random.seed(42)
    pk, sk = keygen()
    ct, secret = encapsulate(pk)
    print("Test 1 : Original Secret:", secret)
    recovered = decapsulate(sk, ct)
    print("Test 1 : Recovered Secret:", recovered)

    assert secret == recovered, f"Failed: {secret} vs {recovered}"

    # Test 2: Wrong secret key
    _, wrong_sk = keygen()
    print("Test 2 : Original Secret:", secret)
    wrong_recovered = decapsulate(wrong_sk, ct)
    print("Test 2 : Recovered Secret:", wrong_recovered)
    assert wrong_recovered != secret, f"Wrong SK test failed: {secret} vs {wrong_recovered}"

    print("All tests passed!")

# --- Demo ---
def main():
    print("Running demo:")
    pk, sk = keygen()
    ct, shared = encapsulate(pk)
    recovered = decapsulate(sk, ct)
    print("Original:", shared)
    print("Decrypted:", recovered)
    assert shared == recovered, "Mismatch in demo"
    print("Demo successful!\n")

    print("Running tests:")
    test_kyber()

if __name__ == "__main__":
    main()