import random
from functools import reduce

# --- Simplified Kyber Parameters ---
n = 4                # Degree of polynomials (representing polynomials modulo x^n + 1)
q = 17               # Modulus for polynomial coefficients (small prime for demonstration)
k = 2                # Dimension (module rank), so our keys are vectors (or matrices) of size k
noise_magnitude = 1  # Maximum absolute value for noise coefficients

class Polynomial:
    """A simple polynomial class that represents a polynomial of degree < n
    with integer coefficients modulo q."""
    def __init__(self, coeffs=None):
        # If no coefficients are given, default to the zero polynomial
        self.coeffs = coeffs if coeffs else [0]*n
    
    def add(self, other, mod=q):
        """Adds two polynomials coefficient-wise modulo mod."""
        return Polynomial([(a + b) % mod for a, b in zip(self.coeffs, other.coeffs)])
    
    def subtract(self, other, mod=q):
        """Subtracts another polynomial from this one coefficient-wise modulo mod."""
        return Polynomial([(a - b) % mod for a, b in zip(self.coeffs, other.coeffs)])
    
    def multiply(self, other, mod=q):
        """
        Multiplies two polynomials using the schoolbook method.
        Reduction is performed modulo (x^n + 1), which means that
        x^n is replaced with -1.
        """
        result = [0] * (2*n)
        # Perform convolution of the coefficients
        for i in range(n):
            for j in range(n):
                result[i+j] += self.coeffs[i] * other.coeffs[j]
        #  Reduce modulo x^n + 1: For i in [n, 2*n-1], subtract result[i] from result[i-n]
        for i in range(n, 2*n):
            result[i - n] -= result[i]
            result[i] = 0 # Optional: zero out the higher-degree part
        # Return the resulting polynomial with coefficients reduced modulo mod
        return Polynomial([x % mod for x in result[:n]])
    
    def __repr__(self):
        return f"Poly({self.coeffs})"

# --- Helper Functions ---
def random_poly(small=False):
    """
    Generate a random polynomial.
    
    If 'small' is True, generate a polynomial with coefficients
    in the range [-noise_magnitude, noise_magnitude]. This is used
    for secrets and noise.
    
    Otherwise, generate a polynomial with coefficients in [0, q-1].
    """
    if small:
        return Polynomial([random.randint(-noise_magnitude, noise_magnitude) for _ in range(n)])
    else:
        return Polynomial([random.randint(0, q-1) for _ in range(n)])

def matrix_mult_vec(A, vec, mod=q):
    """
    Multiply a matrix A (of size k x k, with polynomial entries) by a
    vector of polynomials (of length k). The result is computed using
    polynomial multiplication and addition.
    """
    result = [Polynomial() for _ in range(k)]
    for i in range(k):
        for j in range(k):
            product = A[i][j].multiply(vec[j], mod)
            result[i] = result[i].add(product, mod)
    return result

def vec_add_noise(vec, noise_mag=noise_magnitude):
    """
    Add noise to a vector of polynomials by generating a small random
    polynomial for each component and adding it.
    """
    noise = [random_poly(small=True) for _ in range(k)]
    return [vec[i].add(noise[i]) for i in range(k)]

# --- Key Generation ---
def keygen():
    """
    Generates a public/secret key pair for our simplified scheme.
    
    Process:
      1. Generate a public random matrix A.
      2. Generate a secret key vector s and error vector e (both small).
      3. Compute the public key t = A*s + e.
    
    Returns:
      - A tuple ((A, t), s) where (A, t) is the public key and s is the private key.
    """
    # 1. Public parameter: random matrix A of polynomials
    A = [[random_poly() for _ in range(k)] for _ in range(k)]
    
    # 2. Secret key s and error vector e (with small coefficients)
    s = [random_poly(small=True) for _ in range(k)]
    e = [random_poly(small=True) for _ in range(k)]
    
    # 3. Compute public key t = A * s + e
    t = matrix_mult_vec(A, s)
    t = [t[i].add(e[i]) for i in range(k)]
    
    return (A, t), s  # (public key, private key)

# --- Encapsulation (Sender) ---
def encapsulate(pk):
    """
    Encapsulation process to generate a ciphertext and a shared secret.
    
    Process:
      1. Generate a random vector r and add small noise (e1 and e2).
      2. Compute u = A^T * r + e1.
      3. Compute v = t^T * r + e2 + encode(m), where m is the message (secret).
         Here we encode m as a polynomial with m * (q//2) in the first coefficient.
    
    Returns:
      - A tuple ((u, v), m) where (u, v) is the ciphertext and m is the shared secret.
    """
    A, t = pk
    
    # 1. Sample a random vector r and noise e1 (for u) and e2 (for v)
    r = [random_poly(small=True) for _ in range(k)]
    e1 = vec_add_noise([Polynomial()]*k)
    e2 = random_poly(small=True)
    
    # 2. Compute u = A^T * r + e1
    #    First, compute the transpose of A.
    A_transposed = [[A[j][i] for j in range(k)] for i in range(k)]
    u = matrix_mult_vec(A_transposed, r)
    u = [u[i].add(e1[i]) for i in range(k)]
    
    # 3. Generate a shared secret m (0 or 1 for simplicity) and encode it.
    m = random.randint(0, 1)
    # Simple encoding: a polynomial with first coefficient m*(q//2) and the rest zero.
    encoded_m = Polynomial([m * (q // 2)] + [0] * (n - 1))
    # Compute v = t^T * r + e2 + encoded_m.
    # Here, we multiply componentwise and sum the results.
    tTr = reduce(lambda acc, i: acc.add(t[i].multiply(r[i])), range(k), Polynomial())
    v = tTr.add(e2).add(encoded_m)
    
    return (u, v), m  # Ciphertext and shared secret

# --- Decapsulation (Receiver) ---
def decapsulate(sk, ct):
    """
    Decapsulation process to recover the shared secret from the ciphertext.
    
    Process:
      1. Compute w = v - s^T * u.
      2. Decode the shared secret m from the first coefficient of w.
         Here we compare against a threshold (q//4) to decide whether m is 0 or 1.
    
    Args:
      sk: The secret key (vector of polynomials s).
      ct: The ciphertext, a tuple (u, v).
    
    Returns:
      The recovered shared secret m (0 or 1).
    """
    s = sk
    u, v = ct
    
    # 1. Compute s^T * u (i.e., sum of s[i] * u[i] for i in range(k))
    sTu = reduce(lambda acc, i: acc.add(s[i].multiply(u[i])), range(k), Polynomial())
    w = v.subtract(sTu, mod=q)
    
    # 2. Decode m by checking if the first coefficient is close to 0 or q//2.
    # The threshold is chosen as q//4.
    threshold = q//4
    m_recovered = 0 if abs(w.coeffs[0]) < threshold else 1
    return m_recovered

# --- Demo ---
def main():
    """
    A simple demonstration of the key encapsulation mechanism.
    It performs key generation, encapsulation, decapsulation, and asserts that
    both parties derive the same shared secret.
    """
    # Generate public and private keys
    pk, sk = keygen()
    print("Public key (A, t) and private key (s) generated.\n")
    
    # Encapsulation: sender encapsulates a secret
    ct, shared_secret = encapsulate(pk)
    print(f"Sender encapsulated secret: {shared_secret}\n")
    
    # Decapsulation: receiver recovers the secret using their private key
    recovered_secret = decapsulate(sk, ct)
    print(f"Receiver decrypted secret: {recovered_secret}\n")
    
    # Verify that both parties derive the same shared secret
    assert shared_secret == recovered_secret, "Secrets do not match!"
    print("Success: Shared secrets match!")

if __name__ == "__main__":
    main()
