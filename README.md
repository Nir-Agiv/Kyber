# Kyber KEM Simplified Implementation

A simplified, educational version of the Kyber Key Encapsulation Mechanism (KEM), designed to demonstrate the core concepts of lattice-based cryptography. **Not for production use.**

## Features
- **Key Generation**: Create public and private keys using polynomial arithmetic.
- **Encapsulation**: Generate a shared secret and its encapsulated ciphertext.
- **Decapsulation**: Recover the shared secret using the private key.
- **Testing Suite**: Includes correctness and failure tests for verification.

## Parameters (Simplified)
- Polynomial degree: `n = 8`
- Modulus: `q = 257`
- Module rank: `k = 3`
- Noise magnitude: `1` (ensures errors stay within bounds)

## Installation
Requires Python 3.6+. No external dependencies.
```bash
python kyber.py
```

## Usage
### Generate keys
```bash
public_key, private_key = keygen()
```
### Encapsulate a secret
```bash
ciphertext, shared_secret = encapsulate(public_key)
```
### Decapsulate the secret
```bash
recovered_secret = decapsulate(private_key, ciphertext)
```

## Testing
Run the built-in test suite:
```bash
python kyber.py
```

## Security Note
This implementation uses drastically reduced parameters for simplicity. It is not secure against real-world attacks. Refer to the [Kyber official documentation](https://pq-crystals.org/kyber/) for production-ready versions.