# Lab 1 — Symmetric Encryption with Crypto++

## Dependencies

| Dependency | Version |
|---|---|
| Crypto++ | ≥ 8.2 |
| CMake | ≥ 3.16 |
| C++ compiler | GCC ≥ 11 / MSVC 2019 / Clang ≥ 13 |

### Install Crypto++

```bash
# Ubuntu / Debian
sudo apt install libcryptopp-dev

# Windows (vcpkg)
vcpkg install cryptopp:x64-windows
```

---

## Build

```bash
# Out-of-source build (required)
mkdir build && cd build
cmake ..
cmake --build .

# Release build explicitly
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

---

## Usage

### Key generation

```bash
./aescli keygen --bits 256 --out key.bin
./aescli keygen --bits 256 --out key_xts.bin --xts   # XTS: 2× key
```

### Encrypt

```bash
# GCM (AEAD, recommended)
./aescli encrypt --mode gcm --key key.bin --in plain.txt --out ct.bin --aead

# GCM with Additional Authenticated Data
./aescli encrypt --mode gcm --key key.bin --in plain.txt --out ct.bin --aead --aad-text "header"

# CBC
./aescli encrypt --mode cbc --key key.bin --in plain.txt --out ct.bin

# CTR
./aescli encrypt --mode ctr --key key.bin --in plain.txt --out ct.bin

# ECB (insecure — requires --allow-ecb for files > 16 KB)
./aescli encrypt --mode ecb --key key.bin --in small.txt --out ct.bin --allow-ecb

# XTS
./aescli encrypt --mode xts --key key_xts.bin --in plain.txt --out ct.bin

# From string, base64 output
./aescli encrypt --mode gcm --key key.bin --text "hello world" --out ct.bin --encode base64
```

### Decrypt

```bash
# IV is auto-loaded from ct.bin.json sidecar
./aescli decrypt --mode gcm --key key.bin --in ct.bin --out plain.txt --aead

# Supply IV explicitly
./aescli decrypt --mode cbc --key key.bin --in ct.bin --out plain.txt --iv iv.bin
```

### KAT runner

```bash
./aescli --kat nist_vectors.json
```

### Benchmark

```bash
./bench
./bench --runs 100 --bits 256 --csv results.csv
```

---

## Sidecar JSON

Every encrypt operation (except ECB) produces `<outfile>.json`:

```json
{
  "alg"    : "AES-256-GCM",
  "mode"   : "gcm",
  "iv"     : "aabbcc...",
  "aad"    : "...",
  "tag"    : "",
  "key_fp" : "2b7e1516..."
}
```

Decrypt reads this automatically if `--iv` is not supplied.

---

## Nonce-reuse protection

For CTR, GCM, CCM: before encrypting, the tool checks if `<outfile>.json` already exists
with the same key fingerprint and IV. If yes, the operation is **rejected** with an error.
This prevents catastrophic keystream reuse.

---

## Known Limitations

- ECB mode intentionally blocked for files > 16 KB (override with `--allow-ecb`)
- XTS mode uses sector tweak = 0 (single-sector demo); production use requires per-sector tweak
- CCM requires known plaintext length in advance (limitation of CCM design)
- KAT JSON parser is minimal — no support for nested objects or escaped quotes
- Nonce-reuse detection is file-based (sidecar JSON); does not persist across reboots by design
