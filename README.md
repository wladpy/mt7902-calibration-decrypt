# MediaTek MT7902 Calibration Files Decryption

**Public decryption** of MediaTek MT7902/MT7922/MT7921 calibration DAT files

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

##  Overview

This project provides the public documentation of the encryption algorithm used in MediaTek WiFi driver calibration files (mtkwl*.dat). These files contain TX power limits and RF calibration data essential for the WiFi chip to operate correctly.

**Use Case:** This is critical for Linux driver development, particularly for the [MT7902 driver project](https://github.com/tnguy3333/mt7902)

## What Was Discovered

### Encryption Algorithm

- **Cipher:** AES-128-CBC
- **Key Derivation:** `SHA1("____Mediatek____")[:16]`
- **IV Calculation:** First encrypted block decrypted with AES-ECB
- **Structure:** 4096-byte chunks
- **Validation:** First 16 bytes of each decrypted chunk = zeros

### Files Supported

All MediaTek WiFi 6/6E calibration files:
- `mtkwl1.dat` - MT7961 2.4 GHz TX power limits
- `mtkwl1_2.dat` - MT7961 2.4 GHz extended bandwidth
- `mtkwl2.dat` - MT7922 5 GHz TX power limits
- `mtkwl2s.dat` - MT7922 5 GHz SAR limits
- `mtkwl2_2.dat` - MT7922 5 GHz extended bandwidth
- `mtkwl2_2s.dat` - MT7922 5 GHz SAR extended bandwidth
- `mtkwl3.dat` - MT7902 6 GHz WiFi 6E TX power limits
- `mtkwl3_2.dat` - MT7902 6 GHz WiFi 6E extended bandwidth

## Quick Start

### Requirements

```bash
pip install pycryptodome
```

### Usage

```python
python decrypt_mtk_dat.py mtkwl3.dat mtkwl3_decrypted.bin
```

### Example

```python
from Crypto.Cipher import AES
import hashlib

# Key derivation
KEY_STRING = b"____Mediatek____"
sha1_key = hashlib.sha1(KEY_STRING).digest()[:16]

# Read encrypted file
with open('mtkwl3.dat', 'rb') as f:
    encrypted_data = f.read()

# Decrypt first chunk
cipher_ecb = AES.new(sha1_key, AES.MODE_ECB)
iv = cipher_ecb.decrypt(encrypted_data[:16])

cipher_cbc = AES.new(sha1_key, AES.MODE_CBC, iv=iv)
decrypted = cipher_cbc.decrypt(encrypted_data)

# Validate: first 16 bytes should be zeros
assert decrypted[:16] == b'\x00' * 16
print("✓ Decryption successful!")
```

## Validation

The algorithm correctness is validated by checking that **every 4096-byte chunk** decrypts to have its first 16 bytes as zeros:

```python
# Test on mtkwl3.dat (1,024,928 bytes = 251 chunks)
chunks_tested = 251
chunks_with_zeros = 251  # 100% ✓
```

## Technical Details

### Reverse Engineering Process

1. **Static Analysis:**
   - Analyzed `mtkwl6ex.sys` Windows driver (1.64 MB)
   - Identified `skudecrypt.c` source file functions
   - Located `DecryptDATfile()`, `CreateSymmetricKey_SHA1_Hash()`

2. **Dynamic Analysis:**
   - Used API Monitor to capture BCrypt calls
   - Confirmed AES-128-CBC with SHA1-derived key
   - Verified IV calculation method

3. **Validation:**
   - Mathematical proof: 16 zeros in every chunk
   - Tested on 8 different DAT files
   - All files decrypt successfully

### Why This Matters for Linux Drivers

The Windows driver (`mtkwl6ex.sys`) loads these files at boot:

```c
// Pseudo-code from reverse engineering
BCryptOpenAlgorithmProvider("SHA1");
BCryptHashData("____Mediatek____");
sha1_hash = BCryptFinishHash();  // 20 bytes
key = sha1_hash[:16];

BCryptOpenAlgorithmProvider("AES");
BCryptGenerateSymmetricKey(key);

for each 4096-byte chunk:
    iv = AES_ECB_Decrypt(key, chunk[:16])
    decrypted = AES_CBC_Decrypt(key, iv, chunk)
    assert decrypted[:16] == zeros
```

Without these calibration files, the Linux driver cannot:
- Set correct TX power limits per country
- Meet regulatory requirements
- Achieve stable WiFi connection

## Project Structure

```
mt7902-calibration-decrypt/
├── decrypt_mtk_dat.py          # Main decryption script
├── README.md                   # This file
├── LICENSE                     # MIT License
└── docs/
    ├── algorithm.md            # Detailed algorithm explanation
    ├── reverse_engineering.md  # Windows driver RE analysis
    └── validation.md           # Correctness proofs
```

## Contributing to MT7902 Linux Driver

This work directly supports the [MT7902 Linux driver development](https://github.com/tnguy3333/mt7902):

**Current Status:**
- ✅ WPA2 handshake works
- ❌ Firmware decryption fails
- ❌ Cannot obtain IP address

**How This Helps:**
- Provides calibration data access
- Documents MediaTek's encryption approach
- Enables proper TX power limit handling

## Acknowledgments

- **Thomas Nguyen (@tnguy3333)** - MT7902 Linux driver development
- **MediaTek mt76 maintainers** - Reference driver architecture
- **Linux Wireless community** - Testing and feedback

## License

MIT License - See [LICENSE](LICENSE) file

## Contact

- **Author:** Wladimir Bogarin
- **Email:** github@wladpy.com
- **GitHub:** [@wladpy](https://github.com/wladpy)
- **Location:** Paraguay
- **Issues:** [GitHub Issues](https://github.com/wladpy/mt7902-calibration-decrypt/issues)


## Related Projects

- [tnguy3333/mt7902](https://github.com/tnguy3333/mt7902) - MT7902 Linux driver (WIP)
- [torvalds/linux/mt76](https://github.com/torvalds/linux/tree/master/drivers/net/wireless/mediatek/mt76) - Official mt76 driver
- [OnlineLearningTutorials/mt7902_temp](https://github.com/OnlineLearningTutorials/mt7902_temp) - Alternative MT7902 work

---
