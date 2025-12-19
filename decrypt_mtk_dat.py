#!/usr/bin/env python3
"""
MediaTek WiFi Calibration File Decryption Tool

Decrypts mtkwl*.dat calibration files used by MediaTek WiFi 6/6E drivers.
These files contain TX power limits and RF calibration data.

Algorithm:
    - Cipher: AES-128-CBC
    - Key: SHA1("____Mediatek____")[:16]
    - IV: First encrypted block decrypted via AES-ECB
    - Structure: 4096-byte chunks with validation

Author: [Your Name]
License: MIT
Repository: https://github.com/YOUR_USERNAME/mt7902-calibration-decrypt
"""

import sys
import hashlib
from pathlib import Path
from Crypto.Cipher import AES

# MediaTek's static encryption key string
KEY_STRING = b"____Mediatek____"

# Chunk size for processing encrypted data
CHUNK_SIZE = 4096


def derive_aes_key() -> bytes:
    """
    Derive AES-128 key from MediaTek's static string.
    
    Returns:
        bytes: 16-byte AES key derived from SHA1 hash
    """
    sha1_hash = hashlib.sha1(KEY_STRING).digest()
    return sha1_hash[:16]  # Use first 16 bytes as AES-128 key


def decrypt_dat_file(input_path: str, output_path: str) -> None:
    """
    Decrypt a MediaTek calibration DAT file.
    
    Args:
        input_path: Path to encrypted .dat file
        output_path: Path where decrypted file will be saved
        
    Raises:
        FileNotFoundError: If input file doesn't exist
        ValueError: If decryption validation fails
    """
    input_file = Path(input_path)
    output_file = Path(output_path)
    
    # Validate input
    if not input_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    
    # Read encrypted data
    print(f"Reading encrypted file: {input_file.name}")
    encrypted_data = input_file.read_bytes()
    file_size = len(encrypted_data)
    print(f"File size: {file_size:,} bytes")
    
    # Derive encryption key
    aes_key = derive_aes_key()
    
    # Decrypt data
    print("Decrypting...")
    decrypted_chunks = []
    num_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
    
    for chunk_idx in range(num_chunks):
        start = chunk_idx * CHUNK_SIZE
        end = min(start + CHUNK_SIZE, file_size)
        chunk = encrypted_data[start:end]
        
        # Pad last chunk if necessary
        if len(chunk) < CHUNK_SIZE:
            chunk = chunk + b'\x00' * (CHUNK_SIZE - len(chunk))
        
        # Calculate IV from first encrypted block using ECB
        cipher_ecb = AES.new(aes_key, AES.MODE_ECB)
        iv = cipher_ecb.decrypt(chunk[:16])
        
        # Decrypt chunk using CBC with calculated IV
        cipher_cbc = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        decrypted_chunk = cipher_cbc.decrypt(chunk)
        
        # Validate: first 16 bytes should be zeros
        if decrypted_chunk[:16] != b'\x00' * 16:
            raise ValueError(
                f"Decryption validation failed at chunk {chunk_idx}. "
                f"Expected 16 zeros, got: {decrypted_chunk[:16].hex()}"
            )
        
        # Store decrypted chunk (trim if last chunk)
        if chunk_idx == num_chunks - 1:
            actual_size = file_size - start
            decrypted_chunks.append(decrypted_chunk[:actual_size])
        else:
            decrypted_chunks.append(decrypted_chunk)
        
        # Progress indicator
        if (chunk_idx + 1) % 50 == 0:
            print(f"  Processed {chunk_idx + 1}/{num_chunks} chunks...")
    
    # Combine all decrypted chunks
    decrypted_data = b''.join(decrypted_chunks)
    
    # Write output
    output_file.write_bytes(decrypted_data)
    print(f"✓ Successfully decrypted to: {output_file.name}")
    print(f"  Output size: {len(decrypted_data):,} bytes")
    print(f"  Validated: {num_chunks} chunks")


def main():
    """Main entry point for command-line usage."""
    if len(sys.argv) != 3:
        print("MediaTek WiFi Calibration File Decryption Tool")
        print()
        print("Usage:")
        print(f"  {sys.argv[0]} <input.dat> <output.bin>")
        print()
        print("Example:")
        print(f"  {sys.argv[0]} mtkwl3.dat mtkwl3_decrypted.bin")
        print()
        print("Supported files:")
        print("  mtkwl1.dat, mtkwl1_2.dat   - MT7961 2.4 GHz")
        print("  mtkwl2.dat, mtkwl2_2.dat   - MT7922 5 GHz")
        print("  mtkwl2s.dat, mtkwl2_2s.dat - MT7922 5 GHz SAR")
        print("  mtkwl3.dat, mtkwl3_2.dat   - MT7902 6 GHz WiFi 6E")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    try:
        decrypt_dat_file(input_file, output_file)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
