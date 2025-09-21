#!/usr/bin/env python3
"""
cbc_bitflip.py -- small utility to perform CBC bit-flipping edits on a ciphertext when you know the plaintext.

Usage examples:
1) Single replacement (bdmin -> admin):
   python3 cbc_bitflip.py --cipher 8b6222... --plain "access_username= bdmin&password=..." --replace bdmin:admin:[occurrence]

2) Multiple replacements (comma-separated):
   python3 cbc_bitflip.py --cipher <hex> --plain "<plaintext>" --replace old1:new1:[occurence],old2:new2:[occurrence]

3) If the target lies in the first plaintext block (block 0), provide IV hex:
   python3 cbc_bitflip.py --cipher <hex> --plain "<plaintext>" --replace foo:bar --iv <iv_hex>

Outputs:
- New ciphertext hex (printed)
- If IV modified, prints new IV hex
- A table of flips applied (absolute plaintext index, block, offset, previous block/IV, old and new cipher bytes, mask)
- Optionally writes output to --out-file

Notes/warnings:
- old and new substrings must be the same length for simple bytewise replacements.
- This tool does NOT re-encrypt or verify decryption; it only edits ciphertext bytes for CBC bit-flip attacks.
- Use only on targets you have permission to test.
"""

import argparse
from binascii import unhexlify, hexlify
from math import ceil
import sys

BLOCK_SIZE = 16

def art():
    banner = r"""
  ____ ____   ____   ____  _   _     ____ _   _  ____       
 / ___| __ ) / ___| | __ )(_)_| |_  /  __] | (_)/ _  \    
| |   |  _ \| |     |  _ \| |\_ __\ | |_ | | | | |_) |   
| |___| |_) | |___  | |_) | | | |   | __]| |_| |  __/   
 \____|____/ \____| |____/|_|  \_\  |_/   \__]_|_|        
 
 CBC Bit-Flipping Utility (Python)
 Usage: python3 cbc_bitflip.py --cipher <hex> --plain "<plaintext>" --replace old:new:[occurrence] [--iv <iv_hex>] [--out-file <file>]
"""
    print(banner)
    sys.exit(0)


def hex_to_blocks(hexstr, block_size=BLOCK_SIZE):
    b = unhexlify(hexstr)
    if len(b) % block_size != 0:
        raise ValueError("Ciphertext length is not a multiple of the block size (16 bytes). Provide full ciphertext blocks.")
    return [bytearray(b[i:i+block_size]) for i in range(0, len(b), block_size)]

def blocks_to_hex(blocks):
    return hexlify(b"".join(blocks)).decode()

def find_all_occurrences(haystack: bytes, needle: bytes):
    start = 0
    res = []
    while True:
        idx = haystack.find(needle, start)
        if idx == -1:
            break
        res.append(idx)
        start = idx + 1
    return res

def apply_replacements(cipher_hex, known_plaintext_bytes, replacements, iv_hex=None):
    cipher_blocks = hex_to_blocks(cipher_hex)
    new_blocks = [bytearray(b) for b in cipher_blocks]
    flips = []
    modified_iv = None

    for old_bytes, new_bytes, occurrence in replacements:
        if len(old_bytes) != len(new_bytes):
            raise ValueError("Replacement pair must have the same byte length (old and new).")
        occs = find_all_occurrences(known_plaintext_bytes, old_bytes)
        if not occs:
            continue
        if occurrence > 0:
            if len(occs) >= occurrence:
                occs = [occs[occurrence-1]]
            else:
                occs = []  # occurrence not found, skip
            
        for occ in occs:
            for i in range(len(old_bytes)):
                abs_index = occ + i
                block_idx = abs_index // BLOCK_SIZE
                offset = abs_index % BLOCK_SIZE
                prev_block_idx = block_idx - 1
                mask = old_bytes[i] ^ new_bytes[i]
                if mask == 0:
                    continue
                if prev_block_idx >= 0:
                    old_c = new_blocks[prev_block_idx][offset]
                    new_c = old_c ^ mask
                    new_blocks[prev_block_idx][offset] = new_c
                    flips.append((abs_index, block_idx, offset, f"block {prev_block_idx}", old_c, new_c, mask))
                else:
                    # modify IV
                    if iv_hex is None:
                        raise ValueError(f"Target byte at absolute index {abs_index} is in plaintext block 0. Provide --iv to modify IV.")
                    iv_block = bytearray(unhexlify(iv_hex))
                    old_iv_b = iv_block[offset]
                    new_iv_b = old_iv_b ^ mask
                    iv_block[offset] = new_iv_b
                    modified_iv = hexlify(bytes(iv_block)).decode()
                    flips.append((abs_index, block_idx, offset, "IV", old_iv_b, new_iv_b, mask))
    return blocks_to_hex(new_blocks), modified_iv, flips

def parse_replacements(text):
    """
    Parses replacement string.
    Format: old:new[:occurrence], multiple replacements comma-separated
    Example: a:d:0,b:c:1
    Returns: list of tuples (old_bytes, new_bytes, occurrence)
    """
    pairs = []
    for part in text.split(","):
        fields = part.split(":")
        if len(fields) < 2:
            raise argparse.ArgumentTypeError("Replacements must be in the form old:new[:occurrence]")
        old, new = fields[0], fields[1]
        occ = int(fields[2]) if len(fields) == 3 else 0
        pairs.append((old.encode('utf-8'), new.encode('utf-8'), occ))
    return pairs

def pretty_print_flips(flips):
    if not flips:
        print("No flips applied.")
        return
    print("\n╔════════════╦══════════╦════════╦════════════╦══════════════╦══════════════╦═══════╗")
    print("║ abs_idx    ║ pt_block ║ offset ║ prev_block ║ old_cipher   ║ new_cipher   ║ mask  ║")
    print("╠════════════╬══════════╬════════╬════════════╬══════════════╬══════════════╬═══════╣")
    for f in flips:
        abs_idx, block_idx, offset, prev_block_desc, old_c, new_c, mask = f
        print(f"║ {abs_idx:10d} ║ {block_idx:8d} ║ {offset:6d} ║ {prev_block_desc:10s} ║ 0x{old_c:02X}         ║ 0x{new_c:02X}         ║ 0x{mask:02X}  ║")
    print("╚════════════╩══════════╩════════╩════════════╩══════════════╩══════════════╩═══════╝\n")


def main():
    if len(sys.argv) == 1:
        art()
        
    p = argparse.ArgumentParser(description="CBC bit-flip editor (requires known plaintext).")
    p.add_argument("--cipher", required=True, help="Ciphertext hex (full blocks).")
    p.add_argument("--plain", required=True, help="Known plaintext (exact bytes).")
    p.add_argument("--replace", required=True, help="Replacement(s) old:new or old1:new1:[occurrence],old2:new2:[occurrence] (old and new must be same length).")
    p.add_argument("--iv", required=False, help="Hex of IV (16 bytes) if you need to modify plaintext block 0.")
    p.add_argument("--out-file", required=False, help="Optional: save new ciphertext hex to file.")

    args = p.parse_args()

    cipher_hex = args.cipher.strip()
    plain = args.plain.encode('utf-8')
    replacements = parse_replacements(args.replace)
    iv_hex = args.iv.strip() if args.iv else None

    cipher_bytes = unhexlify(cipher_hex)
    
    # auto-pad if needed
    if len(plain) < len(cipher_bytes):
        pad_len = len(cipher_bytes) - len(plain)
        if pad_len <= 16:  # valid PKCS#7 range
            plain += bytes([pad_len]) * pad_len
            print(f"[+] Auto-added PKCS#7 padding of {pad_len} bytes to plaintext.")
        else:
            raise ValueError("Plaintext is too short compared to ciphertext, can't auto-pad safely.")
    elif len(plain) > len(cipher_bytes):
        raise ValueError("Plaintext longer than ciphertext.")

    new_cipher_hex, new_iv_hex, flips = apply_replacements(cipher_hex, plain, replacements, iv_hex)
    print("\nOriginal cipher:")
    print(cipher_hex)
    print("\nModified cipher:")
    print(new_cipher_hex)
    if new_iv_hex:
        print("\nModified IV:")
        print(new_iv_hex)
    pretty_print_flips(flips)

    if args.out_file:
        with open(args.out_file, "w") as f:
            f.write(new_cipher_hex)
        print(f"\nNew ciphertext written to {args.out_file}")

if __name__ == "__main__":
    main()
