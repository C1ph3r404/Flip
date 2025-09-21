### 🔥 AES CBC Bit Flip (Math, but fun)

---

Alright, picture this: we want to trick the server into thinking we typed `admin` instead of `bdmin` in our login. But we can’t type it directly — so we go full hacker mode and **flip a bit in the ciphertext**.    

**Setup:**  

* Plaintext (unpadded):  
```
access_username=bdmin&password=sUp3rPaSs1
```
* AES block size = 16 → PKCS#7 padding to 48 bytes (`\x07` × 7).  
* Leaked ciphertext (3 blocks, hex, split for clarity):  
```
C₀ = 5dffa5ab07022a287f3439833db1893d
C₁ = 3da844a0098814d20b6d60a4af083bc0
C₂ = 4c49a1fe2e64a58aaa8902086f8c96ad
```

---

**Plaintext blocks after padding:**  

* P₀ = `access_username=` (bytes 0–15)  
* P₁ = `bdmin&password=s` (bytes 16–31) ← **target block** (our `bdmin`)  
* P₂ = `Up3rPaSs1` + padding (bytes 32–47)  

We only want to flip the first char: `b (0x62)` → `a (0x61)`.

---

### 🔐 How CBC decryption works (friendly version)

For block `i`:

$$
P_i = D_k(C_i) \oplus C_{i-1}
$$

Translation:  
- Decrypt the ciphertext block with the key  
- XOR with the **previous ciphertext block** (or IV if it’s the first block)  

So if we tweak a byte in `C₀`, it changes the corresponding byte in `P₁` after decryption. 🔄

**Bit flip formula:**  

$$
\text{mask} = \text{old} \oplus \text{new}
$$

$$
C'_0[j] = C_0[j] \oplus \text{mask}
$$

Boom — after decryption:

$$
P'_1[j] = P_1[j] \oplus \text{mask} = \text{new value we want}
$$

---

### ⚡ Concrete example

* old = `'b'` = `0x62`  
* new = `'a'` = `0x61`  
* mask = `0x62 ⊕ 0x61 = 0x03`  

We want to flip the **first byte of P₁**:  

* P₁ index = 16 → block 1, offset 0  
* So flip **C₀[0]**  

Original `C₀` = `5d ffa5ab07022a287f3439833db1893d` → first byte `0x5d`  
Flip it:  

```
C₀'[0] = 0x5d ⊕ 0x03 = 0x5e
```

Only that **one byte changes**. Rest of `C₀`, `C₁`, `C₂` stay the same.

---

### 🎉 Result

Original ciphertext:

```

5dffa5ab07022a287f3439833db1893d3da844a0098814d20b6d60a4af083bc04c49a1fe2e64a58aaa8902086f8c96ad

```

Modified ciphertext (one byte flipped):

```

5effa5ab07022a287f3439833db1893d3da844a0098814d20b6d60a4af083bc04c49a1fe2e64a58aaa8902086f8c96ad

```

See that? `5d → 5e` at the very start. That’s literally all it took to make the server believe we typed `admin` instead of `bdmin`. 🔥  

---

Basically, CBC bit-flip = **hacker’s tiny magic trick**: tweak the ciphertext → server decrypts → boom, it sees what we want.

---
