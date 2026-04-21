"""
AES (Advanced Encryption Standard) - Implémentation Python pure
Sans aucune librairie de cryptographie.
Supporte AES-128, AES-192 et AES-256.

Usage:
    aes = AES(key)
    chiffré = aes.encrypt(texte_clair)
    clair   = aes.decrypt(chiffré)
"""

import os

# ─────────────────────────────────────────────────────────────────────────────
# TABLE S-BOX (SubBytes)
# ─────────────────────────────────────────────────────────────────────────────
SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

# ─────────────────────────────────────────────────────────────────────────────
# TABLE S-BOX INVERSE (InvSubBytes)
# ─────────────────────────────────────────────────────────────────────────────
INV_SBOX = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
    0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
    0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
    0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
    0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
    0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
    0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
    0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
    0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
    0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
    0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTES DE TOUR (Round Constants) pour KeyExpansion
# ─────────────────────────────────────────────────────────────────────────────
RCON = [
    0x00,  # non utilisé (index 0)
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1B, 0x36,
]

# ─────────────────────────────────────────────────────────────────────────────
# TABLES DE MULTIPLICATION DANS GF(2^8) pour MixColumns
# ─────────────────────────────────────────────────────────────────────────────

def _xtime(a):
    """Multiplication par 2 dans GF(2^8) (mod 0x11B)."""
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF

def _gmul(a, b):
    """Multiplication générale dans GF(2^8) par algorithme 'peasant russe'."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

# Tables précalculées pour MixColumns (×2, ×3) et InvMixColumns (×9, ×11, ×13, ×14)
MUL2  = [_gmul(i, 2)  for i in range(256)]
MUL3  = [_gmul(i, 3)  for i in range(256)]
MUL9  = [_gmul(i, 9)  for i in range(256)]
MUL11 = [_gmul(i, 11) for i in range(256)]
MUL13 = [_gmul(i, 13) for i in range(256)]
MUL14 = [_gmul(i, 14) for i in range(256)]


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS : état AES = liste plate de 16 octets (colonne-major)
# ─────────────────────────────────────────────────────────────────────────────

def _bytes_to_state(block: bytes) -> list:
    """Convertit 16 octets en état AES (colonne-major)."""
    s = [0] * 16
    for r in range(4):
        for c in range(4):
            s[r + 4 * c] = block[r + 4 * c]
    return s

def _state_to_bytes(state: list) -> bytes:
    """Reconvertit l'état AES en 16 octets."""
    return bytes(state)


# ─────────────────────────────────────────────────────────────────────────────
# ÉTAPES DU CHIFFREMENT
# ─────────────────────────────────────────────────────────────────────────────

def _add_round_key(state: list, round_key: list) -> list:
    """XOR entre l'état et la sous-clé de tour."""
    return [state[i] ^ round_key[i] for i in range(16)]

def _sub_bytes(state: list) -> list:
    """Substitution non-linéaire via S-Box."""
    return [SBOX[b] for b in state]

def _inv_sub_bytes(state: list) -> list:
    """Substitution inverse via S-Box inverse."""
    return [INV_SBOX[b] for b in state]

def _shift_rows(state: list) -> list:
    """Décalage cyclique des lignes vers la gauche."""
    s = state[:]
    # Ligne 0 : pas de décalage
    # Ligne 1 : décalage de 1
    s[1],  s[5],  s[9],  s[13] = state[5],  state[9],  state[13], state[1]
    # Ligne 2 : décalage de 2
    s[2],  s[6],  s[10], s[14] = state[10], state[14], state[2],  state[6]
    # Ligne 3 : décalage de 3
    s[3],  s[7],  s[11], s[15] = state[15], state[3],  state[7],  state[11]
    return s

def _inv_shift_rows(state: list) -> list:
    """Décalage cyclique des lignes vers la droite (inverse)."""
    s = state[:]
    # Ligne 1 : décalage de 3 à droite (= 1 à gauche inversé)
    s[1],  s[5],  s[9],  s[13] = state[13], state[1],  state[5],  state[9]
    # Ligne 2 : décalage de 2
    s[2],  s[6],  s[10], s[14] = state[10], state[14], state[2],  state[6]
    # Ligne 3 : décalage de 1 à droite
    s[3],  s[7],  s[11], s[15] = state[7],  state[11], state[15], state[3]
    return s

def _mix_columns(state: list) -> list:
    """Mélange linéaire des colonnes dans GF(2^8)."""
    s = state[:]
    for c in range(4):
        i = c * 4
        a = state[i:i+4]
        s[i]   = MUL2[a[0]] ^ MUL3[a[1]] ^ a[2]       ^ a[3]
        s[i+1] = a[0]       ^ MUL2[a[1]] ^ MUL3[a[2]] ^ a[3]
        s[i+2] = a[0]       ^ a[1]       ^ MUL2[a[2]]  ^ MUL3[a[3]]
        s[i+3] = MUL3[a[0]] ^ a[1]       ^ a[2]        ^ MUL2[a[3]]
    return s

def _inv_mix_columns(state: list) -> list:
    """Mélange inverse des colonnes dans GF(2^8)."""
    s = state[:]
    for c in range(4):
        i = c * 4
        a = state[i:i+4]
        s[i]   = MUL14[a[0]] ^ MUL11[a[1]] ^ MUL13[a[2]] ^ MUL9[a[3]]
        s[i+1] = MUL9[a[0]]  ^ MUL14[a[1]] ^ MUL11[a[2]] ^ MUL13[a[3]]
        s[i+2] = MUL13[a[0]] ^ MUL9[a[1]]  ^ MUL14[a[2]] ^ MUL11[a[3]]
        s[i+3] = MUL11[a[0]] ^ MUL13[a[1]] ^ MUL9[a[2]]  ^ MUL14[a[3]]
    return s


# ─────────────────────────────────────────────────────────────────────────────
# EXPANSION DE CLÉ (Key Schedule)
# ─────────────────────────────────────────────────────────────────────────────

def _key_expansion(key: bytes) -> list:
    """
    Génère toutes les sous-clés de tour à partir de la clé principale.
    Retourne une liste de (Nr+1) sous-clés, chacune de 16 octets.
    Supporte AES-128 (16), AES-192 (24) et AES-256 (32) octets.
    """
    key_len = len(key)
    if key_len == 16:
        Nk, Nr = 4, 10
    elif key_len == 24:
        Nk, Nr = 6, 12
    elif key_len == 32:
        Nk, Nr = 8, 14
    else:
        raise ValueError("Longueur de clé invalide : 16, 24 ou 32 octets requis.")

    # W : liste de mots de 4 octets
    W = []
    for i in range(Nk):
        W.append(list(key[4*i : 4*i+4]))

    total_words = 4 * (Nr + 1)
    i = Nk
    while len(W) < total_words:
        temp = W[i - 1][:]
        if i % Nk == 0:
            # RotWord + SubWord + XOR Rcon
            temp = [SBOX[temp[1]] ^ RCON[i // Nk],
                    SBOX[temp[2]],
                    SBOX[temp[3]],
                    SBOX[temp[0]]]
        elif Nk > 6 and (i % Nk) == 4:
            temp = [SBOX[b] for b in temp]
        W.append([W[i - Nk][j] ^ temp[j] for j in range(4)])
        i += 1

    # Reconvertit en sous-clés de 16 octets (4 mots par sous-clé)
    round_keys = []
    for r in range(Nr + 1):
        rk = []
        for c in range(4):
            rk.extend(W[r * 4 + c])
        round_keys.append(rk)
    return round_keys


# ─────────────────────────────────────────────────────────────────────────────
# CHIFFREMENT / DÉCHIFFREMENT D'UN BLOC (16 octets)
# ─────────────────────────────────────────────────────────────────────────────

def _encrypt_block(block: bytes, round_keys: list) -> bytes:
    """Chiffre un bloc de 16 octets avec les sous-clés données."""
    Nr = len(round_keys) - 1
    state = _bytes_to_state(block)

    state = _add_round_key(state, round_keys[0])

    for r in range(1, Nr):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[r])

    # Tour final (sans MixColumns)
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[Nr])

    return _state_to_bytes(state)

def _decrypt_block(block: bytes, round_keys: list) -> bytes:
    """Déchiffre un bloc de 16 octets avec les sous-clés données."""
    Nr = len(round_keys) - 1
    state = _bytes_to_state(block)

    state = _add_round_key(state, round_keys[Nr])

    for r in range(Nr - 1, 0, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, round_keys[r])
        state = _inv_mix_columns(state)

    # Tour initial inverse (sans InvMixColumns)
    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, round_keys[0])

    return _state_to_bytes(state)


# ─────────────────────────────────────────────────────────────────────────────
# PADDING PKCS#7
# ─────────────────────────────────────────────────────────────────────────────

def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Ajoute un rembourrage PKCS#7."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def _pkcs7_unpad(data: bytes) -> bytes:
    """Retire le rembourrage PKCS#7."""
    if not data:
        raise ValueError("Données vides.")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 16:
        raise ValueError("Rembourrage PKCS#7 invalide.")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Rembourrage PKCS#7 corrompu.")
    return data[:-pad_len]


# ─────────────────────────────────────────────────────────────────────────────
# CLASSE PRINCIPALE AES (mode CBC)
# ─────────────────────────────────────────────────────────────────────────────

class AES:
    """
    AES en mode CBC avec IV aléatoire et rembourrage PKCS#7.

    Paramètres :
        key (bytes) : clé de 16, 24 ou 32 octets (AES-128/192/256).

    Méthodes :
        encrypt(plaintext: str | bytes) -> bytes
            Chiffre et retourne : IV (16 octets) || chiffré
        decrypt(ciphertext: bytes) -> str
            Déchiffre et retourne le texte clair UTF-8.
    """

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("La clé doit faire 16, 24 ou 32 octets.")
        self._round_keys = _key_expansion(key)
        self._Nr = len(self._round_keys) - 1

    # ── Chiffrement CBC ──────────────────────────────────────────────────────
    def encrypt(self, plaintext) -> bytes:
        """
        Chiffre le texte clair (str ou bytes) en mode CBC.
        Retourne IV || ciphertext.
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        iv = os.urandom(16)
        padded = _pkcs7_pad(plaintext)
        ciphertext = bytearray()
        prev = iv

        for i in range(0, len(padded), 16):
            block = bytes(a ^ b for a, b in zip(padded[i:i+16], prev))
            enc   = _encrypt_block(block, self._round_keys)
            ciphertext.extend(enc)
            prev = enc

        return iv + bytes(ciphertext)

    # ── Déchiffrement CBC ────────────────────────────────────────────────────
    def decrypt(self, ciphertext: bytes) -> str:
        """
        Déchiffre IV || ciphertext (mode CBC).
        Retourne le texte clair en UTF-8.
        """
        if len(ciphertext) < 32 or (len(ciphertext) - 16) % 16 != 0:
            raise ValueError("Longueur de texte chiffré invalide.")

        iv         = ciphertext[:16]
        ciphertext = ciphertext[16:]
        plaintext  = bytearray()
        prev       = iv

        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            dec   = _decrypt_block(block, self._round_keys)
            plaintext.extend(a ^ b for a, b in zip(dec, prev))
            prev = block

        return _pkcs7_unpad(bytes(plaintext)).decode('utf-8')

'''
# ─────────────────────────────────────────────────────────────────────────────
# DÉMONSTRATION
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  AES Python pur — Démonstration (CBC, PKCS#7)")
    print("=" * 60)

    # ── AES-128 ──────────────────────────────────────────────────────────────
    key128 = b"cle_secrete_16b!"          # 16 octets
    aes128 = AES(key128)
    message = "Bonjour, voici un message secret en français !"

    print(f"\n[AES-128]")
    print(f"  Clé      : {key128}")
    print(f"  Message  : {message}")````

    chiffre = aes128.encrypt(message)
    print(f"  Chiffré  : {chiffre.hex()}")

    clair = aes128.decrypt(chiffre)
    print(f"  Déchiffré: {clair}")
    print(f"  OK       : {message == clair}")

    # ── AES-192 ──────────────────────────────────────────────────────────────
    key192 = b"cle_secrete_24_octets!!!"  # 24 octets
    aes192 = AES(key192)
    print(f"\n[AES-192]")
    chiffre192 = aes192.encrypt(message)
    print(f"  Chiffré  : {chiffre192.hex()}")
    print(f"  Déchiffré: {aes192.decrypt(chiffre192)}")

    # ── AES-256 ──────────────────────────────────────────────────────────────
    key256 = b"cle_tres_secrete_de_32_octets!!!"  # 32 octets
    aes256 = AES(key256)
    print(f"\n[AES-256]")
    chiffre256 = aes256.encrypt(message)
    print(f"  Chiffré  : {chiffre256.hex()}")
    print(f"  Déchiffré: {aes256.decrypt(chiffre256)}")

    # ── Test avec clé et texte personnalisés ─────────────────────────────────
    print("\n" + "=" * 60)
    print("  Test interactif")
    print("=" * 60)
    ma_cle = b"Ma_Cle_Secrete!!"   # exactement 16 octets
    mon_texte = "AES implémenté sans librairie — 100 % Python pur."
    aes = AES(ma_cle)
    c = aes.encrypt(mon_texte)
    print(f"  Texte original : {mon_texte}")
    print(f"  Chiffré (hex)  : {c.hex()}")
    print(f"  Déchiffré      : {aes.decrypt(c)}")
    print("\nDone ✓")
'''