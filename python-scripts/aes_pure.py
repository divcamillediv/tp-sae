"""
╔══════════════════════════════════════════════════════════════╗
║        AES — Implémentation Python pure (sans librairie)     ║
║        Mode CBC · Padding PKCS#7 · AES-128 / 192 / 256      ║
╚══════════════════════════════════════════════════════════════╝
"""

import os

# ══════════════════════════════════════════════════════════════════════════════
#  TABLE S-BOX  (SubBytes — substitution non-linéaire)
# ══════════════════════════════════════════════════════════════════════════════
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

# ══════════════════════════════════════════════════════════════════════════════
#  TABLE S-BOX INVERSE  (InvSubBytes — déchiffrement)
# ══════════════════════════════════════════════════════════════════════════════
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

# ══════════════════════════════════════════════════════════════════════════════
#  CONSTANTES DE TOUR  (RCON — Key Schedule)
# ══════════════════════════════════════════════════════════════════════════════
RCON = [
    0x00,                          # index 0 non utilisé
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1B, 0x36,
]

# ══════════════════════════════════════════════════════════════════════════════
#  TABLES DE MULTIPLICATION DANS GF(2⁸)  (MixColumns / InvMixColumns)
# ══════════════════════════════════════════════════════════════════════════════

def _gmul(a: int, b: int) -> int:
    """Multiplication de a par b dans GF(2⁸) modulo 0x11B."""
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

# Précalcul des 6 tables nécessaires à AES
MUL2  = [_gmul(i,  2) for i in range(256)]
MUL3  = [_gmul(i,  3) for i in range(256)]
MUL9  = [_gmul(i,  9) for i in range(256)]
MUL11 = [_gmul(i, 11) for i in range(256)]
MUL13 = [_gmul(i, 13) for i in range(256)]
MUL14 = [_gmul(i, 14) for i in range(256)]


# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS ÉTAT
# ══════════════════════════════════════════════════════════════════════════════

def _bytes_to_state(block: bytes) -> list:
    return list(block)

def _state_to_bytes(state: list) -> bytes:
    return bytes(state)


# ══════════════════════════════════════════════════════════════════════════════
#  LES 4 TRANSFORMATIONS AES
# ══════════════════════════════════════════════════════════════════════════════

def _add_round_key(state: list, rk: list) -> list:
    return [state[i] ^ rk[i] for i in range(16)]

def _sub_bytes(state: list) -> list:
    return [SBOX[b] for b in state]

def _inv_sub_bytes(state: list) -> list:
    return [INV_SBOX[b] for b in state]

def _shift_rows(state: list) -> list:
    s = state[:]
    s[1],  s[5],  s[9],  s[13] = state[5],  state[9],  state[13], state[1]
    s[2],  s[6],  s[10], s[14] = state[10], state[14], state[2],  state[6]
    s[3],  s[7],  s[11], s[15] = state[15], state[3],  state[7],  state[11]
    return s

def _inv_shift_rows(state: list) -> list:
    s = state[:]
    s[1],  s[5],  s[9],  s[13] = state[13], state[1],  state[5],  state[9]
    s[2],  s[6],  s[10], s[14] = state[10], state[14], state[2],  state[6]
    s[3],  s[7],  s[11], s[15] = state[7],  state[11], state[15], state[3]
    return s

def _mix_columns(state: list) -> list:
    s = state[:]
    for c in range(4):
        i = c * 4
        a = state[i : i + 4]
        s[i]   = MUL2[a[0]] ^ MUL3[a[1]] ^ a[2]        ^ a[3]
        s[i+1] = a[0]        ^ MUL2[a[1]] ^ MUL3[a[2]]  ^ a[3]
        s[i+2] = a[0]        ^ a[1]        ^ MUL2[a[2]]  ^ MUL3[a[3]]
        s[i+3] = MUL3[a[0]]  ^ a[1]        ^ a[2]        ^ MUL2[a[3]]
    return s

def _inv_mix_columns(state: list) -> list:
    s = state[:]
    for c in range(4):
        i = c * 4
        a = state[i : i + 4]
        s[i]   = MUL14[a[0]] ^ MUL11[a[1]] ^ MUL13[a[2]] ^ MUL9[a[3]]
        s[i+1] = MUL9[a[0]]  ^ MUL14[a[1]] ^ MUL11[a[2]] ^ MUL13[a[3]]
        s[i+2] = MUL13[a[0]] ^ MUL9[a[1]]  ^ MUL14[a[2]] ^ MUL11[a[3]]
        s[i+3] = MUL11[a[0]] ^ MUL13[a[1]] ^ MUL9[a[2]]  ^ MUL14[a[3]]
    return s


# ══════════════════════════════════════════════════════════════════════════════
#  EXPANSION DE CLÉ  (Key Schedule)
# ══════════════════════════════════════════════════════════════════════════════

def _key_expansion(key: bytes) -> list:
    """Génère les (Nr+1) sous-clés de 16 octets. Supporte AES-128/192/256."""
    n = len(key)
    if n == 16:   Nk, Nr = 4, 10
    elif n == 24: Nk, Nr = 6, 12
    elif n == 32: Nk, Nr = 8, 14
    else: raise ValueError("Clé invalide : 16, 24 ou 32 octets requis.")

    W = [list(key[4*i : 4*i+4]) for i in range(Nk)]
    total = 4 * (Nr + 1)
    i = Nk

    while len(W) < total:
        temp = W[i - 1][:]
        if i % Nk == 0:
            temp = [
                SBOX[temp[1]] ^ RCON[i // Nk],
                SBOX[temp[2]],
                SBOX[temp[3]],
                SBOX[temp[0]],
            ]
        elif Nk > 6 and (i % Nk) == 4:
            temp = [SBOX[b] for b in temp]
        W.append([W[i - Nk][j] ^ temp[j] for j in range(4)])
        i += 1

    round_keys = []
    for r in range(Nr + 1):
        rk = []
        for c in range(4):
            rk.extend(W[r * 4 + c])
        round_keys.append(rk)
    return round_keys


# ══════════════════════════════════════════════════════════════════════════════
#  CHIFFREMENT / DÉCHIFFREMENT D'UN BLOC (16 octets)
# ══════════════════════════════════════════════════════════════════════════════

def _encrypt_block(block: bytes, round_keys: list) -> bytes:
    Nr    = len(round_keys) - 1
    state = _bytes_to_state(block)
    state = _add_round_key(state, round_keys[0])
    for r in range(1, Nr):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[r])
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[Nr])
    return _state_to_bytes(state)


def _decrypt_block(block: bytes, round_keys: list) -> bytes:
    Nr    = len(round_keys) - 1
    state = _bytes_to_state(block)
    state = _add_round_key(state, round_keys[Nr])
    for r in range(Nr - 1, 0, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, round_keys[r])
        state = _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, round_keys[0])
    return _state_to_bytes(state)


# ══════════════════════════════════════════════════════════════════════════════
#  PADDING PKCS#7
# ══════════════════════════════════════════════════════════════════════════════

def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Données vides.")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 16:
        raise ValueError("Rembourrage PKCS#7 invalide.")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Rembourrage PKCS#7 corrompu — clé ou données incorrectes.")
    return data[:-pad_len]


# ══════════════════════════════════════════════════════════════════════════════
#  CLASSE AES  (mode CBC avec IV aléatoire préfixé)
# ══════════════════════════════════════════════════════════════════════════════

class AES:
    """
    AES-CBC avec IV aléatoire (16 octets) préfixé au chiffré.

        key   : bytes de 16 (AES-128), 24 (AES-192) ou 32 (AES-256) octets.
        encrypt(texte) -> bytes     IV || chiffré
        decrypt(bytes) -> str       texte clair UTF-8
    """

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("La clé doit faire 16, 24 ou 32 octets.")
        self._round_keys = _key_expansion(key)

    def encrypt(self, plaintext) -> bytes:
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        iv      = os.urandom(16)
        padded  = _pkcs7_pad(plaintext)
        chiffre = bytearray()
        prev    = iv
        for i in range(0, len(padded), 16):
            bloc = bytes(a ^ b for a, b in zip(padded[i:i+16], prev))
            enc  = _encrypt_block(bloc, self._round_keys)
            chiffre.extend(enc)
            prev = enc
        return iv + bytes(chiffre)

    def decrypt(self, ciphertext: bytes) -> str:
        if len(ciphertext) < 32 or (len(ciphertext) - 16) % 16 != 0:
            raise ValueError("Taille invalide. Données AES-CBC attendues (IV + corps).")
        iv    = ciphertext[:16]
        corps = ciphertext[16:]
        clair = bytearray()
        prev  = iv
        for i in range(0, len(corps), 16):
            bloc = corps[i:i+16]
            dec  = _decrypt_block(bloc, self._round_keys)
            clair.extend(a ^ b for a, b in zip(dec, prev))
            prev = bloc
        return _pkcs7_unpad(bytes(clair)).decode("utf-8")


# ══════════════════════════════════════════════════════════════════════════════
#  UTILITAIRES D'AFFICHAGE
# ══════════════════════════════════════════════════════════════════════════════

SEP = "─" * 62

def _banniere():
    print()
    print("╔════════════════════════════════════════════════════════════╗")
    print("║         AES — Chiffreur / Déchiffreur Python pur          ║")
    print("║         Mode CBC · PKCS#7 · AES-128 / 192 / 256           ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print()

def _menu():
    print(SEP)
    print("  MENU PRINCIPAL")
    print(SEP)
    print("  [1]  Chiffrer un texte clair")
    print("  [2]  Déchiffrer un texte chiffré (hex)")
    print("  [3]  Quitter")
    print(SEP)

def _saisir_cle() -> bytes:
    """Demande la variante AES et la clé, puis l'ajuste à la bonne longueur."""
    print()
    print("  Choisissez la variante AES :")
    print("    [1]  AES-128  (clé de 16 octets)")
    print("    [2]  AES-192  (clé de 24 octets)")
    print("    [3]  AES-256  (clé de 32 octets)")

    taille = 16
    variant = "AES-128"
    while True:
        c = input("  Votre choix [1/2/3] : ").strip()
        if c == "1":  taille = 16; variant = "AES-128"; break
        elif c == "2": taille = 24; variant = "AES-192"; break
        elif c == "3": taille = 32; variant = "AES-256"; break
        else: print("  ✗  Entrez 1, 2 ou 3.")

    print(f"\n  Variante : {variant}  ({taille} octets)")
    print("  (La clé sera complétée avec des zéros si trop courte, tronquée si trop longue.)")

    cle_str   = input("  Entrez la clé : ")
    cle_bytes = cle_str.encode("utf-8")
    cle_bytes = (cle_bytes + b"\x00" * taille)[:taille]   # ajustement

    print(f"  Clé utilisée (hex) : {cle_bytes.hex()}")
    return cle_bytes


# ══════════════════════════════════════════════════════════════════════════════
#  ACTIONS CHIFFREMENT / DÉCHIFFREMENT
# ══════════════════════════════════════════════════════════════════════════════

def _chiffrement():
    print()
    print("  ┌─ CHIFFREMENT " + "─" * 47)

    cle = _saisir_cle()

    print()
    texte = input("  Texte clair à chiffrer : ")
    if not texte:
        print("  ✗  Texte vide. Opération annulée.")
        return

    try:
        aes     = AES(cle)
        chiffre = aes.encrypt(texte)
        hex_out = chiffre.hex()

        print()
        print("  ┌─ RÉSULTAT " + "─" * 50)
        print(f"  │  Texte original   : {texte}")
        print(f"  │  Taille (octets)  : {len(chiffre)}")
        print(f"  │")
        print(f"  │  Chiffré (hex) :")
        for i in range(0, len(hex_out), 64):
            print(f"  │    {hex_out[i:i+64]}")
        print("  └" + "─" * 61)
        print()
        print("  ✔  Conservez le texte chiffré (hex) et votre clé pour déchiffrer.")

    except Exception as e:
        print(f"\n  ✗  Erreur : {e}")


def _dechiffrement():
    print()
    print("  ┌─ DÉCHIFFREMENT " + "─" * 45)

    cle = _saisir_cle()

    print()
    hex_in    = input("  Texte chiffré (hexadécimal) : ").strip()
    hex_clean = hex_in.replace(" ", "").replace("-", "")

    if not hex_clean:
        print("  ✗  Aucune donnée saisie. Opération annulée.")
        return

    try:
        donnees = bytes.fromhex(hex_clean)
    except ValueError:
        print("  ✗  Format hexadécimal invalide.")
        return

    try:
        aes   = AES(cle)
        clair = aes.decrypt(donnees)

        print()
        print("  ┌─ RÉSULTAT " + "─" * 50)
        print(f"  │  Texte déchiffré : {clair}")
        print("  └" + "─" * 61)

    except (ValueError, UnicodeDecodeError) as e:
        print(f"\n  ✗  Échec du déchiffrement : {e}")
        print("     Vérifiez que la clé et les données sont correctes.")


# ══════════════════════════════════════════════════════════════════════════════
#  FONCTION PRINCIPALE  — boucle while True
# ══════════════════════════════════════════════════════════════════════════════

def main():
    _banniere()

    while True:
        _menu()
        choix = input("  Votre choix : ").strip()

        if choix == "1":
            _chiffrement()

        elif choix == "2":
            _dechiffrement()

        elif choix == "3":
            print()
            print("  Au revoir !")
            print()
            break

        else:
            print("\n  ✗  Option invalide. Entrez 1, 2 ou 3.\n")
            continue

        input("\n  [Appuyez sur Entrée pour revenir au menu]")
        print()


if __name__ == "__main__":
    main()
