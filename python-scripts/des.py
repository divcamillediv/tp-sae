# =====================================================================
# IMPLÉMENTATION DES (Data Encryption Standard) - PURE PYTHON
# =====================================================================

# --- TABLES DE CONSTANTES DES ---
PI = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

PI_INV = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

S_BOXES = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7], [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8], [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0], [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10], [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5], [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15], [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8], [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1], [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7], [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15], [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9], [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4], [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9], [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6], [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14], [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11], [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8], [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6], [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1], [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6], [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2], [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7], [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2], [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8], [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
       59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39,
       31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
       29, 21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
       26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
       51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# --- FONCTIONS UTILITAIRES ---
def permute(block, table):
    return "".join(block[i - 1] for i in table)

def xor(s1, s2):
    return "".join('0' if a == b else '1' for a, b in zip(s1, s2))

def hex_to_bin(h, length=64):
    return bin(int(h, 16))[2:].zfill(length)

def bin_to_hex(b, length=16):
    return hex(int(b, 2))[2:].zfill(length).upper()

# --- FORMATAGE ET PADDING ---
def text_to_blocks(text):
    """Convertit un texte en blocs binaires de 64 bits (avec padding PKCS#7)."""
    # Padding pour que la longueur soit un multiple de 8 octets
    pad_len = 8 - (len(text.encode('utf-8')) % 8)
    padded_text = text.encode('utf-8') + bytes([pad_len] * pad_len)
    
    blocks = []
    for i in range(0, len(padded_text), 8):
        block_bytes = padded_text[i:i+8]
        block_bin = "".join(bin(b)[2:].zfill(8) for b in block_bytes)
        blocks.append(block_bin)
    return blocks

def blocks_to_text(blocks):
    """Convertit des blocs binaires de 64 bits en texte (en retirant le padding)."""
    full_bin = "".join(blocks)
    bytes_list = [int(full_bin[i:i+8], 2) for i in range(0, len(full_bin), 8)]
    
    # Retirer le padding PKCS#7
    pad_len = bytes_list[-1]
    unpadded_bytes = bytes(bytes_list[:-pad_len])
    
    try:
        return unpadded_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return "[Erreur de décodage : La clé est probablement incorrecte]"

# --- GÉNÉRATION DES CLÉS ---
def generate_subkeys(key_hex):
    key_bin = hex_to_bin(key_hex, 64)
    key_pc1 = permute(key_bin, PC1)
    L, R = key_pc1[:28], key_pc1[28:]
    subkeys = []
    for shift in SHIFTS:
        L = L[shift:] + L[:shift]
        R = R[shift:] + R[:shift]
        subkeys.append(permute(L + R, PC2))
    return subkeys

# --- FONCTION DE RONDE (FEISTEL) ---
def f_function(right, subkey):
    expanded = permute(right, E)
    xored = xor(expanded, subkey)
    res = ""
    for i in range(8):
        chunk = xored[i*6:(i+1)*6]
        row = int(chunk[0] + chunk[5], 2)
        col = int(chunk[1:5], 2)
        res += bin(S_BOXES[i][row][col])[2:].zfill(4)
    return permute(res, P)

# --- MOTEUR DE BLOC DES ---
def process_block(block_bin, subkeys):
    """Traite un bloc binaire de 64 bits à travers les 16 rondes."""
    block = permute(block_bin, PI)
    L, R = block[:32], block[32:]
    
    for i in range(16):
        old_R = R
        R = xor(L, f_function(R, subkeys[i]))
        L = old_R
        
    res_block = permute(R + L, PI_INV)
    return res_block

# --- FONCTIONS PRINCIPALES DE CHIFFREMENT/DÉCHIFFREMENT ---
def encrypt_des(plaintext, key_hex):
    subkeys = generate_subkeys(key_hex)
    blocks_bin = text_to_blocks(plaintext)
    cipher_blocks = []
    
    for block in blocks_bin:
        cipher_bin = process_block(block, subkeys) # Ordre normal des clés
        cipher_blocks.append(bin_to_hex(cipher_bin))
        
    return "".join(cipher_blocks)

def decrypt_des(ciphertext_hex, key_hex):
    subkeys = generate_subkeys(key_hex)[::-1] # Ordre inversé des clés pour déchiffrer
    
    # Découper le texte chiffré en blocs de 16 caractères hex (64 bits)
    blocks_hex = [ciphertext_hex[i:i+16] for i in range(0, len(ciphertext_hex), 16)]
    plain_blocks = []
    
    for block_h in blocks_hex:
        block_bin = hex_to_bin(block_h, 64)
        plain_bin = process_block(block_bin, subkeys)
        plain_blocks.append(plain_bin)
        
    return blocks_to_text(plain_blocks)

# =====================================================================
# MENU INTERACTIF
# =====================================================================

def verifier_cle(cle):
    """Vérifie si la clé est valide (16 caractères Hexadécimaux)."""
    if len(cle) != 16:
        return False
    try:
        int(cle, 16)
        return True
    except ValueError:
        return False

def main():
    while True:
        print("\n" + "="*50)
        print(" OUTIL DE CHIFFREMENT DES (Data Encryption Standard)")
        print("="*50)
        print("1. Chiffrer un texte clair")
        print("2. Déchiffrer un texte codé")
        print("3. Quitter")
        
        choix = input("\nVotre choix (1, 2 ou 3) : ").strip()
        
        if choix == '1':
            print("\n--- CHIFFREMENT ---")
            texte = input("Entrez le texte à chiffrer : ")
            cle = input("Entrez une clé secrète (16 caractères Hexadécimaux, ex: 0123456789ABCDEF) : ").strip().upper()
            
            if not verifier_cle(cle):
                print("[Erreur] La clé doit comporter exactement 16 caractères hexadécimaux (0-9, A-F).")
                continue
                
            resultat = encrypt_des(texte, cle)
            print(f"\n> Texte chiffré (Hex) : {resultat}")
            
        elif choix == '2':
            print("\n--- DÉCHIFFREMENT ---")
            code_hex = input("Entrez le code chiffré (en Hexadécimal) : ").strip().upper()
            cle = input("Entrez la clé secrète (16 caractères Hexadécimaux) : ").strip().upper()
            
            if not verifier_cle(cle):
                print("[Erreur] La clé doit comporter exactement 16 caractères hexadécimaux.")
                continue
            
            # Vérification basique du code chiffré (doit être un multiple de 16 caractères hex)
            if len(code_hex) % 16 != 0:
                print("[Erreur] Le code chiffré n'est pas valide (la longueur n'est pas un multiple de 16 caractères).")
                continue
                
            resultat = decrypt_des(code_hex, cle)
            print(f"\n> Texte déchiffré (Clair) : {resultat}")
            
        elif choix == '3':
            print("Fermeture du programme. À bientôt !")
            break
            
        else:
            print("Choix invalide. Veuillez entrer 1, 2 ou 3.")

if __name__ == "__main__":
    main()