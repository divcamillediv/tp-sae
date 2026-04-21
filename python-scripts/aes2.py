# =====================================================================
# IMPLÉMENTATION AES-128 (Advanced Encryption Standard) - PURE PYTHON
# =====================================================================

# --- TABLES CONSTANTES AES ---
SBOX = [
    0x63, 0x7c, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca,
    0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
    0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04,
    0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09,
    0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53,
    0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0,
    0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51,
    0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd,
    0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60,
    0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0,
    0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7,
    0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba,
    0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
    0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
    0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c,
    0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16, 0xca
]

INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

# --- MATHÉMATIQUES CORPS FINIS ---
def xtime(a):
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def gf_mult(a, b):
    res = 0
    while b:
        if b & 1: res ^= a
        a = xtime(a)
        b >>= 1
    return res

# --- GESTION DE LA MATRICE AES ---
def bytes_to_matrix(text):
    return [[text[r + 4 * c] for c in range(4)] for r in range(4)]

def matrix_to_bytes(matrix):
    return [matrix[r][c] for c in range(4) for r in range(4)]

def add_round_key(state, round_key):
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key[r][c]

def sub_bytes(state, is_inv=False):
    box = INV_SBOX if is_inv else SBOX
    for r in range(4):
        for c in range(4):
            state[r][c] = box[state[r][c]]

def shift_rows(state, is_inv=False):
    if not is_inv:
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]
    else:
        state[1] = state[1][-1:] + state[1][:-1]
        state[2] = state[2][-2:] + state[2][:-2]
        state[3] = state[3][-3:] + state[3][:-3]

def mix_columns(state, is_inv=False):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        if not is_inv:
            state[0][c] = gf_mult(0x02, col[0]) ^ gf_mult(0x03, col[1]) ^ col[2] ^ col[3]
            state[1][c] = col[0] ^ gf_mult(0x02, col[1]) ^ gf_mult(0x03, col[2]) ^ col[3]
            state[2][c] = col[0] ^ col[1] ^ gf_mult(0x02, col[2]) ^ gf_mult(0x03, col[3])
            state[3][c] = gf_mult(0x03, col[0]) ^ col[1] ^ col[2] ^ gf_mult(0x02, col[3])
        else:
            state[0][c] = gf_mult(0x0e, col[0]) ^ gf_mult(0x0b, col[1]) ^ gf_mult(0x0d, col[2]) ^ gf_mult(0x09, col[3])
            state[1][c] = gf_mult(0x09, col[0]) ^ gf_mult(0x0e, col[1]) ^ gf_mult(0x0b, col[2]) ^ gf_mult(0x0d, col[3])
            state[2][c] = gf_mult(0x0d, col[0]) ^ gf_mult(0x09, col[1]) ^ gf_mult(0x0e, col[2]) ^ gf_mult(0x0b, col[3])
            state[3][c] = gf_mult(0x0b, col[0]) ^ gf_mult(0x0d, col[1]) ^ gf_mult(0x09, col[2]) ^ gf_mult(0x0e, col[3])

# --- GÉNÉRATION DES CLÉS (Key Expansion) ---
def expand_key(key):
    key_words = [[key[4*c + r] for r in range(4)] for c in range(4)]
    
    for i in range(4, 4 * 11):
        temp = list(key_words[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[i // 4]
            
        new_word = [key_words[i - 4][r] ^ temp[r] for r in range(4)]
        key_words.append(new_word)
        
    round_keys = []
    for i in range(11):
        rk_matrix = [[key_words[4*i + c][r] for c in range(4)] for r in range(4)]
        round_keys.append(rk_matrix)
    return round_keys

# --- TRAITEMENT D'UN SEUL BLOC ---
def aes_encrypt_block(plaintext_block, round_keys):
    state = bytes_to_matrix(plaintext_block)
    add_round_key(state, round_keys[0])
    
    for round_num in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[round_num])
        
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10])
    return matrix_to_bytes(state)

def aes_decrypt_block(ciphertext_block, round_keys):
    state = bytes_to_matrix(ciphertext_block)
    
    add_round_key(state, round_keys[10])
    shift_rows(state, is_inv=True)
    sub_bytes(state, is_inv=True)
    
    for round_num in range(9, 0, -1):
        add_round_key(state, round_keys[round_num])
        mix_columns(state, is_inv=True)
        shift_rows(state, is_inv=True)
        sub_bytes(state, is_inv=True)
        
    add_round_key(state, round_keys[0])
    return matrix_to_bytes(state)

# --- PADDING ET DÉCOUPAGE ---
def pad(data_bytes):
    """Ajoute le padding PKCS#7 pour avoir un multiple de 16 octets."""
    pad_len = 16 - (len(data_bytes) % 16)
    return data_bytes + bytes([pad_len] * pad_len)

def unpad(data_bytes):
    """Retire le padding PKCS#7."""
    pad_len = data_bytes[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Erreur de Padding: Clé incorrecte ou données corrompues.")
    return data_bytes[:-pad_len]

# --- FONCTIONS GLOBALES TEXTE COMPLET ---
def encrypt_aes(plaintext, key_hex):
    key_bytes = list(bytes.fromhex(key_hex))
    round_keys = expand_key(key_bytes)
    
    pt_bytes = plaintext.encode('utf-8')
    padded_pt = pad(pt_bytes)
    
    ciphertext = []
    for i in range(0, len(padded_pt), 16):
        block = list(padded_pt[i:i+16])
        enc_block = aes_encrypt_block(block, round_keys)
        ciphertext.extend(enc_block)
        
    return bytes(ciphertext).hex().upper()

def decrypt_aes(ciphertext_hex, key_hex):
    key_bytes = list(bytes.fromhex(key_hex))
    round_keys = expand_key(key_bytes)
    
    ct_bytes = list(bytes.fromhex(ciphertext_hex))
    pt_bytes = []
    
    for i in range(0, len(ct_bytes), 16):
        block = ct_bytes[i:i+16]
        dec_block = aes_decrypt_block(block, round_keys)
        pt_bytes.extend(dec_block)
        
    unpadded_pt = unpad(bytes(pt_bytes))
    return unpadded_pt.decode('utf-8')

# =====================================================================
# MENU INTERACTIF
# =====================================================================

def verifier_cle(cle):
    if len(cle) != 32:
        return False
    try:
        bytes.fromhex(cle)
        return True
    except ValueError:
        return False

def executer_tests_auto(nb_tests=10):
    print(f"\n--- LANCEMENT DE {nb_tests} TESTS DE SYMÉTRIE ---")
    succes = 0
    
    # Test avec des messages de longueurs différentes
    messages_test = [
        "Test court", 
        "Ceci est un message de pile 32 chars.",
        "Un message beaucoup plus long pour tester le chaînage des blocs et le padding PKCS7.",
        "1234567890123456" # Exactement un bloc
    ]
    
    cle_fixe = "2B7E151628AED2A6ABF7158809CF4F3C" # Clé NIST standard
    
    for i, texte in enumerate(messages_test):
        try:
            print(f"Test {i+1} : '{texte[:20]}...' ", end="")
            
            # 1. Chiffrement
            code_hex = encrypt_aes(texte, cle_fixe)
            
            # 2. Déchiffrement
            retour_clair = decrypt_aes(code_hex, cle_fixe)
            
            if retour_clair == texte:
                print("✅ RÉUSSI")
                succes += 1
            else:
                print("❌ ÉCHEC (Texte corrompu)")
                print(f"   Attendu : {texte}")
                print(f"   Obtenu   : {retour_clair}")
        except Exception as e:
            print(f"❌ ERREUR CRITIQUE : {e}")

    print(f"\nRésultat final : {succes}/{len(messages_test)} tests réussis.")
    if succes < len(messages_test):
        print("CONSEIL : Vérifiez l'ordre de la boucle dans 'decrypt_aes'.")
        print("Elle doit faire : InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns.")

# Pour lancer les tests, ajoutez cette ligne :
'''
def main():
    while True:
        print("\n" + "="*55)
        print(" OUTIL DE CHIFFREMENT AES-128 (Advanced Encryption Standard)")
        print("="*55)
        print("1. Chiffrer un texte clair")
        print("2. Déchiffrer un texte codé")
        print("3. Quitter")
        
        choix = input("\nVotre choix (1, 2 ou 3) : ").strip()
        
        if choix == '1':
            print("\n--- CHIFFREMENT ---")
            texte = input("Entrez le texte à chiffrer : ")
            cle = input("Entrez une clé secrète (32 caractères Hexadécimaux) : ").strip().upper()
            
            if not verifier_cle(cle):
                print("[Erreur] La clé doit comporter exactement 32 caractères hexadécimaux (16 octets).")
                continue
                
            try:
                resultat = encrypt_aes(texte, cle)
                print(f"\n> Texte chiffré (Hex) : {resultat}")
            except Exception as e:
                print(f"[Erreur] {e}")
            
        elif choix == '2':
            print("\n--- DÉCHIFFREMENT ---")
            code_hex = input("Entrez le code chiffré (en Hexadécimal) : ").strip().upper()
            cle = input("Entrez la clé secrète (32 caractères Hexadécimaux) : ").strip().upper()
            
            if not verifier_cle(cle):
                print("[Erreur] La clé doit comporter exactement 32 caractères hexadécimaux.")
                continue
            
            if len(code_hex) % 32 != 0:
                print("[Erreur] Le code chiffré n'est pas valide (la longueur n'est pas un multiple de 32 caractères hexadécimaux).")
                continue
                
            try:
                resultat = decrypt_aes(code_hex, cle)
                print(f"\n> Texte déchiffré (Clair) : {resultat}")
            except Exception as e:
                print(f"\n[Erreur de Déchiffrement] Clé incorrecte, ou données corrompues. ({e})")
            
        elif choix == '3':
            print("Fermeture du programme. À bientôt !")
            break
            
        else:
            print("Choix invalide. Veuillez entrer 1, 2 ou 3.")
'''
if __name__ == "__main__":
    # main()
    executer_tests_auto()
