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
executer_tests_auto()