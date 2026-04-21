import collections

def dechiffrer_par_frequence(texte_chiffré):
    # Fréquence théorique des lettres en français (de la plus fréquente à la moins fréquente)
    FREQ_FRANCAIS = "ESARINTULODP CMVFBGHJQXYZKW"
    
    # Nettoyer le texte pour ne garder que les lettres pour l'analyse
    lettres_seules = [c.upper() for c in texte_chiffré if c.isalpha()]
    compteur = collections.Counter(lettres_seules)
    
    # Trier les lettres du texte chiffré par occurrence décroissante
    lettres_triees = [item[0] for item in compteur.most_common()]
    
    # Créer la table de correspondance (Mapping)
    # On associe la lettre la plus fréquente du texte à 'E', etc.
    mapping = {}
    for i in range(len(lettres_triees)):
        if i < len(FREQ_FRANCAIS):
            mapping[lettres_triees[i]] = FREQ_FRANCAIS[i]
    
    # Reconstruire le texte
    resultat = ""
    for char in texte_chiffré:
        if char.upper() in mapping:
            # Conserver la casse originale
            lettre_claire = mapping[char.upper()]
            resultat += lettre_claire if char.isupper() else lettre_claire.lower()
        else:
            resultat += char
            
    return resultat

# Votre texte chiffré
cipher_text = """Dsyi isffxi xd 50 ntndu Jxiyi-Vlokiu. 
Usyux gn Mnygx xiu svvyqxx qno gxi osfnkdi... 
Usyux? Dsd! Yd tkggnmx qxyqgx c'kooxcyvukbgxi mnygski 
oxikiux xdvsox xu usyjsyoi n g'xdtnlkiixyo. Xu gn tkx d'xiu 
qni wnvkgx qsyo gxi mnodkisdi cx gxmksddnkoxi osfnkdi cxi vnfqi 
oxuondvlxi cx Bnbnsoyf, Npynokyf, Gnycndyf xu Qxukbsdyf"""

print(dechiffrer_pimport collections

def dechiffrer_par_frequence(texte_chiffré):
    # Fréquence théorique des lettres en français (de la plus fréquente à la moins fréquente)
    FREQ_FRANCAIS = "ESARINTULODP CMVFBGHJQXYZKW"
    
    # Nettoyer le texte pour ne garder que les lettres pour l'analyse
    lettres_seules = [c.upper() for c in texte_chiffré if c.isalpha()]
    compteur = collections.Counter(lettres_seules)
    
    # Trier les lettres du texte chiffré par occurrence décroissante
    lettres_triees = [item[0] for item in compteur.most_common()]
    
    # Créer la table de correspondance (Mapping)
    # On associe la lettre la plus fréquente du texte à 'E', etc.
    mapping = {}
    for i in range(len(lettres_triees)):
        if i < len(FREQ_FRANCAIS):
            mapping[lettres_triees[i]] = FREQ_FRANCAIS[i]
    
    # Reconstruire le texte
    resultat = ""
    for char in texte_chiffré:
        if char.upper() in mapping:
            # Conserver la casse originale
            lettre_claire = mapping[char.upper()]
            resultat += lettre_claire if char.isupper() else lettre_claire.lower()
        else:
            resultat += char
            
    return resultat

# Votre texte chiffré
cipher_text = """Dsyi isffxi xd 50 ntndu Jxiyi-Vlokiu. 
Usyux gn Mnygx xiu svvyqxx qno gxi osfnkdi... 
Usyux? Dsd! Yd tkggnmx qxyqgx c'kooxcyvukbgxi mnygski 
oxikiux xdvsox xu usyjsyoi n g'xdtnlkiixyo. Xu gn tkx d'xiu 
qni wnvkgx qsyo gxi mnodkisdi cx gxmksddnkoxi osfnkdi cxi vnfqi 
oxuondvlxi cx Bnbnsoyf, Npynokyf, Gnycndyf xu Qxukbsdyf"""

print(dechiffrer_par_frequence(cipher_text))ar_frequence(cipher_text))