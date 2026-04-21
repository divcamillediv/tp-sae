#!/bin/bash

# ==========================================
# Paramètres du réseau (à adapter si besoin)
# ==========================================
DNS_SERVER="192.168.10.2"
DOMAIN="domain.local"

# Listes des machines et IPs de votre infrastructure
HOSTS=("r1" "r2" "r2-data" "dns" "web01")
IPS=("192.168.10.1" "192.168.10.254" "192.168.20.1" "192.168.10.2" "192.168.10.11")

# Codes couleurs pour un affichage plus lisible
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # Pas de couleur

# Vérification de la présence de la commande dig
if ! command -v dig &> /dev/null; then
    echo -e "${RED}Erreur : l'outil 'dig' n'est pas installé.${NC}"
    echo "Veuillez l'installer avec : sudo apt install dnsutils"
    exit 1
fi

echo "================================================="
echo "  Début des tests DNS sur le serveur $DNS_SERVER "
echo "================================================="

# ---------------------------------------------------------
# 1. Test de la zone de recherche directe (A / Nom vers IP)
# ---------------------------------------------------------
echo -e "\n>>> 1. TEST DE RECHERCHE DIRECTE (Nom -> IP)"
echo "--------------------------------------------"

for host in "${HOSTS[@]}"; do
    fqdn="${host}.${DOMAIN}"
    # Interrogation du serveur DNS (l'option +short ne retourne que l'IP)
    result=$(dig @"${DNS_SERVER}" "${fqdn}" +short)
    
    if [ -n "$result" ]; then
        # Affichage du résultat sur une seule ligne (au cas où il y a plusieurs IPs)
        echo -e "[ ${GREEN}OK${NC} ] ${fqdn}  ->  ${result//$'\n'/ /}"
    else
        echo -e "[ ${RED}ÉCHEC${NC} ] Impossible de résoudre : ${fqdn}"
    fi
done

# ---------------------------------------------------------
# 2. Test de la zone de recherche inversée (PTR / IP vers Nom)
# ---------------------------------------------------------
echo -e "\n>>> 2. TEST DE RECHERCHE INVERSÉE (IP -> Nom)"
echo "---------------------------------------------"

for ip in "${IPS[@]}"; do
    # L'option -x permet de faire la requête PTR automatique
    result=$(dig @"${DNS_SERVER}" -x "${ip}" +short)
    
    if [ -n "$result" ]; then
        # On supprime le point final "." que 'dig' ajoute toujours à la fin du FQDN
        clean_result=${result%.}
        echo -e "[ ${GREEN}OK${NC} ] ${ip}  ->  ${clean_result}"
    else
        echo -e "[ ${RED}ÉCHEC${NC} ] Pas d'enregistrement PTR pour : ${ip}"
    fi
done

echo -e "\n================================================="
echo "                   Tests terminés !              "
echo "================================================="