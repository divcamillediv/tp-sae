#!/bin/bash

# Arrêter le script en cas d'erreur
set -e

# Vérification des privilèges root
if [ "$EUID" -ne 0 ]; then
  echo "Veuillez exécuter ce script en tant que root ou avec sudo."
  exit 1
fi

echo "==========================================="
echo "   Installation et Configuration de Bind9  "
echo "==========================================="

echo ">> 1. Mise à jour et installation des paquets (bind9, dnsutils)..."
apt-get update -y
apt-get install -y bind9 bind9utils bind9-doc dnsutils

echo ">> 2. Configuration des zones dans /etc/bind/named.conf.local..."
# On ajoute les zones uniquement si elles n'existent pas déjà
if ! grep -q "domain.local" /etc/bind/named.conf.local; then
cat << 'EOF' >> /etc/bind/named.conf.local

zone "domain.local" {
    type master;
    file "/etc/bind/db.domain.local";
};

zone "168.192.in-addr.arpa" {
    type master;
    file "/etc/bind/db.192.168";
};
EOF
fi

echo ">> 3. Création du fichier de zone de recherche directe (domain.local)..."
cat << 'EOF' > /etc/bind/db.domain.local
$TTL    604800
@       IN      SOA     dns.domain.local. admin.domain.local. (
                              2         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      dns.domain.local.
dns     IN      A       192.168.10.2
r1      IN      A       192.168.10.1
r2      IN      A       192.168.10.254
r2-data IN      A       192.168.20.1
web01   IN      A       192.168.10.11
EOF

echo ">> 4. Création du fichier de zone de recherche inversée (192.168.0.0/16)..."
cat << 'EOF' > /etc/bind/db.192.168
$TTL    604800
@       IN      SOA     dns.domain.local. admin.domain.local. (
                              2         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      dns.domain.local.
2.10    IN      PTR     dns.domain.local.
1.10    IN      PTR     r1.domain.local.
254.10  IN      PTR     r2.domain.local.
1.20    IN      PTR     r2-data.domain.local.
11.10   IN      PTR     web01.domain.local.
EOF

echo ">> 5. Application des permissions standards de Bind9..."
chown root:bind /etc/bind/db.domain.local /etc/bind/db.192.168
chmod 644 /etc/bind/db.domain.local /etc/bind/db.192.168

echo ">> 6. Vérification de la configuration et redémarrage du service..."
named-checkconf
named-checkzone domain.local /etc/bind/db.domain.local
named-checkzone 168.192.in-addr.arpa /etc/bind/db.192.168

systemctl restart bind9
systemctl enable bind9

echo "==========================================="
echo " Installation terminée avec succès !"
echo "==========================================="