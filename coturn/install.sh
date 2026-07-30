#!/bin/bash
# ── Installation coturn sur le VPS chaltet.com ───────────────────────────────
# À exécuter en root sur le serveur après git pull

set -e

TURN_PASSWORD="CHANGE_MOI"   # ← remplace par un vrai mot de passe
DOMAIN="turn.chaltet.com"
EMAIL="ton@email.com"         # ← remplace par ton email pour certbot

echo "==> Installation coturn..."
apt update && apt install -y coturn certbot

echo "==> Activation de coturn au démarrage..."
echo 'TURNSERVER_ENABLED=1' > /etc/default/coturn

echo "==> Certificat SSL pour $DOMAIN..."
# Arrêter nginx temporairement pour libérer le port 80
systemctl stop nginx
certbot certonly --standalone -d $DOMAIN --non-interactive --agree-tos -m $EMAIL
systemctl start nginx

echo "==> Copie de la config coturn..."
mkdir -p /var/log/coturn
cp coturn/turnserver.conf /etc/turnserver.conf
# Injecter le mot de passe dans la config
sed -i "s/TURN_PASSWORD_ICI/$TURN_PASSWORD/" /etc/turnserver.conf

echo "==> Ouverture des ports firewall..."
ufw allow 3478/tcp
ufw allow 3478/udp
ufw allow 5349/tcp
ufw allow 5349/udp
ufw allow 49152:65535/udp

echo "==> Démarrage coturn..."
systemctl enable coturn
systemctl restart coturn
systemctl status coturn --no-pager

echo ""
echo "==> Mise à jour du .env..."
echo "TURN_URL=$DOMAIN" >> /var/www/chaltet/.env
echo "TURN_USERNAME=chaltet" >> /var/www/chaltet/.env
echo "TURN_CREDENTIAL=$TURN_PASSWORD" >> /var/www/chaltet/.env

echo ""
echo "==> Suppression des anciennes creds Twilio du .env..."
sed -i '/TWILIO_ACCOUNT_SID/d' /var/www/chaltet/.env
sed -i '/TWILIO_AUTH_TOKEN/d' /var/www/chaltet/.env

echo ""
echo "==> Redémarrage de l'app..."
cd /var/www/chaltet && pm2 restart chaltet

echo ""
echo "✅ Done! coturn tourne sur $DOMAIN:3478 et $DOMAIN:5349"
