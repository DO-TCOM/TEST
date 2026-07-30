# CONTEXT — Projet Chaltet

## Règles de travail
- Ne jamais coder sans accord de OG
- Ne jamais prendre de décision seul
- Toujours suggérer avant d'agir
- Valider chaque modification avec OG avant de push
- Demander le token uniquement au moment du push
- Réponses courtes et simples

## Serveur Hostinger
- SSH : root@srv1740016
- Dossier projet : /var/www/chaltet
- Token GitHub : /root/.gh_token

## Stack technique
- Node.js : port 3000
- Nginx : port 80/443
- Redis : port 6379 (local)
- COTURN : port 3478 (WebRTC)
- Webhook deploy : port 9000

## PM2
- App : "chaltet"
- Commande reload : pm2 reload chaltet

## Workflow deploy
1. OG demande une modif ici
2. Je code et prépare le push
3. OG me donne le token (cat /root/.gh_token sur le serveur)
4. Je push GitHub
5. Webhook → deploy.sh → pm2 reload (sans coupure)

## Deploy script
- Fichier : /var/www/chaltet/deploy.sh
- Commande manuelle : bash /var/www/chaltet/deploy.sh

## GitHub
- Repo : https://github.com/DO-TCOM/chaltet
- Branche : master
- Webhook secret : voir /var/www/webhook.js sur le serveur

## Architecture fichiers importants
- server.js : serveur principal Node.js
- public/client.js : logique client
- public/landing.html : page d'accueil
- public/room.html : page de room
- config.json : configuration whitelist/redirect
- .env : variables d'environnement

## Ports firewall Hostinger ouverts
- 22 (SSH), 80 (HTTP), 443 (HTTPS), 3478 TCP+UDP (COTURN), 9000 (Webhook)
