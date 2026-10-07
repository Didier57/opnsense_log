# OPNsense Log Analyzer

Une application web auto-hébergée et Dockerisée pour **collecter, stocker, visualiser et
analyser en continu les journaux `filterlog` du pare-feu OPNsense** en temps réel.

Elle s'inspire de [Shayano/opnsense-log-viewer](https://github.com/Shayano/opnsense-log-viewer)
mais est conçue pour un fonctionnement permanent : collecte syslog continue, stockage
persistant, recherche historique, vue Temps réel et synchronisation optionnelle de la
configuration OPNsense via SSH.

> **Principe fondamental :** cette application ne dépend jamais de l'interface web OPNsense.
> OPNsense n'est utilisé que comme *source de journaux* et *source de configuration*.
> L'application possède son propre analyseur, sa base de données, son API, son frontend, son
> cache et sa configuration, et continue d'analyser les journaux même lorsque le SSH OPNsense
> est temporairement indisponible.

## Fonctionnalités

- **Réception syslog continue** en UDP et/ou TCP (`SYSLOG_PROTOCOL=udp|tcp|both`).
- **Analyseur modulaire** produisant des événements structurés à partir des lignes
  `filterlog` d'OPNsense : formats RFC3164, RFC5424, horodatage ISO personnalisé et
  `filterlog` brut. Gère IPv4/IPv6, TCP/UDP, ICMP/ICMPv6 et les lignes malformées.
- **Vue Temps réel** via WebSocket avec démarrer/pause/reprendre/vider, taille de tampon
  configurable et filtres rapides. Mettre en pause la vue **n'arrête jamais** la réception
  côté serveur.
- **Recherche historique** exécutée côté serveur (DuckDB) — des millions de lignes ne sont
  jamais chargées dans le navigateur. Plage date/heure, filtres rapides et filtres avancés
  (ET/OU, opérateurs, regex).
- **Tableau de bord et analyse** : cartes (événements/bloqués/autorisés/interfaces), séries
  temporelles, AUTORISÉ vs BLOQUÉ, trafic par interface, principales IP source/destination,
  principaux ports, principales règles, principaux protocoles, et une section d'analyse par
  dimension.
- **Correspondance interfaces et règles** récupérée depuis OPNsense via SSH, affichant par
  ex. `LAN (vtnet0)` au lieu du périphérique brut, avec **historique des changements de
  règles** conservé dans le temps.
- **Export** des résultats de recherche en CSV, JSON et Parquet.
- **Politique de rétention** (`LOG_RETENTION_DAYS`, `0` = illimitée) avec une tâche de
  nettoyage en arrière-plan.
- **Filtres enregistrés**, pagination, détails d'événement.
- **Surveillance et journalisation interne** avec une page Système → État
  (reçus / analysés / invalides / événements par seconde) et une page Système → Journaux.
- **Détection de sécurité et alertes** : un moteur en arrière-plan (indépendant de
  l'interface) détectant les scans de ports, les attaques par force brute et (en option) les
  pics de trafic. Les alertes sont listées dans **Sécurité → Alertes** et peuvent être
  envoyées par e-mail (SMTP). Les réglages se font depuis l'interface web
  (Sécurité → Détection, Paramètres → Notifications).
- **Blocage automatique** : ajout des IP publiques des alertes (force brute / scan de ports)
  dans un **alias pare-feu OPNsense de type « Host(s) »** via l'API REST, en mode manuel ou
  automatique, avec liste blanche et expiration (TTL).
- **Géolocalisation (pays)** : pays d'origine des IP publiques (base gratuite DB-IP Lite, ou
  MaxMind GeoLite2 si une clé est fournie), avec drapeaux et statistiques par pays.
- **Recherche de noms d'hôtes** : DNS inverse plus les noms locaux issus des baux DHCP du
  pare-feu (ISC / Kea / Dnsmasq) récupérés via SSH.
- **Import des journaux OPNsense** : lecture des fichiers de journaux du pare-feu par SSH
  pour combler les événements manquants (au démarrage et via un bouton), y compris les trous
  au milieu d'une journée.
- **Authentification** (locale, hachée avec Argon2) avec jetons JWT.
- **Dockerisée** : une seule image servant à la fois l'API et le frontend, avec un
  healthcheck.

## Architecture

Pipeline d'ingestion résistant aux pertes :

```
OPNsense ── syslog ──▶ Récepteur syslog ──▶ File de réception ──▶ Workers d'analyse ──▶ Insertion par lots ──▶ DuckDB
                            │                                          │
                            └──────────────▶ WebSocket Temps réel ◀────┘
```

```
backend/
  app/
    api/         routeurs FastAPI (health, auth, logs, search, statistics, filters,
                 rules, interfaces, settings, system, export, live)
    parser/      analyseurs filterlog / RFC3164 / RFC5424 / personnalisé
    storage/     base DuckDB, dépôt, rétention
    syslog/      serveur syslog UDP/TCP avec file + workers par lots
    opnsense/    client SSH, chargeur config.xml, baux DHCP, synchronisation, stockage des réglages
    detection/   détecteurs scan de ports / force brute / pics, stockage des alertes
    notifications/ notifications e-mail SMTP
    websocket/   concentrateur Temps réel
    core/        journalisation, compteurs, sécurité
    main.py      application FastAPI + cycle de vie
  tests/         tests analyseur / recherche / ssh
  scripts/       hash_password.py
frontend/
  src/           interface React + Vite + TypeScript
Dockerfile       build multi-étapes (frontend + backend dans une seule image)
docker-compose.yml
```

Le stockage utilise **DuckDB** (colonnes, adapté à l'analytique, mono-fichier, sans serveur).

## Démarrage rapide

1. Copiez le fichier d'environnement (identifiants par défaut `admin` / `admin`) :

   ```bash
   cp .env.example .env
   docker compose up -d
   ```

   Définissez `AUTH_USERNAME` / `AUTH_PASSWORD` dans `.env` (ou `docker-compose.yml`) pour
   changer l'identifiant. Aucune étape de hachage n'est nécessaire. Pour un mot de passe
   haché, définissez plutôt `AUTH_PASSWORD_HASH` (générez-le avec
   `docker compose run --rm opnsense-log-analyzer python scripts/hash_password.py`) ; il est
   prioritaire sur `AUTH_PASSWORD` lorsqu'il est défini.

2. Ouvrez l'interface web sur <http://SERVER_IP:8080> et connectez-vous.

3. Configurez OPNsense pour envoyer les journaux vers cet hôte :

   **Système → Paramètres → Journalisation → Destinations distantes**
   ajoutez une destination `SERVER_IP:5140` (UDP par défaut), puis appliquez.

Les données sont stockées dans le volume Docker nommé `opnsense_logs` et **persistent donc
entre `docker compose down` / `up`**.

### Mise à jour

```bash
docker compose pull && docker compose up -d
```

## Configuration

Toute la configuration se fait via des variables d'environnement (voir `.env.example`) :

| Variable | Défaut | Description |
| --- | --- | --- |
| `WEB_PORT` | `8080` | port HTTP de l'interface web / de l'API |
| `SYSLOG_PORT` | `5140` | port d'écoute syslog |
| `SYSLOG_PROTOCOL` | `udp` | `udp`, `tcp` ou `both` |
| `DATA_DIR` | `/data` | répertoire de données (monter un volume ici) |
| `LOG_RETENTION_DAYS` | `30` | rétention en jours (`0` = illimitée) |
| `AUTH_ENABLED` | `true` | activer l'authentification locale |
| `AUTH_USERNAME` | `admin` | nom d'utilisateur |
| `AUTH_PASSWORD` | `admin` | mot de passe (en clair, configuration la plus simple) |
| `AUTH_PASSWORD_HASH` | – | hachage Argon2 ; prioritaire sur `AUTH_PASSWORD` |
| `SECRET_KEY` | – | secret de signature JWT |
| `DISPLAY_TIMEZONE` | `Europe/Luxembourg` | fuseau horaire utilisé pour l'affichage |
| `SYSLOG_TIMEZONE` | `DISPLAY_TIMEZONE` | fuseau dans lequel OPNsense émet les horodatages syslog |
| `LOG_LEVEL` | `INFO` | `INFO`/`WARNING`/`ERROR`/`DEBUG` |

La connexion SSH à OPNsense (hôte, port, nom d'utilisateur, type d'authentification,
mot de passe/chemin de clé, synchronisation activée et intervalle) se configure **depuis
l'interface web** sous **Paramètres → OPNsense**. Les valeurs sont stockées côté serveur
dans le volume de données et remplacent les valeurs par défaut, aucune variable
d'environnement n'est donc nécessaire. (Les déploiements avancés/sans interface peuvent
toujours définir les variables `OPNSENSE_*` comme valeurs de repli.)

> Les horodatages sont stockés en **UTC**. Les lignes syslog d'OPNsense ne portent aucun
> décalage de fuseau : elles sont donc interprétées dans `SYSLOG_TIMEZONE` (par défaut
> `DISPLAY_TIMEZONE`), converties en UTC, puis affichées dans le fuseau local du lecteur.

## Développement

Backend :

```bash
cd backend
python -m venv .venv && . .venv/Scripts/activate      # Windows
pip install -r requirements-dev.txt
pytest
uvicorn app.main:app --reload --port 8080
```

Frontend :

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173, proxy /api vers :8080
```

## Tests

```bash
cd backend && pytest
```

Couvre l'analyseur filterlog (la ligne d'exemple exacte d'OPNsense, IPv4 TCP/UDP, IPv6,
ICMP, champs manquants, lignes invalides), l'analyse RFC3164/RFC5424, la recherche dans le
dépôt (ET/OU/regex/plage de temps/IP/port/règle/interface) et le client SSH
(valide, mauvais mot de passe, clé invalide, injoignable).

## Sécurité

- Mots de passe hachés (Argon2), sessions JWT.
- Filtres SQL paramétrés/listés en liste blanche (protection contre l'injection SQL).
- Validation stricte des champs et opérateurs de filtre.
- Les clés SSH ne sont jamais écrites dans les journaux.
- Les requêtes coûteuses sont limitées et les gros exports sont diffusés en flux.

## Feuille de route

Déjà implémenté au-delà de la V1 :

- **Moteur de détection** — scans de ports, force brute et (en option) pics de trafic, avec
  une liste d'alertes et des notifications e-mail (SMTP).
- **Blocage automatique** — alimentation d'un alias pare-feu OPNsense via l'API REST.
- **Géolocalisation (pays)** — pays des IP publiques avec drapeaux et statistiques.
- **Recherche de noms d'hôtes** — DNS inverse et noms des baux DHCP/Dnsmasq.
- **Import des journaux OPNsense** — rattrapage des événements manquants par SSH.
- **Historique des changements de règles**.

Encore prévu :

- **V2** — statistiques avancées, alias, export Excel, webhooks, API complète documentée,
  multi-OPNsense, multi-utilisateur, LDAP/OIDC.
- **V3** — détection enrichie : détection d'anomalies, alertes IP / renseignement sur les
  menaces et corrélation d'événements.

## Licence

MIT
