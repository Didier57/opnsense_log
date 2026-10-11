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
  côté serveur. Le flux résiste aux rafales (événements regroupés) et se **reconnecte
  automatiquement** (heartbeat côté serveur + surveillance côté client).
- **Recherche historique** exécutée côté serveur (DuckDB) — des millions de lignes ne sont
  jamais chargées dans le navigateur. Plage date/heure, filtres rapides et filtres avancés
  (ET/OU, opérateurs, regex).
- **Tableau de bord et analyse** : cartes (événements/bloqués/autorisés/interfaces), séries
  temporelles, AUTORISÉ vs BLOQUÉ, trafic par interface, principales IP source/destination,
  principaux ports, principales règles, principaux protocoles, et une section d'analyse par
  dimension. Un **sélecteur de période** (jour / semaine / mois / année, avec flèches
  précédent/suivant) borne les statistiques au lieu de tout l'historique.
- **Correspondance interfaces et règles** récupérée depuis OPNsense via SSH, affichant par
  ex. `LAN (vtnet0)` au lieu du périphérique brut, avec **historique des changements de
  règles** conservé dans le temps.
- **Export** des résultats de recherche en CSV et JSON.
- **Politique de rétention** (`LOG_RETENTION_DAYS`, `0` = illimitée) avec une tâche de
  nettoyage en arrière-plan.
- **Filtres enregistrés**, pagination, détails d'événement.
- **Surveillance et journalisation interne** avec une page Système → État
  (reçus / analysés / invalides / événements par seconde) et une page Système → Journaux.
- **Détection de sécurité et alertes** : un moteur en arrière-plan (indépendant de
  l'interface) détectant les scans de ports, la force brute (globale et **par port de
  service**), le **balayage réseau** (une même source vers de nombreux hôtes) et (en option)
  les pics de trafic. Les **ports des services de messagerie** sont ignorés par défaut
  (réglable) pour éviter les faux positifs. Les alertes sont listées dans **Sécurité →
  Alertes** (avec **recherche** sur toutes les colonnes et le **label de la règle** qui a
  bloqué la source) et peuvent être **notifiées par e-mail (SMTP) et/ou NTFY** (canal choisi
  par instance) — la notification est ignorée si la source est déjà bloquée par l'application
  ou gérée par un autre plugin. Réglages depuis l'interface web (Sécurité → Détection ; SMTP
  global dans Paramètres → Notifications).
- **Blocage automatique** : ajout des IP publiques des alertes (force brute / scan de ports /
  balayage réseau) dans un **alias pare-feu OPNsense de type « Host(s) »** via l'API REST, en
  mode manuel ou automatique. **Mode simulation (dry-run)**, **liste blanche** gérée depuis
  l'interface, **anti-doublon** (détection automatique des listes de blocage déjà présentes —
  CrowdSec, Q-Feeds… — pour ne jamais re-bloquer), **réconciliation de l'alias** au démarrage,
  et **durée qui double à chaque récidive**, renouvelée juste avant expiration tant que l'IP
  insiste (e-mail uniquement au premier blocage). L'interface affiche le **contenu réel de
  l'alias** (avec signalement des IP **orphelines**) et propose un bouton **« Nettoyer
  l'alias »**.
- **Cluster HA OPNsense** : définissez le **rôle** (maître / esclave) de l'instance. Un esclave
  **hérite de la clé API du maître** (la synchro HA répliquant les clés, une clé locale serait
  écrasée) ; les blocages et retraits sont écrits **sur le maître** puis répliqués vers les
  esclaves via la **synchronisation de configuration HA d'OPNsense** (la synchro HA doit être
  configurée sur le maître, avec « Aliases » activé).
- **Géolocalisation (pays)** : pays d'origine des IP publiques (base gratuite DB-IP Lite, ou
  MaxMind GeoLite2 si une clé est fournie), avec drapeaux et statistiques par pays.
- **Recherche de noms d'hôtes** : DNS inverse plus les noms locaux issus des baux DHCP du
  pare-feu (ISC / Kea / Dnsmasq) récupérés via SSH.
- **Import des journaux OPNsense** : lecture des fichiers de journaux du pare-feu par SSH
  pour combler les événements manquants (au démarrage et via un bouton), y compris les trous
  au milieu d'une journée.
- **WHOIS intégré** : depuis les alertes et la liste des IP bloquées, un bouton interroge le
  WHOIS de l'adresse via TCP/43 (IANA → RIR), sans captcha ni site externe.
- **Authentification multi-utilisateurs** (locale, hachée avec Argon2) avec jetons JWT et
  **rôles** : **admin** (accès complet) et **viewer** (Tableau de bord, Journaux, Analyse).
  Le compte administrateur se crée à la **première connexion** ; les comptes se gèrent dans
  **Paramètres → Utilisateurs**.
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
    api/         routeurs FastAPI (health, auth, users, instances, logs, search, statistics,
                 filters, rules, interfaces, settings, system, export, live, lookup,
                 detection, geoip, opnsense_import, blocking_public, whois)
    parser/      analyseurs filterlog / RFC3164 / RFC5424 / personnalisé
    storage/     base DuckDB, dépôt, rétention
    syslog/      serveur syslog UDP/TCP avec file + workers par lots
    opnsense/    client SSH, chargeur config.xml, baux DHCP, synchronisation, stockage des réglages
    detection/   détecteurs scan de ports / force brute (globale et par service) /
                 balayage réseau / pics, liste blanche, stockage des alertes
    notifications/ notifications e-mail SMTP et NTFY (canal par instance)
    websocket/   concentrateur Temps réel
    core/        journalisation, compteurs, sécurité
    main.py      application FastAPI + cycle de vie
  tests/         tests analyseur / recherche / ssh / détection / blocage / multi-instance /
                 utilisateurs / WHOIS / NTFY / HA
  scripts/       hash_password.py
frontend/
  src/           interface React + Vite + TypeScript
Dockerfile       build multi-étapes (frontend + backend dans une seule image)
docker-compose.yml
```

Le stockage utilise **DuckDB** (colonnes, adapté à l'analytique, mono-fichier, sans serveur).

## Démarrage rapide

1. Copiez le fichier d'environnement et démarrez :

   ```bash
   cp .env.example .env
   docker compose up -d
   ```

   Aucun identifiant n'est nécessaire dans `.env` : au **premier lancement**, une page
   d'**enregistrement** vous invite à créer le compte **administrateur**. Les comptes
   (rôles **admin** / **viewer**) se gèrent ensuite dans **Paramètres → Utilisateurs**.

   *Migration* : si vous aviez déjà un administrateur défini via `AUTH_USERNAME` /
   `AUTH_PASSWORD` (ou `AUTH_PASSWORD_HASH`) dans `.env`, il est **migré
   automatiquement** au premier démarrage (voir le log `Created initial administrator…`) ;
   vous pouvez ensuite retirer ces variables.

2. Ouvrez l'interface web sur <http://SERVER_IP:8080> et créez votre compte administrateur.

3. Configurez OPNsense pour envoyer les journaux vers cet hôte :

   **Système → Paramètres → Journalisation → Destinations distantes**
   ajoutez une destination `SERVER_IP:5140` (UDP par défaut), puis appliquez.

Les données sont stockées dans le volume Docker nommé `opnsense_logs` et **persistent donc
entre `docker compose down` / `up`**.

### Plusieurs OPNsense (multi-instance)

L'application gère plusieurs pare-feu indépendants. Chaque instance possède sa propre base
de données, sa configuration (SSH, API, détection, blocage) et **son propre port syslog**
(5140 pour la première, puis 5141, 5142…). Seule la configuration e-mail (SMTP) est commune.

- Créez/renommez les instances dans **Paramètres → Instances**.
- dans `docker-compose.yml`, une **plage de ports** est publiée (`SYSLOG_PORT_START` à
  `SYSLOG_PORT_END`) pour rendre toutes les instances joignables ; élargissez-la selon le
  nombre de pare-feu prévus.
- Dans chaque OPNsense, envoyez les journaux vers le port affiché pour son instance
  (colonne « port » de la page Instances).
- Un sélecteur en haut de la page permet de basculer d'une instance à l'autre.

### Mise à jour

```bash
docker compose pull && docker compose up -d
```

## Configuration

Toute la configuration se fait via des variables d'environnement (voir `.env.example`) :

| Variable | Défaut | Description |
| --- | --- | --- |
| `WEB_PORT` | `8080` | port HTTP de l'interface web / de l'API |
| `SYSLOG_PORT` | `5140` | premier port d'écoute syslog (les instances suivantes utilisent 5141, 5142…) |
| `SYSLOG_PORT_START` | `5140` | début de la plage de ports publiée par docker-compose |
| `SYSLOG_PORT_END` | `5160` | fin de la plage de ports publiée par docker-compose |
| `SYSLOG_PROTOCOL` | `udp` | `udp`, `tcp` ou `both` |
| `DATA_DIR` | `/data` | répertoire de données (monter un volume ici) |
| `LOG_RETENTION_DAYS` | `30` | rétention en jours (`0` = illimitée) |
| `AUTH_ENABLED` | `true` | activer l'authentification locale |
| `SECRET_KEY` | – | secret de signature JWT |
| `DISPLAY_TIMEZONE` | `Europe/Luxembourg` | fuseau horaire utilisé pour l'affichage |
| `SYSLOG_TIMEZONE` | `DISPLAY_TIMEZONE` | fuseau dans lequel OPNsense émet les horodatages syslog |
| `LOG_LEVEL` | `INFO` | `INFO`/`WARNING`/`ERROR`/`DEBUG` |

Les comptes utilisateurs (rôles **admin** / **viewer**) ne se configurent plus par variables
d'environnement : ils sont créés à la première connexion puis gérés dans
**Paramètres → Utilisateurs**. `AUTH_USERNAME` / `AUTH_PASSWORD` / `AUTH_PASSWORD_HASH`
restent acceptés **uniquement** pour migrer un administrateur existant au premier démarrage.

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

- **Moteur de détection** — scans de ports, force brute (globale et par port de service),
  balayage réseau et (en option) pics de trafic, avec liste d'alertes, recherche et
  notifications e-mail (SMTP) et/ou NTFY.
- **Blocage automatique** — alias pare-feu OPNsense via l'API REST : modes manuel/auto/
  simulation (dry-run), liste blanche, anti-doublon (listes existantes détectées), 
  réconciliation d'alias, durée qui double à chaque récidive et nettoyage des IP orphelines.
- **Cluster HA OPNsense** — rôles maître / esclave, héritage de la clé API du maître et
  propagation des blocages via la synchro de configuration HA d'OPNsense.
- **Géolocalisation (pays)** — pays des IP publiques avec drapeaux et statistiques.
- **Recherche de noms d'hôtes** — DNS inverse et noms des baux DHCP/Dnsmasq.
- **Import des journaux OPNsense** — rattrapage des événements manquants par SSH.
- **Historique des changements de règles**.
- **Multi-OPNsense** — plusieurs pare-feu gérés en parallèle (bases, ports syslog et
  configurations séparés, sélecteur d'instance), e-mail partagé.
- **Multi-utilisateur** — rôles **admin** / **viewer**, création de l'admin à la première
  connexion, gestion des comptes dans l'application.
- **WHOIS intégré** — interrogation WHOIS (IANA → RIR) depuis les alertes et les IP bloquées.
- **Notifications NTFY** — canal push par instance, en complément de l'e-mail SMTP.

Encore prévu :

- **V2** — statistiques avancées, alias, export Excel, webhooks, API complète documentée,
  LDAP/OIDC.
- **V3** — détection enrichie : détection d'anomalies, alertes IP / renseignement sur les
  menaces et corrélation d'événements.

## Licence

MIT
