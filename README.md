# 🌍 projet-wireshark — Cartographie du trafic réseau capturé

> Transforme une capture Wireshark (`.pcap`) en carte KML mondiale : chaque paquet réseau devient une ligne rouge tracée depuis **Fès, Maroc** vers sa destination géographique réelle.

---

## Table des matières

1. [Vue d'ensemble](#vue-densemble)
2. [Pipeline en 5 étapes](#pipeline-en-5-étapes)
3. [Prérequis & Installation](#prérequis--installation)
4. [Configuration](#configuration)
5. [Utilisation](#utilisation)
6. [Bugs corrigés](#bugs-corrigés)
7. [Note technique — Format couleur KML (ABGR)](#note-technique--format-couleur-kml-abgr)
8. [Visualiser le résultat dans Google Earth](#visualiser-le-résultat-dans-google-earth)
9. [Structure du projet](#structure-du-projet)
10. [Dépendances](#dépendances)
11. [Obtenir la base GeoLite2 gratuitement](#obtenir-la-base-geolite2-gratuitement)

---

## Vue d'ensemble

`map_succes.py` est un script Python qui réalise une **analyse géographique du trafic réseau** capturé avec Wireshark. Il lit un fichier `.pcap`, extrait chaque adresse IP de destination, la géolocalise via une base de données locale MaxMind GeoLite2, et génère un fichier **KML** (Keyhole Markup Language) affichable dans Google Earth ou Google Maps.

Le résultat visuel : une mappemonde avec des **lignes rouges rayonnant depuis Fès** vers tous les serveurs contactés dans le monde.

```
capture.pcap  ──►  map_succes.py  ──►  map_succes.kml  ──►  🌍 Google Earth
```

---

## Pipeline en 5 étapes

### Étape 1 — Lecture PCAP avec `dpkt`

```python
with open(PCAP_FILE, "rb") as f:
    pcap = dpkt.pcap.Reader(f)
    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
```

`dpkt` décode les trames à bas niveau. Chaque paquet est lu **en binaire** puis analysé couche par couche : trame Ethernet → paquet IP → extraction des adresses source (`ip.src`) et destination (`ip.dst`). Les paquets non-IPv4 (IPv6, ARP, etc.) sont ignorés silencieusement.

---

### Étape 2 — Décodage Ethernet / IP

```python
ip  = eth.data                      # couche réseau
src = socket.inet_ntoa(ip.src)      # bytes → "1.2.3.4"
dst = socket.inet_ntoa(ip.dst)
```

`socket.inet_ntoa()` convertit les 4 octets bruts de l'adresse IP en notation décimale pointée lisible. Le script conserve les deux adresses (source et destination) pour chaque paquet IPv4 trouvé dans la capture.

---

### Étape 3 — Filtre IPs publiques (`ipaddress.is_global`)

```python
ipaddress.ip_address(ip_str).is_global
```

Toutes les adresses **non-routables** sont éliminées avant géolocalisation. Sont exclues automatiquement :

| Plage | Type | Exemple |
|-------|------|---------|
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | Privée (RFC 1918) | `192.168.1.1` |
| `127.0.0.0/8` | Loopback | `127.0.0.1` |
| `169.254.0.0/16` | Link-local | `169.254.1.1` |
| `224.0.0.0/4` | Multicast | `224.0.0.251` |

Seules les adresses **publiques** (routable sur Internet) sont conservées, ce qui évite de tenter de géolocaliser des IPs locales introuvables dans la base GeoLite2.

---

### Étape 4 — Géolocalisation via GeoLite2 (base locale)

```python
with geoip2.database.Reader(GEODB_FILE) as reader:
    response = reader.city(ip_str)
    lat = response.location.latitude
    lon = response.location.longitude
    country = response.country.name
```

La base **GeoLite2-City.mmdb** est interrogée localement (aucune requête réseau externe). Pour chaque IP publique, on récupère ses coordonnées GPS et le nom de son pays. Si l'IP est absente de la base ou si les coordonnées sont nulles, elle est ignorée.

---

### Étape 5 — Export KML avec lignes rouges

```python
ls = kml.newlinestring(
    name="→ France",
    coords=[(ORIGIN_LON, ORIGIN_LAT), (dst_lon, dst_lat)]
)
ls.style.linestyle.color = "ff0000ff"   # Rouge en ABGR
ls.style.linestyle.width = 2
kml.save(OUTPUT_KML)
```

`simplekml` construit le document XML KML. Chaque destination devient un **segment de ligne** (`LineString`) reliant Fès aux coordonnées de destination. La couleur `ff0000ff` (rouge opaque) est encodée en format ABGR propre au KML (voir [section dédiée](#note-technique--format-couleur-kml-abgr)).

---

## Prérequis & Installation

### Python

Python 3.10 ou supérieur requis (utilisation des type hints avec `|` et `tuple[...]`).

```bash
python --version
# Python 3.10+
```

### Bibliothèques Python

```bash
pip install dpkt geoip2 simplekml
```

| Bibliothèque | Rôle |
|---|---|
| `dpkt` | Décodage bas-niveau des fichiers PCAP |
| `geoip2` | Client pour interroger les bases MaxMind (.mmdb) |
| `simplekml` | Génération de fichiers KML |
| `ipaddress` | Filtrage des IPs (bibliothèque standard, incluse dans Python) |
| `socket` | Conversion adresses binaires → chaînes (bibliothèque standard) |

### Fichiers nécessaires

| Fichier | Où l'obtenir |
|---|---|
| `capture.pcap` | Via Wireshark : Fichier → Enregistrer sous |
| `GeoLite2-City.mmdb` | MaxMind (voir [section dédiée](#obtenir-la-base-geolite2-gratuitement)) |

---

## Configuration

En tête du script, modifiez les trois constantes pour correspondre à votre machine :

```python
# map_succes.py — section CONFIGURATION
PCAP_FILE  = r"C:\Users\VotreNom\captures\capture.pcap"
GEODB_FILE = r"C:\Users\VotreNom\GeoLite2\GeoLite2-City.mmdb"
OUTPUT_KML = r"C:\Users\VotreNom\output\map_succes.kml"
```

> **Windows** : utilisez des chaînes brutes (`r"..."`) ou des doubles backslashes (`\\`) pour les chemins.  
> **Linux/macOS** : utilisez des chemins Unix normaux (`/home/user/captures/capture.pcap`).

L'origine géographique (Fès) est définie par :

```python
ORIGIN_LAT  = 34.0181
ORIGIN_LON  = -5.0078
ORIGIN_NAME = "Fès, Maroc"
```

Modifiez ces valeurs si vous souhaitez changer le point de départ des lignes.

---

## Utilisation

```bash
# 1. Cloner le repo
git clone https://github.com/penelopeeckhar/projet-wireshark.git
cd projet-wireshark

# 2. Installer les dépendances
pip install dpkt geoip2 simplekml

# 3. Configurer les chemins dans map_succes.py (voir section Configuration)

# 4. Lancer le script
python map_succes.py
```

Sortie attendue dans le terminal :

```
[1/4] Lecture du fichier PCAP…
      1 248 paquets IPv4 lus.
[2/4] Filtrage des IPs publiques…
      87 adresses IP publiques uniques trouvées.
[3/4] Géolocalisation…
      Lignes KML générées.
[4/4] Export KML…
[✓] KML sauvegardé : C:\Users\VotreNom\output\map_succes.kml
```

---

## Note technique — Format couleur KML (ABGR)

KML n'utilise **pas** le format RGB familier du HTML/CSS. Il utilise l'ordre **ABGR** (Alpha–Bleu–Vert–Rouge), soit l'exact inverse.

```
HTML/CSS :  #RRGGBB      #ff0000  → rouge
KML       :  AABBGGRR    ff0000ff → rouge
             ││││││└└ Rouge (RR) = ff
             ││││└└── Vert  (GG) = 00
             ││└└──── Bleu  (BB) = 00
             └└─────── Alpha     = ff (opaque)
```

Dans ce script, la couleur rouge utilisée pour les lignes est :

```python
ls.style.linestyle.color = "ff0000ff"
#                           ││││││└└ RR = ff → rouge maximal
#                           ││││└└── GG = 00
#                           ││└└──── BB = 00
#                           └└─────── AA = ff → totalement opaque
```

> ⚠️ Erreur fréquente : écrire `"ff0000ff"` en pensant RGB (ce qui donnerait du bleu en KML). Toujours raisonner en ABGR lorsqu'on travaille avec des fichiers KML.

---

## Visualiser le résultat dans Google Earth

1. Télécharger [Google Earth Pro](https://www.google.com/earth/about/versions/) (gratuit)
2. Fichier → Ouvrir → sélectionner `map_succes.kml`
3. Les lignes rouges depuis Fès vers le monde apparaissent sur le globe

Alternativement, importez le fichier `.kml` dans [Google My Maps](https://www.google.com/mymaps) pour une vue en ligne.

---

## Structure du projet

```
projet-wireshark/
│
├── map_succes.py          # Script principal (corrigé)
├── README.md              # Ce fichier
│
├── captures/              # (à créer) Vos fichiers .pcap
│   └── capture.pcap
│
├── GeoLite2/              # (à créer) Base de géolocalisation
│   └── GeoLite2-City.mmdb
│
└── output/                # (à créer) Fichiers KML générés
    └── map_succes.kml
```

---

## Dépendances

```
dpkt>=1.9.8
geoip2>=4.8.0
simplekml>=1.3.6
```

Créez un fichier `requirements.txt` avec ce contenu et installez via :

```bash
pip install -r requirements.txt
```

---

## Obtenir la base GeoLite2 gratuitement

MaxMind propose la base GeoLite2 **gratuitement** après création d'un compte :

1. Créer un compte sur [maxmind.com](https://www.maxmind.com/en/geolite2/signup)
2. Aller dans **My Account → GeoIP2 / GeoLite2 → Download Databases**
3. Télécharger **GeoLite2-City** au format **MMDB**
4. Décompresser l'archive et placer `GeoLite2-City.mmdb` dans le dossier configuré dans `GEODB_FILE`

> La licence GeoLite2 est gratuite pour usage personnel et non-commercial. Pour un usage commercial, MaxMind propose la base GeoIP2 payante plus précise.

---

## Licence

MIT — libre d'utilisation, de modification et de distribution.

## AUTEUR

Abir Majdi étudiante en génie de développement numérique et cybersécurité en ENSA Fès
