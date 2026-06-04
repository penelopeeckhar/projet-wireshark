# 🌍 projet-wireshark — Cartographie du trafic réseau

> Transforme une capture Wireshark (`.pcap`) en carte KML mondiale :  
> chaque flux réseau devient une **ligne rouge** tracée depuis **Fès, Maroc** vers sa destination géographique réelle.

---

## Résultat obtenu — `map_succes.kml`

La capture fournie (`capture.pcap`, **56 Mo**, **4 min 28 s** de trafic réel) a produit les destinations suivantes :

| Pays | Lignes KML | Services identifiés |
|---|---|---|
| 🇺🇸 United States | 49 | Google, Microsoft, Cloudflare, Fastly/GitHub, Meta |
| 🇵🇹 Portugal | 13 | Akamai CDN |
| 🇫🇷 France | 6 | Google, Fastly |
| 🇲🇦 Morocco | 4 | Maroc Telecom / IAM |
| 🇪🇸 Spain | 3 | Akamai |
| 🇸🇪 Sweden | 2 | — |
| 🇦🇺 Australia | 2 | — |
| 🇬🇧 United Kingdom | 2 | — |
| 🇨🇭 Switzerland | 2 | — |
| 🇩🇪 Germany | 1 | — |
| 🇯🇵 Japan | 1 | — |
| 🇸🇦 Saudi Arabia | 1 | — |
| 🇺🇦 Ukraine | 1 | — |

**87 lignes KML** · **13 pays** · **20 IP publiques uniques**  
Protocoles : TCP (`3 076 paquets`) + UDP (`2 226 paquets`) · Port dominant : HTTPS/443

---

## Table des matières

1. [Vue d'ensemble](#vue-densemble)
2. [Pipeline en 5 étapes](#pipeline-en-5-étapes)
3. [Particularité technique — En-tête non standard](#particularité-technique--en-tête-non-standard)
4. [Bugs corrigés](#bugs-corrigés)
5. [Note — Format couleur KML (ABGR)](#note--format-couleur-kml-abgr)
6. [Prérequis & Installation](#prérequis--installation)
7. [Configuration](#configuration)
8. [Utilisation](#utilisation)
9. [Visualiser le résultat dans Google Earth](#visualiser-le-résultat-dans-google-earth)
10. [Contenu du repo](#contenu-du-repo)
11. [Obtenir la base GeoLite2 gratuitement](#obtenir-la-base-geolite2-gratuitement)
12. [Conseils — Améliorer la capture](#conseils--améliorer-la-capture)

---

## Vue d'ensemble

`map_succes.py` est un script Python qui réalise une **analyse géographique du trafic réseau** capturé avec Wireshark. Il lit un fichier `.pcap`, extrait chaque adresse IP de destination publique, la géolocalise via une base de données locale MaxMind GeoLite2, et génère un fichier **KML** affichable dans Google Earth.

```
capture.pcap  ──►  map_succes.py  ──►  map_succes.kml  ──►  🌍 Google Earth
   56 Mo              Python 3.10+         87 lignes          13 pays
```

---

## Pipeline en 5 étapes

### Étape 0 — Détection automatique de la base GeoLite2

```python
matches = glob.glob(os.path.join(base, "**", "*.mmdb"), recursive=True)
```

Le script cherche automatiquement le fichier `.mmdb` dans le dossier courant et dans `Downloads`, sans nécessiter de configuration manuelle du chemin. Plus besoin de modifier une constante pour chaque machine.

---

### Étape 1 — Lecture PCAP avec parser manuel

```python
magic_le = struct.unpack_from('<I', raw, 0)[0]
# Détection endianness → lecture des record headers 16 octets
# → extraction payload → détection IP
```

`dpkt` n'est **pas utilisé** — le script implémente son propre parser binaire en utilisant uniquement `struct` et `socket` de la bibliothèque standard. Avantages : pas de dépendance fragile, gestion des magic bytes non standard, re-synchronisation automatique sur les paquets corrompus.

---

### Étape 2 — Filtrage des IPs publiques (`is_global`)

```python
ipaddress.ip_address(ip_str).is_global
```

Toutes les adresses non-routables sont éliminées avant géolocalisation :

| Plage | Type |
|---|---|
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | Privée RFC 1918 |
| `127.0.0.0/8` | Loopback |
| `169.254.0.0/16` | Link-local |
| `224.0.0.0/4` | Multicast |

---

### Étape 3 — Géolocalisation via GeoLite2 (local)

```python
response = reader.city(ip_str)
lat, lon, country = response.location.latitude, ...
```

Base GeoLite2-City interrogée **localement** (zéro requête réseau externe). Pour chaque IP publique : latitude, longitude, et nom de pays.

---

### Étape 4 — Construction des segments KML

```python
ls = kml.newlinestring(
    coords=[(ORIGIN_LON, ORIGIN_LAT), (dst_lon, dst_lat)]
)
ls.style.linestyle.color = "ff0000ff"   # Rouge en ABGR
```

Chaque destination devient une `LineString` rouge reliant Fès à sa position GPS.

---

### Étape 5 — Export fichier KML

```python
kml.save(OUTPUT_KML)
```

Le KML est écrit physiquement sur le disque.

---

## Particularité technique — En-tête non standard

La capture de ce projet a été réalisée avec un driver réseau qui ajoute **4 octets supplémentaires** à l'en-tête Ethernet standard.

| Offset | Contenu | Longueur |
|---|---|---|
| `0 – 15` | En-tête custom (MAC dst + MAC src + champs inconnus) | 16 octets |
| `16 – 17` | EtherType `0x0800` (IPv4) | 2 octets |
| `18 – ...` | Header IP standard | à partir d'ici |

Conséquence : **le header IP commence à l'offset 18** au lieu des 14 octets habituels (Ethernet standard) ou 16 (Linux SLL). Le script **détecte cela automatiquement** en testant plusieurs offsets sur les 50 premiers paquets et en choisissant celui qui donne le plus de paquets IPv4 valides.

```
Ethernet standard :  [MAC×6][MAC×6][EtherType×2] → IP à offset 14
Cette capture     :  [MAC×6][MAC×6][????×4][EtherType×2] → IP à offset 18
```
---

## Note — Format couleur KML (ABGR)

KML utilise l'ordre **ABGR** (Alpha–Bleu–Vert–Rouge), l'inverse du HTML.

```
HTML/CSS :   #RRGGBB     #ff0000   → rouge
KML      :   AABBGGRR    ff0000ff  → rouge

Décomposition de "ff0000ff" :
  ff  →  Alpha  (opacité) = 255 = totalement opaque
  00  →  Bleu   = 0
  00  →  Vert   = 0
  ff  →  Rouge  = 255
```

Erreur classique : écrire `ff0000ff` en pensant RGB → ce serait du **bleu** en KML, pas du rouge.

---

## Prérequis & Installation

**Python 3.10+** requis.

```bash
pip install geoip2 simplekml
```

| Bibliothèque | Rôle |
|---|---|
| `geoip2` | Lecture des bases MaxMind `.mmdb` |
| `simplekml` | Génération des fichiers KML |
| `struct`, `socket`, `ipaddress`, `glob` | Standard Python, aucune installation |

---

## Configuration

Deux constantes à adapter en haut du script :

```python
PCAP_FILE  = r"C:\Users\saidm\Downloads\map succés\capture.pcap"
OUTPUT_KML = r"C:\Users\saidm\Downloads\map succés\map_succes.kml"
```

La base `.mmdb` est trouvée **automatiquement** dans `Downloads` ou le dossier courant.

---

## Utilisation

```bash
# 1. Cloner le repo
git clone https://github.com/penelopeeckhar/projet-wireshark.git
cd projet-wireshark

# 2. Installer les dépendances
pip install geoip2 simplekml

# 3. Placer GeoLite2-City.mmdb dans Downloads (détecté automatiquement)

# 4. Lancer
python map_succes.py
```

Sortie attendue :

```
[0/4] Localisation de la base GeoLite2…
      Base trouvée : C:\Users\saidm\Downloads\GeoLite2-City_20250207\GeoLite2-City.mmdb
[1/4] Lecture du fichier PCAP…
      Offset IP détecté automatiquement : 18 octets (48/50 paquets valides)
      5304 paquets IPv4 lus.
[2/4] Filtrage des IPs publiques…
      20 adresses IP publiques uniques trouvées.
[3/4] Géolocalisation…
      20/20 IPs géolocalisées.
[4/4] Export KML…
[✓] KML sauvegardé : C:\Users\saidm\Downloads\map succés\map_succes.kml
```

---

## Visualiser le résultat dans Google Earth

1. Télécharger [Google Earth Pro](https://www.google.com/earth/about/versions/) (gratuit)
2. **Fichier → Ouvrir** → sélectionner `map_succes.kml`
3. Les lignes rouges depuis Fès vers le monde apparaissent sur le globe

Alternativement, importer dans [Google My Maps](https://www.google.com/mymaps) pour une vue en ligne.

---

## DEMO

Network Traffic Analysis : https://drive.google.com/file/d/1lTxLqrnXaFU5r0egPjw9CZreoKh8kNsI/view?usp=sharing

## Contenu du repo

```
projet-wireshark/
│
├── map_succes.py          # Script principal
├── README.md              # Ce fichier
├── capture.pcap           # Capture Wireshark (56 Mo, 4m28s, 7983 paquets)
└── map_succes.kml         # Résultat KML généré (87 lignes, 13 pays)
```

---

## Obtenir la base GeoLite2 gratuitement

1. Créer un compte sur [maxmind.com/en/geolite2/signup](https://www.maxmind.com/en/geolite2/signup)
2. **My Account → Downloads → GeoLite2 City → Download GZIP**
3. Décompresser → placer le dossier dans `Downloads`
4. Le script trouve `GeoLite2-City.mmdb` automatiquement

---

## Conseils — Améliorer la capture

La capture actuelle contient principalement du trafic **HTTPS chiffré** (port 443) vers des CDN (Google, Akamai, Cloudflare, Fastly). Pour obtenir une carte plus riche :

- **Durée** : capturer pendant 10–15 minutes en naviguant activement
- **Activités variées** : ouvrir des dizaines de sites, lancer des applis, regarder une vidéo
- **DNS visible** : activer la capture sur l'interface principale (pas loopback) pour voir les requêtes DNS (port 53) qui révèlent les domaines contactés
- **Filtre Wireshark** pour n'afficher que le trafic sortant : `ip.dst != 10.0.0.0/8 && ip.dst != 192.168.0.0/16`

---

## Licence

MIT — libre d'utilisation, de modification et de distribution.

## Auteur

Abir Majdi élève ingénieure en génie de développemnt numérique et cybersécurité
