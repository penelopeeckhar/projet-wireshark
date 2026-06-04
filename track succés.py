import struct
import socket
import ipaddress
import os
import glob
import geoip2.database
import simplekml

# ─────────────────────────────────────────────
# CONFIGURATION — adaptez ces chemins à votre machine
# ─────────────────────────────────────────────
PCAP_FILE   = r"C:\Users\saidm\Downloads\map succés\capture.pcap"
OUTPUT_KML  = r"C:\Users\saidm\Downloads\map succés\map_succes.kml"

# Coordonnées de l'origine : Fès, Maroc
ORIGIN_LAT  = 34.0181
ORIGIN_LON  = -5.0078
ORIGIN_NAME = "Fès, Maroc"

# ─────────────────────────────────────────────
# DÉTECTION AUTOMATIQUE DU FICHIER .mmdb
# ─────────────────────────────────────────────
def find_geodb() -> str:
    """
    Recherche le fichier GeoLite2-City.mmdb dans :
      1. Le dossier courant (récursif, tous niveaux)
      2. %USERPROFILE%\\Downloads (récursif, tous niveaux)

    Retourne le chemin complet du premier .mmdb trouvé,
    ou lève FileNotFoundError avec un message explicatif.
    """
    search_dirs = [
        os.getcwd(),
        os.path.join(os.path.expanduser("~"), "Downloads"),
    ]
    for base in search_dirs:
        matches = glob.glob(os.path.join(base, "**", "*.mmdb"), recursive=True)
        if matches:
            return matches[0]

    downloads = os.path.join(os.path.expanduser("~"), "Downloads")
    raise FileNotFoundError(
        "\n[✗] Fichier GeoLite2-City.mmdb introuvable.\n"
        "    Téléchargez-le sur https://dev.maxmind.com/geoip/geolite2-free-geolocation-data\n"
        "    (compte gratuit requis) et placez le dossier extrait dans :\n"
        f"    {downloads}"
    )


# ─────────────────────────────────────────────
# ÉTAPE 1 — Lecture du fichier PCAP (parser manuel)
# ─────────────────────────────────────────────
def read_pcap(filepath: str) -> list[tuple[str, str]]:
    """
    Parse un fichier .pcap et retourne la liste des couples
    (ip_src, ip_dst) pour tous les paquets IPv4 valides.

    NOTE TECHNIQUE — En-tête non standard (offset 18) :
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Cette capture contient un en-tête propriétaire de 18 octets
    avant le header IP (au lieu des 14 octets Ethernet standard).
    Structure détectée empiriquement :
      [0:16]  → en-tête custom (inclut MAC src/dst + champs inconnus)
      [16:18] → EtherType (0x0800 = IPv4)
      [18:..] → Header IP standard

    Robustesse : gère les records corrompus par re-synchronisation
    et teste automatiquement les offsets alternatifs si l'offset
    principal ne donne pas de résultats.
    """
    PCAP_MAGIC_MICRO_LE = 0xa1b2c3d4
    PCAP_MAGIC_MICRO_BE = 0xd4c3b2a1
    PCAP_MAGIC_NANO_LE  = 0xa1b23cd4

    TS_MIN = 1577836800   # 2020-01-01
    TS_MAX = 1956528000   # 2032-01-01

    with open(filepath, "rb") as f:
        raw = f.read()

    if len(raw) < 24:
        raise ValueError("Fichier PCAP trop court (< 24 octets).")

    magic_le = struct.unpack_from('<I', raw, 0)[0]
    magic_be = struct.unpack_from('>I', raw, 0)[0]

    if magic_le in (PCAP_MAGIC_MICRO_LE, PCAP_MAGIC_NANO_LE):
        endian = '<'
    elif magic_be in (PCAP_MAGIC_MICRO_LE,):
        endian = '>'
    else:
        # Magic non standard (ex: 0xa1b2cd34) → on tente LE
        endian = '<'

    snaplen = struct.unpack_from(endian + 'I', raw, 16)[0]

    # Offsets IP à tester par ordre de priorité
    # Offset 18 = en-tête custom 18 octets (cas de cette capture)
    # Offset 14 = Ethernet standard
    # Offset 26 = Linux SLL ou double VLAN
    IP_OFFSETS_TO_TRY = [18, 14, 26, 22, 4]

    def try_extract_ip(buf: bytes, ip_off: int):
        """Tente d'extraire (src, dst) depuis ip_off dans buf."""
        if len(buf) < ip_off + 20:
            return None
        b = buf[ip_off]
        version = b >> 4
        ihl     = b & 0xf
        if version != 4 or ihl < 5:
            return None
        proto = buf[ip_off + 9]
        if proto not in (1, 6, 17):   # ICMP, TCP, UDP uniquement
            return None
        try:
            src = socket.inet_ntoa(buf[ip_off + 12:ip_off + 16])
            dst = socket.inet_ntoa(buf[ip_off + 16:ip_off + 20])
            return (src, dst)
        except Exception:
            return None

    # Détection automatique du meilleur offset sur les 50 premiers paquets
    offset_hits = {off: 0 for off in IP_OFFSETS_TO_TRY}
    offset = 24
    sample = 0
    while offset + 16 <= len(raw) and sample < 50:
        ts_sec, _, incl_len, _ = struct.unpack_from(endian + 'IIII', raw, offset)
        if 0 < incl_len <= min(snaplen, 65535) and offset + 16 + incl_len <= len(raw):
            buf = raw[offset + 16:offset + 16 + incl_len]
            for ip_off in IP_OFFSETS_TO_TRY:
                if try_extract_ip(buf, ip_off):
                    offset_hits[ip_off] += 1
            offset += 16 + incl_len
            sample += 1
        else:
            offset += 1

    best_offset = max(offset_hits, key=lambda k: offset_hits[k])
    print(f"      Offset IP détecté automatiquement : {best_offset} octets "
          f"({offset_hits[best_offset]}/{sample} paquets valides)")

    # Parse complet avec le meilleur offset
    offset = 24
    pairs  = []
    while offset + 16 <= len(raw):
        ts_sec, ts_sub, incl_len, orig_len = struct.unpack_from(endian + 'IIII', raw, offset)
        if (TS_MIN <= ts_sec <= TS_MAX
                and 0 < incl_len <= min(snaplen, 65535)
                and offset + 16 + incl_len <= len(raw)):
            buf    = raw[offset + 16:offset + 16 + incl_len]
            result = try_extract_ip(buf, best_offset)
            if result:
                pairs.append(result)
            offset += 16 + incl_len
        else:
            # Re-synchronisation sur le prochain timestamp plausible
            resynced = False
            for skip in range(1, 513):
                if offset + skip + 4 > len(raw):
                    break
                ts2 = struct.unpack_from(endian + 'I', raw, offset + skip)[0]
                if TS_MIN <= ts2 <= TS_MAX:
                    offset += skip
                    resynced = True
                    break
            if not resynced:
                offset += 512

    return pairs


# ─────────────────────────────────────────────
# ÉTAPE 2 — Filtrage des IPs publiques
# ─────────────────────────────────────────────
def is_public(ip_str: str) -> bool:
    """
    Renvoie True si l'adresse IP est publique (routable sur Internet).
    Élimine : RFC 1918, loopback, link-local, multicast, etc.
    """
    try:
        return ipaddress.ip_address(ip_str).is_global
    except ValueError:
        return False


# ─────────────────────────────────────────────
# ÉTAPE 3 — Géolocalisation via GeoLite2
# ─────────────────────────────────────────────
def geolocate(ip_str: str, reader: geoip2.database.Reader) -> tuple[float, float, str] | None:
    """
    Retourne (latitude, longitude, pays) pour une IP donnée,
    ou None si l'IP est absente de la base ou sans coordonnées.
    """
    try:
        response = reader.city(ip_str)
        lat      = response.location.latitude
        lon      = response.location.longitude
        country  = response.country.name or "Inconnu"
        if lat is None or lon is None:
            return None
        return (lat, lon, country)
    except Exception:
        return None


# ─────────────────────────────────────────────
# ÉTAPE 4 — Ajout d'un segment KML
# ─────────────────────────────────────────────
def retKML(kml: simplekml.Kml, dst_coords: tuple[float, float, str]) -> None:
    """
    Ajoute une ligne rouge Fès → destination dans le document KML.

    Format couleur KML (ABGR) :
      "ff0000ff" = Alpha=ff(opaque) + Bleu=00 + Vert=00 + Rouge=ff → ROUGE
      Ordre inverse du HTML/CSS (RGB).
    """
    dst_lat, dst_lon, dst_country = dst_coords

    ls = kml.newlinestring(
        name        = f"→ {dst_country}",
        description = f"Trafic réseau capturé vers {dst_country}",
        coords      = [
            (ORIGIN_LON, ORIGIN_LAT),   # simplekml attend (lon, lat)
            (dst_lon,    dst_lat),
        ]
    )
    ls.style.linestyle.color = "ff0000ff"   # Rouge opaque ABGR
    ls.style.linestyle.width = 2


# ─────────────────────────────────────────────
# ÉTAPE 5 — Sauvegarde KML
# ─────────────────────────────────────────────
def save_kml(kml: simplekml.Kml, output_path: str) -> None:
    """Écrit le fichier KML sur le disque."""
    kml.save(output_path)
    print(f"[✓] KML sauvegardé : {output_path}")


# ─────────────────────────────────────────────
# PIPELINE PRINCIPAL
# ─────────────────────────────────────────────
def main():
    print("[0/4] Localisation de la base GeoLite2…")
    geodb_file = find_geodb()
    print(f"      Base trouvée : {geodb_file}")

    print("[1/4] Lecture du fichier PCAP…")
    pairs = read_pcap(PCAP_FILE)
    print(f"      {len(pairs)} paquets IPv4 lus.")

    print("[2/4] Filtrage des IPs publiques…")
    public_dsts = {dst for _, dst in pairs if is_public(dst)}
    print(f"      {len(public_dsts)} adresses IP publiques uniques trouvées.")

    print("[3/4] Géolocalisation…")
    kml = simplekml.Kml()
    kml.newpoint(name=ORIGIN_NAME, coords=[(ORIGIN_LON, ORIGIN_LAT)])

    geo_ok = 0
    with geoip2.database.Reader(geodb_file) as reader:
        for ip in public_dsts:
            coords = geolocate(ip, reader)
            if coords:
                retKML(kml, coords)
                geo_ok += 1

    print(f"      {geo_ok}/{len(public_dsts)} IPs géolocalisées.")

    print("[4/4] Export KML…")
    save_kml(kml, OUTPUT_KML)


if __name__ == "__main__":
    main()
