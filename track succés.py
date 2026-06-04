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
        # recursive=True + "**" couvre tous les niveaux de sous-dossiers
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
    Parse un fichier .pcap (microseconde ou nanoseconde) et retourne
    la liste des couples (ip_src, ip_dst) pour tous les paquets IPv4 valides.

    Robustesse : gère les records corrompus par re-synchronisation sur le
    prochain timestamp valide (2020-01-01 <= ts <= 2030-01-01), et teste
    plusieurs offsets d'en-tête IP (Ethernet, NULL/loopback, VLAN, padding).
    """
    PCAP_MAGIC_MICRO_LE = 0xa1b2c3d4
    PCAP_MAGIC_MICRO_BE = 0xd4c3b2a1
    PCAP_MAGIC_NANO_LE  = 0xa1b23cd4
    PCAP_MAGIC_NANO_BE  = 0xd4b23ca1

    TS_MIN = 1577836800   # 2020-01-01
    TS_MAX = 1893456000   # 2030-01-01

    with open(filepath, "rb") as f:
        raw = f.read()

    if len(raw) < 24:
        raise ValueError("Fichier pcap trop court (< 24 octets).")

    magic_le = struct.unpack_from('<I', raw, 0)[0]
    magic_be = struct.unpack_from('>I', raw, 0)[0]

    if magic_le in (PCAP_MAGIC_MICRO_LE, PCAP_MAGIC_NANO_LE):
        endian = '<'
    elif magic_be in (PCAP_MAGIC_MICRO_LE, PCAP_MAGIC_NANO_LE):
        endian = '>'
    else:
        raise ValueError(
            f"Magic non reconnue : 0x{magic_le:08x}. "
            "Exportez en .pcap (pas .pcapng) depuis Wireshark."
        )

    snaplen = struct.unpack_from(endian + 'I', raw, 16)[0]

    IP_OFFSETS = [14, 18, 22, 26, 30, 4]

    def extract_ip(buf):
        for ip_off in IP_OFFSETS:
            if len(buf) < ip_off + 20:
                continue
            b = buf[ip_off]
            if (b >> 4) == 4 and (b & 0xf) >= 5 and buf[ip_off + 9] in (1, 6, 17):
                try:
                    return (socket.inet_ntoa(buf[ip_off+12:ip_off+16]),
                            socket.inet_ntoa(buf[ip_off+16:ip_off+20]))
                except Exception:
                    pass
        return None

    offset = 24
    pairs  = []

    while offset + 16 <= len(raw):
        ts_sec, ts_sub, incl_len, orig_len = struct.unpack_from(endian + 'IIII', raw, offset)

        # Record valide : timestamp plausible, taille cohérente avec snaplen
        if (TS_MIN <= ts_sec <= TS_MAX
                and ts_sub < 1_000_000_000
                and 0 < incl_len <= snaplen
                and offset + 16 + incl_len <= len(raw)):
            buf = raw[offset+16 : offset+16+incl_len]
            result = extract_ip(buf)
            if result:
                pairs.append(result)
            offset += 16 + incl_len
        else:
            # Re-synchronisation : chercher le prochain ts valide dans les 512 octets
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
                offset += 512   # avancer quand même pour ne pas boucler à l'infini

    return pairs


# ─────────────────────────────────────────────
# ÉTAPE 2 — Filtrage des IPs publiques (is_global)
# ─────────────────────────────────────────────
def is_public(ip_str: str) -> bool:
    """
    Renvoie True si l'adresse IP est une adresse publique (routable
    sur Internet), False pour les adresses privées (RFC 1918),
    loopback, link-local, multicast, etc.
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
    ou None si l'IP n'est pas dans la base.
    """
    try:
        response = reader.city(ip_str)
        lat = response.location.latitude
        lon = response.location.longitude
        country = response.country.name or "Inconnu"
        if lat is None or lon is None:
            return None
        return (lat, lon, country)
    except Exception:
        return None


# ─────────────────────────────────────────────
# ÉTAPE 4 — Construction d'un segment KML
# ─────────────────────────────────────────────
def retKML(kml: simplekml.Kml, dst_coords: tuple[float, float, str]) -> None:
    """
    Ajoute au document KML une ligne rouge tracée depuis l'origine
    (Fès) jusqu'aux coordonnées de destination.

    NOTE FORMAT COULEUR KML (ABGR) :
      "ff0000ff" = alpha=ff + bleu=00 + vert=00 + rouge=ff → ROUGE opaque
    """
    dst_lat, dst_lon, dst_country = dst_coords

    ls = kml.newlinestring(
        name=f"→ {dst_country}",
        description=f"Trafic réseau capturé vers {dst_country}",
        coords=[
            (ORIGIN_LON, ORIGIN_LAT),
            (dst_lon,    dst_lat),
        ]
    )
    ls.style.linestyle.color = "ff0000ff"
    ls.style.linestyle.width = 2


# ─────────────────────────────────────────────
# ÉTAPE 5 — Export du KML dans un fichier
# ─────────────────────────────────────────────
def save_kml(kml: simplekml.Kml, output_path: str) -> None:
    """
    Sauvegarde le document KML dans un fichier sur le disque.
    """
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
