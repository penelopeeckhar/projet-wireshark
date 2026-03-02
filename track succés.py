import dpkt
import socket
import geoip2.database
import ipaddress

# Charger la base de données GeoLite2
reader = geoip2.database.Reader(r'C:\Users\saidm\Documents\cyber\GeoLite2-City.mmdb')

def is_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_global
    except ValueError:
        return False

def retKML(dstip):
    try:
        dst = reader.city(dstip)

        dstlongitude = dst.location.longitude
        dstlatitude = dst.location.latitude
        srclongitude, srclatitude = -5.0169, 34.0339  # Fès, Maroc

        print(f"Destination: {dstlatitude}, {dstlongitude} | Source: {srclatitude}, {srclongitude}")

        kml = (
            '<Placemark>\n'
            '  <name>%s</name>\n'
            '  <styleUrl>#redLine</styleUrl>\n'
            '  <LineString>\n'
            '    <coordinates>%f,%f %f,%f</coordinates>\n'
            '  </LineString>\n'
            '</Placemark>\n'
        ) % (dstip, srclongitude, srclatitude, dstlongitude, dstlatitude)
        return kml
    except geoip2.errors.AddressNotFoundError:
        print(f"L'adresse {dstip} n'est pas dans la base de données.")
        return ''
    except Exception as e:
        print(f"Erreur dans retKML : {e}")
        return ''


def plotIPs(pcap):
    kml_points = ''
    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue  # Ignorer les paquets non-IP

            # Obtenir les adresses IP source et destination
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            print(f"Source IP: {src}, Destination IP: {dst}")

            # Filtrer les adresses non publiques
            if is_public_ip(dst) and is_public_ip(src):
                kml = retKML(dst, src)
                kml_points += kml
        except Exception as e:
            print(f"Erreur : {e}")
    return kml_points

def main():
    # Charger le fichier PCAP
    with open(r'C:\Users\saidm\Documents\cyber\wire.pcap.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        # Créer le header et le footer KML
        kml_header = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<kml xmlns="http://www.opengis.net/kml/2.2">\n'
    '<Document>\n'
    '<Style id="redLine">\n'
    '  <LineStyle>\n'
    '    <color>ff0000ff</color>\n'  # Rouge en KML
    '    <width>2</width>\n'
    '  </LineStyle>\n'
    '</Style>\n'
)

        kml_footer = '</Document>\n</kml>\n'

        # Construire le document KML
        kml_doc = kml_header + plotIPs(pcap) + kml_footer
        print(kml_doc)

if __name__ == "__main__":
    main()
