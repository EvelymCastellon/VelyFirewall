import ipaddress
import re
import os

# === RANGOS DE REDES INTERNAS ===
INTERNAL_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16')
]

# === CARGAR BLACKLIST DESDE RUTA FIJA ===
BLACKLIST_PATH = "/home/evelym/Lab/VelyFirewall/scripts/blacklist_ips.txt"
BLACKLISTED_IPS = set()
try:
    if os.path.exists(BLACKLIST_PATH):
        with open(BLACKLIST_PATH, "r") as f:
            BLACKLISTED_IPS = set(line.strip() for line in f if line.strip())
    else:
        print(f"⚠️ [ss7_rules] No se encontró {BLACKLIST_PATH}. Continuando sin lista negra.")
except Exception as e:
    print(f"❌ [ss7_rules] Error cargando blacklist: {e}")
    BLACKLISTED_IPS = set()

# === RANGOS MALICIOSOS DE RED ===
BLACKLISTED_RANGES = [
    "23.155.208.0/24", "23.159.56.0/24", "23.161.8.0/24", "23.170.224.0/24",
    "23.171.200.0/24", "23.175.136.0/24", "23.185.184.0/24", "41.57.124.0/22",
    "41.72.0.0/23", "41.77.64.0/21", "41.204.224.0/24", "45.148.10.0/24",
    "198.211.109.0/24", "143.198.202.0/24", "198.8.96.0/19", "103.174.186.0/24"
]
BLACKLISTED_SUBNETS = [ipaddress.ip_network(net) for net in BLACKLISTED_RANGES]

# === PATRONES DE ATAQUE EN HEX ===
ATTACK_PATTERNS = {
    'SEND_ROUTING_INFO': r'\xa1.{1}\x02\x01\x01\x02\x01\x16\x30',
    'SEND_ROUTING_INFO_FOR_SM': r'\xa1.{1}\x02\x01.{1}\x02\x01\x2d',
    'PROVIDE_SUBSCRIBER_INFO': r'\xa2.{1}\x02\x01\x01\x30.{1}\x02\x01\x46\x30',
    'UPDATE_LOCATION': r'\xa1.{1}\x02\x01\x01\x02\x01\x02\x30',
    'CANCEL_LOCATION': r'\xa1.{1}\x02\x01\x01\x02\x01\x03\xa3',
    'INSERT_SUBSCRIBER_DATA': r'\xa1.{1}\x02\x01.{1}\x02\x01\x07\x30'
}

# === OTROS PARÁMETROS DE CONTROL ===
UNAUTHORIZED_NODES = {"9999999999"}

# === FUNCIONES DE DETECCIÓN ===
def is_flooding_attack(features):
    return features.get('f_msg_count_per_imsi', 0) > 50

def is_unauthorized_node(features):
    return features.get('c_network_node_number', '') in UNAUTHORIZED_NODES

def is_send_routing_info_attack(features):
    return features.get('f_count_ok_sri_between2lu', 0) > 15 or (
        features.get('f_count_ok_sri_between2lu', 0) > 5 and 
        features.get('f_frequent_ok_sri_between2lu', 0) == 1)

def is_location_tracking_attack(features):
    return (features.get('f_count_ok_psi_between2lu', 0) > 10 and
            features.get('src_ip') not in INTERNAL_NETWORKS)

def is_hlr_update_attack(features):
    return (
        features.get('f_count_ok_ul_between2lu', 0) > 5 and
        "roaming" in features.get('c_cggt', "").lower() and
        features.get('f_same_cggt_is_hlr_oc', 0) == 0
    )

def is_spoofing_detected(features):
    cggt = features.get('c_cggt', "")
    ip = features.get('src_ip', "")
    if not ip.startswith(("10.", "192.168", "172.16")) and cggt.startswith("CGGT_"):
        return any(k in cggt.lower() for k in ["roaming", "foreign", "external"])
    return False

def is_roaming_bypass(features):
    return "roaming" in features.get('c_cggt', "").lower() and features.get('f_same_cggt_is_hlr_oc', 0) == 0

def is_data_integrity_suspect(features):
    imsi = features.get('c_imsi', "")
    return not imsi or len(imsi) != 15 or not imsi.isdigit()

def is_blacklisted_ip(features):
    ip = features.get("src_ip", "")
    if not ip: return False
    if ip in BLACKLISTED_IPS: return True
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in subnet for subnet in BLACKLISTED_SUBNETS) if not ip_obj.is_private else False
    except ValueError:
        return False

def is_malicious_traffic_pattern(features):
    hex_payload = features.get('hex_payload', "")
    return any(re.search(pat, hex_payload) for pat in ATTACK_PATTERNS.values())

# === FUNCIÓN PRINCIPAL ===
def is_anomalous(features):
    threat_score = 0
    threat_score += 3 if is_send_routing_info_attack(features) else 0
    threat_score += 3 if is_location_tracking_attack(features) else 0
    threat_score += 3 if is_hlr_update_attack(features) else 0
    threat_score += 3 if is_flooding_attack(features) else 0
    threat_score += 3 if is_unauthorized_node(features) else 0
    threat_score += 2 if is_spoofing_detected(features) else 0
    threat_score += 2 if is_roaming_bypass(features) else 0
    threat_score += 2 if is_data_integrity_suspect(features) else 0
    threat_score += 2 if is_malicious_traffic_pattern(features) else 0
    threat_score += 1 if is_blacklisted_ip(features) else 0
    return 1 if threat_score >= 3 else 0
