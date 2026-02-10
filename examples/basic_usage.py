from nullsec_payload_wifiaudit.core import WiFiAuditor
a=WiFiAuditor()
nets=[{"ssid":"HomeNet","encryption":"WPA2","signal":-45},{"ssid":"Guest","encryption":"Open","signal":-60}]
r=a.classify_security(nets)
print(f"Total: {r['total']}, Weak: {r['weak']}")
