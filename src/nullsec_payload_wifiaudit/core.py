"""WiFi Audit Core"""
import subprocess,json,re,os,time

class WiFiAuditor:
    def scan_networks(self,interface="wlan1mon"):
        try:
            result=subprocess.check_output(["iwlist",interface,"scan"],text=True,timeout=30)
            networks=[]
            for cell in result.split("Cell ")[1:]:
                net={}
                m=re.search(r'ESSID:"([^"]*)"',cell)
                if m: net["ssid"]=m.group(1)
                m=re.search(r"Address: ([0-9A-F:]+)",cell)
                if m: net["bssid"]=m.group(1)
                m=re.search(r"Signal level[=:](-?\d+)",cell)
                if m: net["signal"]=int(m.group(1))
                enc="Open"
                if "WPA2" in cell: enc="WPA2"
                elif "WPA" in cell: enc="WPA"
                elif "WEP" in cell: enc="WEP"
                net["encryption"]=enc
                if net.get("ssid"): networks.append(net)
            return networks
        except: return []
    
    def classify_security(self,networks):
        classified={"WPA2":[],"WPA":[],"WEP":[],"Open":[]}
        for net in networks:
            enc=net.get("encryption","Unknown")
            if enc in classified: classified[enc].append(net)
        return {"total":len(networks),"by_security":classified,
                "weak":len(classified.get("WEP",[]))+len(classified.get("Open",[]))}
    
    def generate_report(self,scan_results):
        report={"timestamp":time.strftime("%Y-%m-%d %H:%M:%S"),"networks":len(scan_results)}
        if scan_results:
            signals=[n.get("signal",0) for n in scan_results if n.get("signal")]
            if signals: report["avg_signal"]=sum(signals)//len(signals)
        return report
