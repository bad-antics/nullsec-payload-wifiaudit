import unittest,sys,os
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"..","src"))
from nullsec_payload_wifiaudit.core import WiFiAuditor

class TestAuditor(unittest.TestCase):
    def test_classify(self):
        a=WiFiAuditor()
        nets=[{"ssid":"A","encryption":"WPA2"},{"ssid":"B","encryption":"Open"},{"ssid":"C","encryption":"WEP"}]
        r=a.classify_security(nets)
        self.assertEqual(r["weak"],2)
        self.assertEqual(r["total"],3)
    def test_report(self):
        a=WiFiAuditor()
        r=a.generate_report([{"ssid":"Test","signal":-50}])
        self.assertEqual(r["networks"],1)

if __name__=="__main__": unittest.main()
