import unittest

from scorer import score_incident


class TestFalsePositiveAnalysis(unittest.TestCase):
    def _fp_for(self, alerts, mitre=None):
        return score_incident(alerts, mitre or [])[2].get("false_positive")

    def test_01_high_confidence_genuine_threat(self):
        alerts = [
            {"severity": "high", "confidence": 90, "src_ip": "185.22.14.8", "event_type": "authentication_failure"},
            {"severity": "high", "confidence": 88, "src_ip": "185.22.14.8", "event_type": "authentication_success"},
            {"severity": "critical", "confidence": 94, "src_ip": "185.22.14.8", "event_type": "privilege_escalation"},
        ]
        fp = self._fp_for(alerts, [{"technique_id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"}])
        self.assertIsNotNone(fp)
        self.assertLess(fp["score"], 40)
        self.assertIn(fp["likelihood"], {"Low", "LOW", "low"})
        self.assertIn("High-quality evidence", fp["factors"])

    def test_02_low_confidence_detection(self):
        alerts = [
            {"severity": "low", "confidence": 15, "src_ip": "10.10.10.10", "event_type": "port_scan"},
        ]
        fp = self._fp_for(alerts)
        self.assertIsNotNone(fp)
        self.assertGreaterEqual(fp["score"], 60)
        self.assertIn(fp["likelihood"], {"High", "HIGH", "high"})
        self.assertIn("Low detection confidence", fp["factors"])

    def test_03_strong_evidence_multiple_indicators(self):
        alerts = [
            {"severity": "medium", "confidence": 70, "src_ip": "203.0.113.99", "event_type": "port_scan"},
            {"severity": "medium", "confidence": 72, "src_ip": "203.0.113.99", "event_type": "authentication_failure"},
            {"severity": "high", "confidence": 80, "src_ip": "203.0.113.99", "event_type": "data_staged"},
        ]
        fp = self._fp_for(alerts, [{"technique_id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"}])
        self.assertIsNotNone(fp)
        self.assertLess(fp["score"], 50)
        self.assertIn("Multiple corroborating indicators", fp["factors"])

    def test_04_weak_single_indicator(self):
        alerts = [{"severity": "low", "confidence": 33, "src_ip": "198.51.100.4", "event_type": "suspicious_script"}]
        fp = self._fp_for(alerts)
        self.assertIsNotNone(fp)
        self.assertGreaterEqual(fp["score"], 55)
        self.assertIn("Single isolated indicator", fp["factors"])

    def test_05_conflicting_evidence(self):
        alerts = [
            {"severity": "medium", "confidence": 64, "src_ip": "198.51.100.7", "event_type": "authentication_failure"},
            {"severity": "medium", "confidence": 68, "src_ip": "198.51.100.7", "event_type": "authentication_success"},
        ]
        fp = self._fp_for(alerts)
        self.assertIsNotNone(fp)
        self.assertIn("Conflicting indicators", fp["factors"])

    def test_06_attachment_high_risk(self):
        alerts = [
            {"severity": "critical", "confidence": 98, "src_ip": "185.22.14.8", "event_type": "data_exfiltration", "indicator": "malware.zip"},
            {"severity": "high", "confidence": 95, "src_ip": "185.22.14.8", "event_type": "data_staged"},
        ]
        fp = self._fp_for(alerts, [{"technique_id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"}])
        self.assertIsNotNone(fp)
        self.assertLess(fp["score"], 35)
        self.assertEqual(fp["likelihood"], "Low")

    def test_07_attachment_low_risk(self):
        alerts = [
            {"severity": "low", "confidence": 29, "src_ip": "10.0.0.6", "event_type": "port_scan"},
            {"severity": "low", "confidence": 31, "src_ip": "10.0.0.6", "event_type": "port_scan"},
        ]
        fp = self._fp_for(alerts)
        self.assertIsNotNone(fp)
        self.assertGreaterEqual(fp["score"], 75)
        self.assertEqual(fp["likelihood"], "High")

    def test_08_insufficient_evidence(self):
        alerts = []
        fp = self._fp_for(alerts)
        self.assertIsNotNone(fp)
        self.assertEqual(fp["score"], 100)
        self.assertEqual(fp["likelihood"], "High")
        self.assertIn("Insufficient evidence", fp["factors"])


if __name__ == "__main__":
    unittest.main()
