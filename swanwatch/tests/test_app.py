import os, tempfile, unittest
os.environ.setdefault('DASHBOARD_USER','admin')
os.environ.setdefault('DASHBOARD_PASSWORD','test-password')
os.environ.setdefault('FLASK_SECRET_KEY','test-secret')
import app

class AppTests(unittest.TestCase):
    def test_duration(self):
        self.assertEqual(app.duration(3660),'1h 1m')
    def test_parse_sas_empty(self):
        self.assertEqual(app.parse_sas(''),[])
    def test_totp(self):
        secret='JBSWY3DPEHPK3PXP'
        code=app.totp_code(secret,1700000000)
        self.assertEqual(len(code),6)
    def test_health(self):
        c=app.app.test_client()
        self.assertEqual(c.get('/health').status_code,200)

if __name__=='__main__':unittest.main()
