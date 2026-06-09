import ssl
import socket
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

class SSLAnalyzer:
    def __init__(self, hostname, port=443, timeout=10):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

    def analyze(self):
        result = {
            "hostname": self.hostname,
            "port": self.port,
            "valid": False,
            "subject": {},
            "issuer": {},
            "version": "",
            "serial_number": "",
            "not_before": "",
            "not_after": "",
            "is_expired": None,
            "days_remaining": None,
            "sans": [],
            "cipher": "",
            "fingerprint_sha256": "",
            "errors": []
        }
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    if not cert:
                        result["errors"].append("No certificate returned")
                        return result
                    cert_obj = x509.load_der_x509_certificate(cert, default_backend())
                    result["valid"] = True
                    result["version"] = str(cert_obj.version.value)
                    result["serial_number"] = str(cert_obj.serial_number)
                    try:
                        result["fingerprint_sha256"] = cert_obj.fingerprint(hashes.SHA256()).hex()
                    except Exception:
                        pass
                    try:
                        result["subject"] = {a.oid._name: str(a.value) for a in cert_obj.subject}
                    except Exception:
                        pass
                    try:
                        result["issuer"] = {a.oid._name: str(a.value) for a in cert_obj.issuer}
                    except Exception:
                        pass
                    nb = getattr(cert_obj, "not_valid_before_utc", None) or getattr(cert_obj, "not_valid_before", None)
                    na = getattr(cert_obj, "not_valid_after_utc", None) or getattr(cert_obj, "not_valid_after", None)
                    if nb:
                        result["not_before"] = str(nb)
                    if na:
                        result["not_after"] = str(na)
                    now = datetime.datetime.now(datetime.timezone.utc)
                    if na:
                        if na < now:
                            result["is_expired"] = True
                        elif nb and nb > now:
                            result["is_expired"] = "not_yet_valid"
                        else:
                            result["is_expired"] = False
                        delta = na - now
                        result["days_remaining"] = delta.days
                    try:
                        ext = cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        result["sans"] = list(ext.value.get_values_for_type(x509.DNSName))
                    except Exception:
                        pass
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        result["cipher"] = cipher_info[0]
        except ImportError as e:
            result["errors"].append(f"Import error: {e}")
        except Exception as e:
            result["errors"].append(str(e))
        return result
