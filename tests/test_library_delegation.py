"""The GS728TPP + S3300 HTTP cert uploaders delegate to python-netgear-switch-
library (SyncSwitch.upload_certificate). The library is mocked so these unit
tests need no real switch and no library install."""
import sys
import types


def _fake_library(monkeypatch, recorder, *, raise_exc=None):
    fake = types.ModuleType("netgear_switch")

    class FakeSwitch:
        def __init__(self, model, host, *, http_password=None):
            recorder["model"] = model
            recorder["host"] = host
            recorder["http_password"] = http_password

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def upload_certificate(self, cert_pem, key_pem, *, force=False):
            recorder["force"] = force
            recorder["cert_pem"] = cert_pem
            recorder["key_pem"] = key_pem
            if raise_exc is not None:
                raise raise_exc

    fake.SyncSwitch = FakeSwitch
    reg = types.ModuleType("netgear_switch.registry")
    reg.get_model = lambda key: f"model:{key}"
    monkeypatch.setitem(sys.modules, "netgear_switch", fake)
    monkeypatch.setitem(sys.modules, "netgear_switch.registry", reg)


def _pems(tmp_path):
    cert = tmp_path / "cert.pem"
    cert.write_text("CERT-PEM-CONTENT")
    key = tmp_path / "key.pem"
    key.write_text("KEY-PEM-CONTENT")
    return str(cert), str(key)


def test_gs728tpp_upload_delegates_to_library(mod, tmp_path, monkeypatch):
    rec = {}
    _fake_library(monkeypatch, rec)
    cert, key = _pems(tmp_path)
    u = mod.GS728TPPUpdater("http://10.2.5.10", "admin", "secret")
    assert u.upload_certificate(cert, key) is True
    assert rec["model"] == "model:gs728tpp"
    assert rec["host"] == "10.2.5.10"
    assert rec["http_password"] == "secret"
    assert rec["cert_pem"] == "CERT-PEM-CONTENT"
    assert rec["key_pem"] == "KEY-PEM-CONTENT"


def test_s3300_upload_delegates_to_library(mod, tmp_path, monkeypatch):
    rec = {}
    _fake_library(monkeypatch, rec)
    cert, key = _pems(tmp_path)
    u = mod.S3300Updater("http://10.1.5.14", "admin", "pw2")
    assert u.upload_certificate(cert, key) is True
    assert rec["model"] == "model:gsm7228ps"
    assert rec["host"] == "10.1.5.14"
    assert rec["http_password"] == "pw2"
    assert rec["cert_pem"] == "CERT-PEM-CONTENT"


def test_library_failure_returns_false(mod, tmp_path, monkeypatch):
    rec = {}
    _fake_library(monkeypatch, rec, raise_exc=RuntimeError("switch rejected cert"))
    cert, key = _pems(tmp_path)
    u = mod.GS728TPPUpdater("http://10.2.5.10", "admin", "secret")
    # A library-side failure is surfaced as a clean False, not an exception.
    assert u.upload_certificate(cert, key) is False
