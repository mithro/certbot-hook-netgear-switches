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

        def upload_certificate_scp(self, *, scp_source, scp_password,
                                   remote_dir, chain=False):
            recorder["scp_source"] = scp_source
            recorder["scp_password"] = scp_password
            recorder["remote_dir"] = remote_dir
            recorder["chain"] = chain
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


def _fastpath(mod, **over):
    kw = dict(
        switch_url="http://10.1.5.13",
        username="admin",
        password="switch-admin-pw",
        model_key="M4300-24X",
        scp_source="switchcert@10.1.5.1:2222",
        scp_password="scp-pw",
        staging_dir="/var/lib/switchcert/staging",
    )
    kw.update(over)
    su, un, pw = kw.pop("switch_url"), kw.pop("username"), kw.pop("password")
    return mod.FastpathScpUpdater(su, un, pw, **kw)


def test_fastpath_upload_delegates_to_library(mod, monkeypatch):
    rec = {}
    _fake_library(monkeypatch, rec)
    u = _fastpath(mod)
    # chain_file present -> chain=True; no PEM files touched (main stages them).
    assert u.upload_certificate("cert", "key", chain_file="/tmp/root.pem") is True
    assert rec["model"] == "model:m4300-24x"
    assert rec["host"] == "10.1.5.13"
    assert rec["http_password"] == "switch-admin-pw"
    assert rec["scp_source"] == "switchcert@10.1.5.1:2222"
    assert rec["scp_password"] == "scp-pw"
    assert rec["remote_dir"] == "/var/lib/switchcert/staging"
    assert rec["chain"] is True


def test_fastpath_upload_no_chain(mod, monkeypatch):
    rec = {}
    _fake_library(monkeypatch, rec)
    u = _fastpath(mod, model_key="GSM7252PS", switch_url="http://10.1.5.22")
    assert u.upload_certificate("cert", "key") is True  # chain_file omitted
    assert rec["model"] == "model:gsm7252ps"
    assert rec["host"] == "10.1.5.22"
    assert rec["chain"] is False


def test_fastpath_model_key_map(mod, monkeypatch):
    for hook_key, lib_key in (("M4300-24X", "m4300-24x"),
                              ("M4300-16X", "m4300-16x"),
                              ("GSM7252PS", "gsm7252ps")):
        rec = {}
        _fake_library(monkeypatch, rec)
        u = _fastpath(mod, model_key=hook_key)
        assert u.upload_certificate("c", "k") is True
        assert rec["model"] == f"model:{lib_key}"


def test_fastpath_library_failure_returns_false(mod, monkeypatch):
    rec = {}
    _fake_library(monkeypatch, rec, raise_exc=RuntimeError("scp copy failed"))
    u = _fastpath(mod)
    assert u.upload_certificate("c", "k", chain_file="/tmp/root.pem") is False


def test_fastpath_login_logout_are_noops(mod, monkeypatch):
    rec = {}
    _fake_library(monkeypatch, rec)
    u = _fastpath(mod)
    assert u.login() is True   # library logs in itself; no SSH here
    assert u.logout() is None
