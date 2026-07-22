import pytest

FAST_KW = dict(scp_source="switchcert@10.1.5.1:2222", scp_password="x",
               staging_dir="/var/lib/switchcert/staging")

@pytest.mark.parametrize("model,port", [
    ("M4300-24X", 443), ("M4300-16X", 49152),
    ("M4300-16X-POE", 49152), ("GSM7252PS", 443)])
def test_create_fastpath(mod, model, port):
    u = mod.create_updater("http://10.1.5.13", "admin", "pw", model, **FAST_KW)
    assert isinstance(u, mod.FastpathScpUpdater)
    assert u.profile["verify_port"] == port

def test_create_still_makes_http(mod):
    u = mod.create_updater("http://10.1.5.14", "admin", "pw", "GS728TPP")
    assert isinstance(u, mod.GS728TPPUpdater)
