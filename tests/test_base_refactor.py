def test_base_has_no_session(mod):
    u = mod.NetgearSwitchUpdater("http://x", "admin", "pw")
    assert not hasattr(u, "session")

def test_http_updater_has_session(mod):
    u = mod.GS728TPPUpdater("http://x", "admin", "pw")
    assert isinstance(u, mod.HttpUpdater)
    assert u.session is not None
    assert u.session.verify is False

def test_verify_certificate_accepts_port(mod):
    import inspect
    sig = inspect.signature(mod.NetgearSwitchUpdater.verify_certificate)
    assert "https_port" in sig.parameters
    assert sig.parameters["https_port"].default == 443
