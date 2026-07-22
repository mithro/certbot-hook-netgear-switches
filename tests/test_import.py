def test_module_loads(mod):
    assert hasattr(mod, "NetgearSwitchUpdater")
    assert hasattr(mod, "create_updater")
