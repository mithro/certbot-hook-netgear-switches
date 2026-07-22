"""Tests for FASTPATH pure functions and constants."""


def test_profiles_present(mod):
    assert set(mod.MODEL_PROFILES) == {"M4300-24X", "M4300-16X", "GSM7252PS"}
    assert mod.MODEL_PROFILES["M4300-16X"]["verify_port"] == 49152
    assert mod.MODEL_PROFILES["GSM7252PS"]["crypto"] == "legacy"
    assert mod.MODEL_PROFILES["M4300-24X"]["secure_server_mode"] == "exec"
    assert mod.MODEL_PROFILES["GSM7252PS"]["secure_server_mode"] == "config"


def test_ssh_opts_legacy_has_group14(mod):
    opts = mod.fastpath_ssh_opts("legacy")
    joined = " ".join(opts)
    assert "diffie-hellman-group14-sha1" in joined
    assert "+ssh-rsa" in joined
    assert "PubkeyAuthentication=no" in joined


def test_ssh_opts_modern_minimal(mod):
    opts = mod.fastpath_ssh_opts("modern")
    joined = " ".join(opts)
    assert "group14-sha1" not in joined
    assert "PubkeyAuthentication=no" in joined


def test_copy_cmd(mod):
    c = mod.fastpath_copy_cmd("scp://switchcert@10.1.5.1:2222/staging/x.pem",
                              "nvram:sslpem-server")
    assert c == "copy scp://switchcert@10.1.5.1:2222/staging/x.pem nvram:sslpem-server"


def test_reload_exec(mod):
    assert mod.secure_server_reload("exec") == [
        "no ip http secure-server", "ip http secure-server"]


def test_reload_config(mod):
    assert mod.secure_server_reload("config") == [
        "configure", "no ip http secure-server", "ip http secure-server", "exit"]
