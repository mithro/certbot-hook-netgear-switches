"""Tests for FASTPATH pure functions and constants."""


def test_profiles_present(mod):
    assert set(mod.MODEL_PROFILES) == {"M4300-24X", "M4300-16X", "GSM7252PS"}
    assert mod.MODEL_PROFILES["M4300-16X"]["verify_port"] == 49152
    assert mod.MODEL_PROFILES["GSM7252PS"]["crypto"] == "legacy"
    assert mod.MODEL_PROFILES["M4300-24X"]["secure_server_mode"] == "exec"
    assert mod.MODEL_PROFILES["GSM7252PS"]["secure_server_mode"] == "exec"
    assert mod.MODEL_PROFILES["GSM7252PS"]["writemem_stuff"] is True
    assert mod.MODEL_PROFILES["M4300-24X"]["writemem_stuff"] is False


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


def test_fastpath_construct(mod):
    u = mod.FastpathScpUpdater(
        "http://10.1.5.22", "admin", "pw",
        model_key="GSM7252PS",
        scp_source="switchcert@10.1.5.1:2222",
        scp_password="s3cr3t",
        staging_dir="/var/lib/switchcert/staging",
    )
    assert u.profile["verify_port"] == 443
    assert u.host == "10.1.5.22"


def test_fastpath_reboot_refused(mod):
    u = mod.FastpathScpUpdater(
        "http://10.1.5.13", "admin", "pw", model_key="M4300-24X",
        scp_source="switchcert@10.1.5.1:2222", scp_password="x",
        staging_dir="/tmp")
    import pytest
    with pytest.raises(RuntimeError):
        u.reboot()


def test_fastpath_source_url(mod):
    u = mod.FastpathScpUpdater(
        "http://10.1.5.13", "admin", "pw", model_key="M4300-24X",
        scp_source="switchcert@10.1.5.1:2222", scp_password="x",
        staging_dir="/var/lib/switchcert/staging")
    assert u._source_url("abc-server.pem") == \
        "scp://switchcert@10.1.5.1:2222/var/lib/switchcert/staging/abc-server.pem"


def test_fastpath_base_has_no_dots(mod):
    # FASTPATH copy-scp rejects dots in the staged filename; base must sanitise
    # the dotted host/IP so the filename is dot-free (except the .pem suffix).
    u = mod.FastpathScpUpdater(
        "http://10.1.5.22", "admin", "pw", model_key="GSM7252PS",
        scp_source="switchcert@10.1.5.2", scp_password="x",
        staging_dir="/var/lib/switchcert/staging")
    assert u.base == "10-1-5-22"
    assert "." not in u.base
