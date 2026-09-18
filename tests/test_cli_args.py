def test_parser_has_fastpath_flags(mod):
    p = mod.build_parser()
    ns = p.parse_args([
        "--switch-url", "http://10.1.5.13", "--model", "M4300-24X",
        "--password", "pw", "--cert-file", "c", "--key-file", "k",
        "--scp-source", "switchcert@10.1.5.1:2222",
        "--scp-password-file", "/etc/certbot/switchcert.secret",
        "--staging-dir", "/var/lib/switchcert/staging",
        "--cert-name", "sw-netgear-m4300-24x.welland.mithis.com"])
    assert ns.scp_source == "switchcert@10.1.5.1:2222"
    assert ns.cert_name.startswith("sw-netgear-m4300-24x")
