import os, stat, pathlib

def test_stage_server_pem(mod, tmp_path):
    cert = tmp_path / "c.pem"; cert.write_text("CERT\n")
    key = tmp_path / "k.pem"; key.write_text("KEY\n")
    staging = tmp_path / "staging"; staging.mkdir()
    srv, root = mod.stage_server_pem(str(staging), "m4300-24x-10.1.5.13",
                                     str(cert), str(key))
    assert pathlib.Path(srv).read_text() == "CERT\nKEY\n"
    assert root is None
    mode = stat.S_IMODE(os.stat(srv).st_mode)
    assert mode == 0o400

def test_stage_with_chain(mod, tmp_path):
    for n in ("c", "k", "ch"):
        (tmp_path / f"{n}.pem").write_text(n.upper() + "\n")
    staging = tmp_path / "s"; staging.mkdir()
    srv, root = mod.stage_server_pem(str(staging), "x",
                                     str(tmp_path/"c.pem"), str(tmp_path/"k.pem"),
                                     str(tmp_path/"ch.pem"))
    assert pathlib.Path(root).read_text() == "CH\n"
    mod.cleanup_staging([srv, root])
    assert not pathlib.Path(srv).exists()
