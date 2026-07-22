import socket, ssl, subprocess, threading, tempfile, os, pathlib

def _make_selfsigned(tmp):
    key = pathlib.Path(tmp) / "k.pem"
    crt = pathlib.Path(tmp) / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-keyout", key, "-out", crt, "-days", "1", "-nodes",
                    "-subj", "/CN=test.local"], check=True,
                   capture_output=True)
    return str(key), str(crt)

def _serve_once(crt, key, ready, port_holder):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port_holder.append(srv.getsockname()[1]); ready.set()
    conn, _ = srv.accept()
    try:
        ssock = ctx.wrap_socket(conn, server_side=True); ssock.close()
    except ssl.SSLError:
        pass
    srv.close()

def test_verify_matches_served_cert(mod, tmp_path):
    key, crt = _make_selfsigned(tmp_path)
    ready, ports = threading.Event(), []
    t = threading.Thread(target=_serve_once, args=(crt, key, ready, ports))
    t.start(); ready.wait()
    u = mod.NetgearSwitchUpdater(f"http://127.0.0.1", "admin", "pw")
    ok = u.verify_certificate(crt, https_port=ports[0])
    t.join()
    assert ok is True

def test_verify_rejects_wrong_cert(mod, tmp_path):
    d1 = tmp_path / "a"; d1.mkdir()
    d2 = tmp_path / "b"; d2.mkdir()
    key1, crt1 = _make_selfsigned(d1)          # cert we expect
    key2, crt2 = _make_selfsigned(d2)          # different cert the server serves
    ready, ports = threading.Event(), []
    t = threading.Thread(target=_serve_once, args=(crt2, key2, ready, ports))
    t.start(); ready.wait()
    u = mod.NetgearSwitchUpdater("http://127.0.0.1", "admin", "pw")
    ok = u.verify_certificate(crt1, https_port=ports[0])   # expects crt1, served crt2
    t.join()
    assert ok is False
