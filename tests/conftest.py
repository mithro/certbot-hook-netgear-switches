import importlib.util
import pathlib
import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent

@pytest.fixture(scope="session")
def mod():
    path = _ROOT / "netgear-updater.py"
    spec = importlib.util.spec_from_file_location("netgear_updater", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
