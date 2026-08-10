"""Layer separation between the envelope and the backends."""

import ast
from pathlib import Path

import pytest

from nm_secrets import Envelope, SecretConfigurationError
from nm_secrets import envelope as envelope_module


def _imports_backends(source: str) -> bool:
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if "backends" in alias.name.split("."):
                    return True
        elif isinstance(node, ast.ImportFrom):
            module_parts = (node.module or "").split(".")
            if "backends" in module_parts:
                return True
            # from . import backends
            if node.level > 0 and any(a.name == "backends" for a in node.names):
                return True
    return False


def test_envelope_has_no_import_dependency_on_backends():
    source = Path(envelope_module.__file__).read_text(encoding="utf-8")
    assert _imports_backends(source) is False


def test_unknown_backend_id_parses_then_fails_at_dispatch(handler):
    envelope = "ENC[v1:unknownbackend:gen2:c29tZXBheWxvYWQ=]"
    parsed = envelope_module.parse(envelope)
    assert isinstance(parsed, Envelope)
    assert parsed.backend_id == "unknownbackend"
    with pytest.raises(SecretConfigurationError):
        handler.decrypt(envelope, name="db_password")
