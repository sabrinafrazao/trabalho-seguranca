import os
import subprocess
import sys

import pytest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(RAIZ, "src", "seguranca.py")
sys.path.insert(0, os.path.join(RAIZ, "src"))


@pytest.fixture
def cli():
    """Executa a CLI real como subprocesso e devolve o CompletedProcess."""
    def _executar(*args):
        return subprocess.run(
            [sys.executable, CLI, *map(str, args)],
            capture_output=True, text=True, encoding="utf-8",
        )
    return _executar


@pytest.fixture
def documento(tmp_path):
    """Documento fictício (sem dados pessoais reais)."""
    caminho = tmp_path / "certificado_ficticio.txt"
    caminho.write_bytes(
        "INSTITUTO FICTÍCIO DE ENSINO\n"
        "Certificamos que FULANO DE TAL (aluno fictício) concluiu o curso\n"
        "de Segurança da Informação, carga horária de 60 horas.\n".encode("utf-8")
    )
    return caminho


@pytest.fixture
def chaves(tmp_path, cli):
    priv, pub = tmp_path / "privada.pem", tmp_path / "publica.pem"
    r = cli("keygen", priv, pub)
    assert r.returncode == 0, r.stderr
    return priv, pub
