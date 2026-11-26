"""Testes adicionais: vetores oficiais, contrato de interoperabilidade e erros."""

import os
import shutil
import subprocess

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

# --------------------------------------------------------------------------
# Vetores de teste oficiais
# --------------------------------------------------------------------------

def test_sha256_vetor_fips_abc(cli, tmp_path):
    arq = tmp_path / "abc.txt"
    arq.write_bytes(b"abc")
    r = cli("hash", arq)
    assert r.stdout.strip() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_sha256_arquivo_vazio(cli, tmp_path):
    arq = tmp_path / "vazio.bin"
    arq.write_bytes(b"")
    r = cli("hash", arq)
    assert r.stdout.strip() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_ed25519_vetor_rfc8032_teste1(cli, tmp_path):
    """RFC 8032, seção 7.1, TEST 1: mensagem vazia. Ed25519 é determinístico."""
    semente = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    esperada = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
        "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    priv = tmp_path / "rfc_priv.pem"
    priv.write_bytes(Ed25519PrivateKey.from_private_bytes(semente).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    msg, sig = tmp_path / "vazio.bin", tmp_path / "rfc.sig"
    msg.write_bytes(b"")
    assert cli("sign", msg, priv, sig).returncode == 0
    assert sig.read_bytes() == esperada


def test_leitura_binaria_sem_normalizacao(cli, tmp_path):
    """CRLF e LF devem produzir hashes diferentes (nenhuma conversão de bytes)."""
    lf, crlf = tmp_path / "lf.txt", tmp_path / "crlf.txt"
    lf.write_bytes(b"linha1\nlinha2\n")
    crlf.write_bytes(b"linha1\r\nlinha2\r\n")
    assert cli("hash", lf).stdout != cli("hash", crlf).stdout


def test_arquivo_binario_qualquer(cli, chaves, tmp_path):
    priv, pub = chaves
    arq, sig = tmp_path / "dados.bin", tmp_path / "dados.sig"
    arq.write_bytes(bytes(range(256)) * 1000)
    assert cli("sign", arq, priv, sig).returncode == 0
    assert cli("verify", arq, pub, sig).returncode == 0


# --------------------------------------------------------------------------
# Comparação de hash
# --------------------------------------------------------------------------

def test_check_aceita_referencia_maiuscula(cli, documento):
    h = cli("hash", documento).stdout.strip()
    assert cli("check", documento, h.upper()).returncode == 0


def test_check_hash_referencia_malformado(cli, documento):
    r = cli("check", documento, "abc123")
    assert r.returncode == 2
    assert "Hash de referência inválido" in r.stderr


def test_check_hash_diferente(cli, documento):
    r = cli("check", documento, "0" * 64)
    assert r.returncode == 1
    assert "FALHA" in r.stdout


# --------------------------------------------------------------------------
# Adulterações da assinatura (R06)
# --------------------------------------------------------------------------

def test_assinatura_com_um_bit_alterado(cli, documento, chaves, tmp_path):
    priv, pub = chaves
    sig = tmp_path / "a.sig"
    cli("sign", documento, priv, sig)
    dados = bytearray(sig.read_bytes())
    dados[10] ^= 0x01
    sig.write_bytes(bytes(dados))
    r = cli("verify", documento, pub, sig)
    assert r.returncode == 1
    assert "ASSINATURA INVÁLIDA" in r.stdout


def test_assinatura_de_outro_documento(cli, documento, chaves, tmp_path):
    priv, pub = chaves
    outro, sig = tmp_path / "outro.txt", tmp_path / "outro.sig"
    outro.write_bytes(b"declaracao ficticia")
    cli("sign", outro, priv, sig)
    assert cli("verify", documento, pub, sig).returncode == 1


@pytest.mark.parametrize("tamanho", [0, 63, 65, 128])
def test_assinatura_com_tamanho_invalido(cli, documento, chaves, tmp_path, tamanho):
    _, pub = chaves
    sig = tmp_path / "ruim.sig"
    sig.write_bytes(b"\x00" * tamanho)
    r = cli("verify", documento, pub, sig)
    assert r.returncode == 2
    assert "64 bytes" in r.stderr


# --------------------------------------------------------------------------
# Tratamento de erros comuns
# --------------------------------------------------------------------------

@pytest.mark.parametrize("comando", ["hash", "check", "sign", "verify"])
def test_arquivo_inexistente(cli, chaves, tmp_path, comando):
    priv, pub = chaves
    inexistente = tmp_path / "nao_existe.txt"
    args = {
        "hash": [inexistente],
        "check": [inexistente, "0" * 64],
        "sign": [inexistente, priv, tmp_path / "x.sig"],
        "verify": [inexistente, pub, tmp_path / "x.sig"],
    }[comando]
    r = cli(comando, *args)
    assert r.returncode == 2
    assert "não encontrado" in r.stderr


def test_caminho_e_diretorio(cli, tmp_path):
    r = cli("hash", tmp_path)
    assert r.returncode == 2
    assert "diretório" in r.stderr


def test_keygen_diretorio_destino_inexistente(cli, tmp_path):
    r = cli("keygen", tmp_path / "nao" / "priv.pem", tmp_path / "pub.pem")
    assert r.returncode == 2
    assert "inexistente" in r.stderr


def test_keygen_nao_sobrescreve_sem_force(cli, chaves):
    priv, pub = chaves
    conteudo = priv.read_bytes()
    r = cli("keygen", priv, pub)
    assert r.returncode == 2
    assert "já existe" in r.stderr
    assert priv.read_bytes() == conteudo
    assert cli("keygen", priv, pub, "--force").returncode == 0
    assert priv.read_bytes() != conteudo


def test_keygen_mesmo_caminho(cli, tmp_path):
    r = cli("keygen", tmp_path / "k.pem", tmp_path / "k.pem")
    assert r.returncode == 2


def test_sign_com_chave_publica_no_lugar_da_privada(cli, documento, chaves, tmp_path):
    _, pub = chaves
    r = cli("sign", documento, pub, tmp_path / "a.sig")
    assert r.returncode == 2
    assert "chave PÚBLICA" in r.stderr


def test_verify_com_chave_privada_no_lugar_da_publica(cli, documento, chaves, tmp_path):
    priv, _ = chaves
    sig = tmp_path / "a.sig"
    cli("sign", documento, priv, sig)
    r = cli("verify", documento, priv, sig)
    assert r.returncode == 2
    assert "chave PRIVADA" in r.stderr


def test_chave_de_outro_algoritmo_rsa(cli, documento, tmp_path):
    rsa = generate_private_key(public_exponent=65537, key_size=2048)
    priv = tmp_path / "rsa.pem"
    priv.write_bytes(rsa.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    r = cli("sign", documento, priv, tmp_path / "a.sig")
    assert r.returncode == 2
    assert "não é do tipo Ed25519" in r.stderr


def test_chave_corrompida(cli, documento, tmp_path):
    pub = tmp_path / "lixo.pem"
    pub.write_text("isto não é uma chave")
    sig = tmp_path / "a.sig"
    sig.write_bytes(b"\x00" * 64)
    r = cli("verify", documento, pub, sig)
    assert r.returncode == 2
    assert "não é uma chave pública" in r.stderr


def test_comando_desconhecido_ou_argumentos_faltando(cli):
    assert cli("decrypt", "x").returncode != 0
    assert cli("verify", "so_um_arg").returncode != 0


# --------------------------------------------------------------------------
# Interoperabilidade com OpenSSL (executado somente se disponível)
# --------------------------------------------------------------------------

def _localizar_openssl():

    encontrado = shutil.which("openssl")
    if encontrado:
        return encontrado
    git = shutil.which("git")
    if git:
        base_git = os.path.dirname(os.path.dirname(os.path.realpath(git)))
        for sub in ("usr/bin", "mingw64/bin", "../usr/bin", "../mingw64/bin"):
            candidato = os.path.normpath(os.path.join(base_git, sub, "openssl.exe"))
            if os.path.isfile(candidato):
                return candidato
    return None


OPENSSL = _localizar_openssl()


@pytest.mark.skipif(OPENSSL is None, reason="openssl não instalado")
def test_interoperabilidade_openssl(cli, documento, chaves, tmp_path):
    openssl = OPENSSL
    priv, pub = chaves
    # 1) assinatura da ferramenta verificada pelo OpenSSL
    sig = tmp_path / "nossa.sig"
    cli("sign", documento, priv, sig)
    r = subprocess.run([openssl, "pkeyutl", "-verify", "-pubin", "-inkey", str(pub),
                        "-rawin", "-in", str(documento), "-sigfile", str(sig)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    # 2) chave e assinatura geradas pelo OpenSSL verificadas pela ferramenta
    ossl_priv, ossl_pub, ossl_sig = (tmp_path / n for n in ("o.pem", "o_pub.pem", "o.sig"))
    subprocess.run([openssl, "genpkey", "-algorithm", "ed25519", "-out", str(ossl_priv)],
                   check=True, capture_output=True)
    subprocess.run([openssl, "pkey", "-in", str(ossl_priv), "-pubout", "-out", str(ossl_pub)],
                   check=True, capture_output=True)
    subprocess.run([openssl, "pkeyutl", "-sign", "-inkey", str(ossl_priv), "-rawin",
                    "-in", str(documento), "-out", str(ossl_sig)], check=True, capture_output=True)
    assert cli("verify", documento, ossl_pub, ossl_sig).returncode == 0
