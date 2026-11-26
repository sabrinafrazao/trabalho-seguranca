"""Testes mínimos exigidos pelo enunciado (TI01 a TI06), executados pela CLI."""

import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def test_TI01_calcular_sha256(cli, documento):
    esperado = hashlib.sha256(documento.read_bytes()).hexdigest()
    r = cli("hash", documento)
    assert r.returncode == 0
    saida = r.stdout.strip()
    assert saida == esperado
    assert len(saida) == 64 and saida == saida.lower()


def test_TI02_arquivo_modificado_diverge_do_hash_original(cli, documento):
    original = cli("hash", documento).stdout.strip()
    assert cli("check", documento, original).returncode == 0

    documento.write_bytes(documento.read_bytes().replace(b"60 horas", b"600 horas"))
    r = cli("check", documento, original)
    assert r.returncode != 0
    assert "NÃO corresponde" in r.stdout


def test_TI03_gerar_par_de_chaves_pem_validas(chaves):
    priv, pub = chaves
    dados_priv, dados_pub = priv.read_bytes(), pub.read_bytes()
    assert dados_priv.startswith(b"-----BEGIN PRIVATE KEY-----")   # PKCS#8
    assert dados_pub.startswith(b"-----BEGIN PUBLIC KEY-----")     # SubjectPublicKeyInfo
    chave_priv = serialization.load_pem_private_key(dados_priv, password=None)
    chave_pub = serialization.load_pem_public_key(dados_pub)
    assert isinstance(chave_priv, Ed25519PrivateKey)
    assert isinstance(chave_pub, Ed25519PublicKey)
    # A pública gerada corresponde à privada gerada.
    raw = serialization.Encoding.Raw, serialization.PublicFormat.Raw
    assert chave_priv.public_key().public_bytes(*raw) == chave_pub.public_bytes(*raw)


def test_TI04_assinar_e_verificar_original(cli, documento, chaves, tmp_path):
    priv, pub = chaves
    sig = tmp_path / "assinatura.sig"
    r = cli("sign", documento, priv, sig)
    assert r.returncode == 0, r.stderr
    assert len(sig.read_bytes()) == 64
    r = cli("verify", documento, pub, sig)
    assert r.returncode == 0
    assert "ASSINATURA VÁLIDA" in r.stdout


def test_TI05_alterar_arquivo_apos_assinatura(cli, documento, chaves, tmp_path):
    priv, pub = chaves
    sig = tmp_path / "assinatura.sig"
    assert cli("sign", documento, priv, sig).returncode == 0
    with open(documento, "ab") as f:
        f.write(b" ")  # alteração mínima: um único byte
    r = cli("verify", documento, pub, sig)
    assert r.returncode != 0
    assert "ASSINATURA INVÁLIDA" in r.stdout
    assert "ASSINATURA VÁLIDA" not in r.stdout


def test_TI06_verificar_com_outra_chave_publica(cli, documento, chaves, tmp_path):
    priv, _ = chaves
    outra_priv, outra_pub = tmp_path / "outra_priv.pem", tmp_path / "outra_pub.pem"
    assert cli("keygen", outra_priv, outra_pub).returncode == 0
    sig = tmp_path / "assinatura.sig"
    assert cli("sign", documento, priv, sig).returncode == 0
    r = cli("verify", documento, outra_pub, sig)
    assert r.returncode != 0
    assert "ASSINATURA INVÁLIDA" in r.stdout
