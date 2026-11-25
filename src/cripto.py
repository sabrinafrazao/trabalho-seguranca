"""Operações criptográficas da ferramenta: SHA-256 e Ed25519.

Todas as funções trabalham sobre os bytes originais dos arquivos (leitura
binária, sem normalização). Erros previsíveis são convertidos em
``ErroSeguranca`` com mensagens compreensíveis para o usuário.
"""

import hashlib
import hmac
import os
import re

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

TAMANHO_ASSINATURA = 64
_BLOCO_LEITURA = 64 * 1024
_REGEX_HASH = re.compile(r"^[0-9a-f]{64}$")


class ErroSeguranca(Exception):
    """Erro de uso ou de entrada (arquivo inexistente, chave inválida etc.)."""


# --------------------------------------------------------------------------
# Utilitários de arquivo
# --------------------------------------------------------------------------

def _validar_arquivo_entrada(caminho, descricao="Arquivo"):
    if not caminho:
        raise ErroSeguranca(f"{descricao}: caminho não informado.")
    if not os.path.exists(caminho):
        raise ErroSeguranca(f"{descricao} não encontrado: '{caminho}'.")
    if os.path.isdir(caminho):
        raise ErroSeguranca(f"{descricao} '{caminho}' é um diretório, não um arquivo.")


def ler_bytes(caminho, descricao="Arquivo"):
    """Lê o conteúdo binário integral de um arquivo, sem qualquer conversão."""
    _validar_arquivo_entrada(caminho, descricao)
    try:
        with open(caminho, "rb") as f:
            return f.read()
    except PermissionError:
        raise ErroSeguranca(f"Sem permissão para ler {descricao.lower()} '{caminho}'.")
    except OSError as e:
        raise ErroSeguranca(f"Não foi possível ler {descricao.lower()} '{caminho}': {e.strerror}.")


def _validar_destino(caminho, descricao):
    if not caminho:
        raise ErroSeguranca(f"{descricao}: caminho não informado.")
    if os.path.isdir(caminho):
        raise ErroSeguranca(f"{descricao} '{caminho}' é um diretório.")
    pasta = os.path.dirname(os.path.abspath(caminho))
    if not os.path.isdir(pasta):
        raise ErroSeguranca(f"Diretório de destino inexistente para {descricao.lower()}: '{pasta}'.")


def _escrever_bytes(caminho, dados, descricao, privado=False):
    _validar_destino(caminho, descricao)
    try:
        if privado:
            # Chave privada: permissões restritas (efetivo em sistemas POSIX).
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
            fd = os.open(caminho, flags, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(dados)
        else:
            with open(caminho, "wb") as f:
                f.write(dados)
    except PermissionError:
        raise ErroSeguranca(f"Sem permissão para gravar {descricao.lower()} '{caminho}'.")
    except OSError as e:
        raise ErroSeguranca(f"Não foi possível gravar {descricao.lower()} '{caminho}': {e.strerror}.")


# --------------------------------------------------------------------------
# R02 / R03 — Hash SHA-256
# --------------------------------------------------------------------------

def calcular_hash(caminho):
    """Retorna o SHA-256 do arquivo em 64 caracteres hexadecimais minúsculos."""
    _validar_arquivo_entrada(caminho)
    h = hashlib.sha256()
    try:
        with open(caminho, "rb") as f:
            for bloco in iter(lambda: f.read(_BLOCO_LEITURA), b""):
                h.update(bloco)
    except PermissionError:
        raise ErroSeguranca(f"Sem permissão para ler o arquivo '{caminho}'.")
    except OSError as e:
        raise ErroSeguranca(f"Não foi possível ler o arquivo '{caminho}': {e.strerror}.")
    return h.hexdigest()


def normalizar_hash_referencia(referencia):
    """Valida o hash de referência (64 hex). Aceita maiúsculas e espaços nas pontas."""
    ref = (referencia or "").strip().lower()
    if not _REGEX_HASH.match(ref):
        raise ErroSeguranca(
            "Hash de referência inválido: esperado SHA-256 com 64 caracteres "
            f"hexadecimais (recebido {len(ref)} caractere(s))."
        )
    return ref


def comparar_hash(caminho, referencia):
    """Retorna (corresponde, hash_calculado). Comparação em tempo constante."""
    ref = normalizar_hash_referencia(referencia)
    calculado = calcular_hash(caminho)
    return hmac.compare_digest(calculado, ref), calculado


# --------------------------------------------------------------------------
# R01 — Geração de chaves Ed25519
# --------------------------------------------------------------------------

def gerar_chaves(caminho_privada, caminho_publica, sobrescrever=False):
    """Gera um par Ed25519: privada em PEM PKCS#8 e pública em PEM SubjectPublicKeyInfo."""
    if caminho_privada and caminho_publica and \
            os.path.abspath(caminho_privada) == os.path.abspath(caminho_publica):
        raise ErroSeguranca("Os caminhos da chave privada e da chave pública devem ser diferentes.")
    for caminho, desc in ((caminho_privada, "Arquivo da chave privada"),
                          (caminho_publica, "Arquivo da chave pública")):
        _validar_destino(caminho, desc)
        if os.path.exists(caminho) and not sobrescrever:
            raise ErroSeguranca(f"{desc} '{caminho}' já existe. Use --force para sobrescrever.")

    privada = Ed25519PrivateKey.generate()
    pem_privada = privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_publica = privada.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _escrever_bytes(caminho_privada, pem_privada, "Arquivo da chave privada", privado=True)
    _escrever_bytes(caminho_publica, pem_publica, "Arquivo da chave pública")


def carregar_chave_privada(caminho):
    dados = ler_bytes(caminho, "Arquivo da chave privada")
    try:
        chave = serialization.load_pem_private_key(dados, password=None)
    except TypeError:
        raise ErroSeguranca(f"A chave privada '{caminho}' está protegida por senha (não suportado).")
    except (ValueError, UnsupportedAlgorithm):
        if b"PUBLIC KEY" in dados:
            raise ErroSeguranca(
                f"'{caminho}' contém uma chave PÚBLICA; o comando exige a chave privada (PEM PKCS#8)."
            )
        raise ErroSeguranca(f"'{caminho}' não é uma chave privada PEM PKCS#8 válida.")
    if not isinstance(chave, Ed25519PrivateKey):
        raise ErroSeguranca(f"A chave privada '{caminho}' não é do tipo Ed25519.")
    return chave


def carregar_chave_publica(caminho):
    dados = ler_bytes(caminho, "Arquivo da chave pública")
    try:
        chave = serialization.load_pem_public_key(dados)
    except (ValueError, UnsupportedAlgorithm):
        if b"PRIVATE KEY" in dados:
            raise ErroSeguranca(
                f"'{caminho}' contém uma chave PRIVADA; o comando exige a chave pública "
                "(PEM SubjectPublicKeyInfo)."
            )
        raise ErroSeguranca(f"'{caminho}' não é uma chave pública PEM SubjectPublicKeyInfo válida.")
    if not isinstance(chave, Ed25519PublicKey):
        raise ErroSeguranca(f"A chave pública '{caminho}' não é do tipo Ed25519.")
    return chave


# --------------------------------------------------------------------------
# R04 / R05 / R06 — Assinatura e verificação Ed25519
# --------------------------------------------------------------------------

def _mesmo_arquivo(a, b):
    if not a or not b:
        return False
    if os.path.exists(a) and os.path.exists(b):
        return os.path.samefile(a, b)
    return os.path.abspath(a) == os.path.abspath(b)


def assinar(caminho_arquivo, caminho_privada, caminho_assinatura, sobrescrever=True):
    """Assina os bytes originais do arquivo (Ed25519 puro, sem pré-hash).

    Recusa gravar a assinatura sobre o próprio arquivo assinado ou sobre a chave
    privada. Com ``sobrescrever=False``, recusa também uma assinatura já existente.
    """
    if _mesmo_arquivo(caminho_assinatura, caminho_arquivo):
        raise ErroSeguranca(
            f"O arquivo de assinatura '{caminho_assinatura}' é o mesmo arquivo que está sendo "
            "assinado; escolha outro destino para não destruir o documento."
        )
    if _mesmo_arquivo(caminho_assinatura, caminho_privada):
        raise ErroSeguranca(
            f"O arquivo de assinatura '{caminho_assinatura}' é o mesmo da chave privada; "
            "escolha outro destino."
        )
    if not sobrescrever and caminho_assinatura and os.path.exists(caminho_assinatura):
        raise ErroSeguranca(
            f"Arquivo de assinatura '{caminho_assinatura}' já existe. Use --force para sobrescrever."
        )
    mensagem = ler_bytes(caminho_arquivo)
    chave = carregar_chave_privada(caminho_privada)
    assinatura = chave.sign(mensagem)
    if len(assinatura) != TAMANHO_ASSINATURA:  # defesa em profundidade
        raise ErroSeguranca("Falha interna: assinatura gerada com tamanho inesperado.")
    _escrever_bytes(caminho_assinatura, assinatura, "Arquivo de assinatura")
    return assinatura


def verificar(caminho_arquivo, caminho_publica, caminho_assinatura):
    """Retorna True somente se a assinatura for válida para o arquivo e a chave."""
    mensagem = ler_bytes(caminho_arquivo)
    chave = carregar_chave_publica(caminho_publica)
    assinatura = ler_bytes(caminho_assinatura, "Arquivo de assinatura")
    if len(assinatura) != TAMANHO_ASSINATURA:
        raise ErroSeguranca(
            f"Arquivo de assinatura '{caminho_assinatura}' tem {len(assinatura)} bytes; "
            f"uma assinatura Ed25519 deve ter exatamente {TAMANHO_ASSINATURA} bytes."
        )
    try:
        chave.verify(assinatura, mensagem)
    except InvalidSignature:
        return False
    return True
