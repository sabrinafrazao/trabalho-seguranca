"""Operações criptográficas da ferramenta: SHA-256 e Ed25519.

Todas as funções trabalham sobre os bytes originais dos arquivos (leitura
binária, sem normalização). Erros previsíveis são convertidos em
``ErroSeguranca`` com mensagens compreensíveis para o usuário.
"""

import hashlib
import hmac
import os
import re

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
