"""CLI da ferramenta de integridade (SHA-256) e assinatura digital (Ed25519).

Uso:
    python src/seguranca.py hash    <arquivo>
    python src/seguranca.py check   <arquivo> <HASH_REFERENCIA>

Códigos de saída:
    0  sucesso (hash corresponde / operação concluída)
    1  verificação falhou (hash divergente)
    2  erro de uso ou de entrada (arquivo inexistente etc.)
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cripto  # noqa: E402
from cripto import ErroSeguranca  # noqa: E402

SUCESSO = 0
FALHA_VERIFICACAO = 1
ERRO = 2


def cmd_hash(args):
    print(cripto.calcular_hash(args.arquivo))
    return SUCESSO


def cmd_check(args):
    corresponde, calculado = cripto.comparar_hash(args.arquivo, args.hash_referencia)
    print(f"Hash calculado:  {calculado}")
    print(f"Hash referência: {cripto.normalizar_hash_referencia(args.hash_referencia)}")
    if corresponde:
        print("RESULTADO: OK - o hash corresponde à referência (integridade confirmada).")
        return SUCESSO
    print("RESULTADO: FALHA - o hash NÃO corresponde à referência (arquivo divergente).")
    return FALHA_VERIFICACAO


def criar_parser():
    parser = argparse.ArgumentParser(
        prog="seguranca",
        description="Ferramenta de integridade (SHA-256) e assinatura digital (Ed25519).",
        epilog="Códigos de saída: 0 = sucesso, 1 = verificação falhou, 2 = erro.",
    )
    sub = parser.add_subparsers(dest="comando", metavar="COMANDO")
    sub.required = True

    p = sub.add_parser("hash", help="calcula o SHA-256 de um arquivo (R02)")
    p.add_argument("arquivo")
    p.set_defaults(func=cmd_hash)

    p = sub.add_parser("check", help="compara o SHA-256 com um valor de referência (R03)")
    p.add_argument("arquivo")
    p.add_argument("hash_referencia", help="hash SHA-256 de referência (64 hexadecimais)")
    p.set_defaults(func=cmd_check)
    return parser


def main(argv=None):
    # Garante saída UTF-8 nos terminais Windows.
    for fluxo in (sys.stdout, sys.stderr):
        try:
            fluxo.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    args = criar_parser().parse_args(argv)
    try:
        return args.func(args)
    except ErroSeguranca as e:
        print(f"ERRO: {e}", file=sys.stderr)
        return ERRO
    except KeyboardInterrupt:
        print("ERRO: operação interrompida.", file=sys.stderr)
        return ERRO
    except Exception as e:  # nunca reportar sucesso diante de falha inesperada
        print(f"ERRO inesperado: {e}", file=sys.stderr)
        return ERRO


if __name__ == "__main__":
    sys.exit(main())
