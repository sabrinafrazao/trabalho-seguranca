"""CLI da ferramenta de integridade (SHA-256) e assinatura digital (Ed25519).

Uso:
    python src/seguranca.py keygen  <chave_privada.pem> <chave_publica.pem> [--force]
    python src/seguranca.py hash    <arquivo>
    python src/seguranca.py check   <arquivo> <HASH_REFERENCIA>
    python src/seguranca.py sign    <arquivo> <chave_privada.pem> <assinatura.sig> [--force]
    python src/seguranca.py verify  <arquivo> <chave_publica.pem> <assinatura.sig>

Códigos de saída:
    0  sucesso (hash corresponde / assinatura válida / operação concluída)
    1  verificação falhou (hash divergente / assinatura inválida)
    2  erro de uso ou de entrada (arquivo inexistente, chave incompatível etc.)
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


def cmd_keygen(args):
    cripto.gerar_chaves(args.chave_privada, args.chave_publica, sobrescrever=args.force)
    print("Par de chaves Ed25519 gerado com sucesso.")
    print(f"  Chave privada (PEM PKCS#8):               {args.chave_privada}")
    print(f"  Chave pública (PEM SubjectPublicKeyInfo): {args.chave_publica}")
    print("ATENÇÃO: mantenha a chave privada em sigilo.")
    return SUCESSO


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


def cmd_sign(args):
    cripto.assinar(args.arquivo, args.chave_privada, args.assinatura, sobrescrever=args.force)
    print(f"Arquivo assinado com sucesso. Assinatura (64 bytes) gravada em: {args.assinatura}")
    return SUCESSO


def cmd_verify(args):
    if cripto.verificar(args.arquivo, args.chave_publica, args.assinatura):
        print("RESULTADO: ASSINATURA VÁLIDA - o arquivo é íntegro e foi assinado "
              "pela chave privada correspondente.")
        return SUCESSO
    print("RESULTADO: ASSINATURA INVÁLIDA - o arquivo foi alterado, a assinatura não "
          "corresponde ou a chave pública não é a do signatário.")
    return FALHA_VERIFICACAO


def criar_parser():
    parser = argparse.ArgumentParser(
        prog="seguranca",
        description="Ferramenta de integridade (SHA-256) e assinatura digital (Ed25519).",
        epilog="Códigos de saída: 0 = sucesso, 1 = verificação falhou, 2 = erro.",
    )
    sub = parser.add_subparsers(dest="comando", metavar="COMANDO")
    sub.required = True

    p = sub.add_parser("keygen", help="gera um par de chaves Ed25519 (R01)")
    p.add_argument("chave_privada", help="arquivo de saída da chave privada (PEM PKCS#8)")
    p.add_argument("chave_publica", help="arquivo de saída da chave pública (PEM SPKI)")
    p.add_argument("--force", action="store_true", help="sobrescreve arquivos existentes")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("hash", help="calcula o SHA-256 de um arquivo (R02)")
    p.add_argument("arquivo")
    p.set_defaults(func=cmd_hash)

    p = sub.add_parser("check", help="compara o SHA-256 com um valor de referência (R03)")
    p.add_argument("arquivo")
    p.add_argument("hash_referencia", help="hash SHA-256 de referência (64 hexadecimais)")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("sign", help="assina um arquivo com a chave privada (R04)")
    p.add_argument("arquivo")
    p.add_argument("chave_privada", help="chave privada Ed25519 (PEM PKCS#8)")
    p.add_argument("assinatura", help="arquivo de saída da assinatura (64 bytes)")
    p.add_argument("--force", action="store_true", help="sobrescreve a assinatura se já existir")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify", help="verifica uma assinatura com a chave pública (R05/R06)")
    p.add_argument("arquivo")
    p.add_argument("chave_publica", help="chave pública Ed25519 (PEM SPKI)")
    p.add_argument("assinatura", help="arquivo de assinatura (64 bytes)")
    p.set_defaults(func=cmd_verify)
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
