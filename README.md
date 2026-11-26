# Ferramenta de Integridade e Assinatura Digital (SHA-256 + Ed25519)

Ferramenta de linha de comando (CLI) para **calcular e comparar hashes SHA-256**, **gerar pares de chaves Ed25519**, **assinar arquivos** e **verificar assinaturas digitais**. Foi desenvolvida para o Trabalho Prático, Etapa 1, da disciplina de Segurança da Informação.

O relatório técnico está em [`docs/RELATORIO_TECNICO.md`](docs/RELATORIO_TECNICO.md).

---

## 1. Requisitos

- **Python 3.9 ou superior** (testado com Python 3.14 no Windows 11)
- Biblioteca [`cryptography`](https://cryptography.io) (≥ 42), baseada em OpenSSL
- `pytest` (somente para rodar os testes)

## 2. Instalação

```shell
git clone https://github.com/sabrinafrazao/trabalho-seguranca.git
cd trabalho-seguranca

# (opcional, recomendado) ambiente virtual
python -m venv .venv
# Windows:      .venv\Scripts\activate
# Linux/macOS:  source .venv/bin/activate

python -m pip install -r requirements.txt
```

> No Linux/macOS, use `python3` no lugar de `python` se for o caso.

## 3. Forma exata de execução

O comando lógico `seguranca` do enunciado corresponde a:

```shell
python src/seguranca.py <comando> <argumentos...>
```

A ordem dos argumentos é exatamente a do enunciado:

| Comando | Sintaxe | Requisito |
|---------|---------|-----------|
| `keygen` | `python src/seguranca.py keygen chave_privada.pem chave_publica.pem [--force]` | R01 |
| `hash`   | `python src/seguranca.py hash documento.txt` | R02 |
| `check`  | `python src/seguranca.py check documento.txt HASH_REFERENCIA` | R03 |
| `sign`   | `python src/seguranca.py sign documento.txt chave_privada.pem assinatura.sig [--force]` | R04 |
| `verify` | `python src/seguranca.py verify documento.txt chave_publica.pem assinatura.sig` | R05 / R06 |

Ajuda: `python src/seguranca.py --help` ou `python src/seguranca.py <comando> --help`.

### Códigos de saída

| Código | Significado |
|:------:|-------------|
| `0` | Sucesso: operação concluída, hash corresponde ou assinatura **válida** |
| `1` | Verificação falhou: hash **divergente** ou assinatura **inválida** |
| `2` | Erro: arquivo inexistente, caminho inválido, chave incompatível, assinatura malformada, argumentos incorretos |

`check` e `verify` só retornam `0` quando a verificação de fato é bem-sucedida. Qualquer erro ou exceção inesperada resulta em código diferente de zero.

## 4. Contrato de interoperabilidade

| Item | Formato adotado |
|------|-----------------|
| Hash | SHA-256, 64 caracteres hexadecimais **minúsculos** (no `check`, a referência também é aceita em maiúsculas) |
| Assinatura | Ed25519 **puro** (RFC 8032), aplicado diretamente aos bytes originais do arquivo, **sem pré-hash** |
| Chave pública | PEM `-----BEGIN PUBLIC KEY-----` (SubjectPublicKeyInfo) |
| Chave privada | PEM `-----BEGIN PRIVATE KEY-----` (PKCS#8, sem senha) |
| Arquivo de assinatura | binário com **exatamente 64 bytes** |
| Leitura de arquivos | binária (`rb`), sem conversão de codificação ou de quebras de linha |

A compatibilidade com o OpenSSL é verificada nos testes automatizados (`test_interoperabilidade_openssl`): o OpenSSL valida assinaturas geradas por esta ferramenta, e a ferramenta valida chaves e assinaturas geradas pelo OpenSSL.

## 5. Exemplos de utilização

```shell
# R01 - gerar o par de chaves
python src/seguranca.py keygen privada.pem publica.pem

# R02 - calcular o hash
python src/seguranca.py hash exemplos/certificado_ficticio.txt
# a100c4f56d1d51e67578a010cd0146785bb167dbbc7546190875a9ad99166518

# R03 - comparar com o hash de referência
python src/seguranca.py check exemplos/certificado_ficticio.txt a100c4f56d1d51e67578a010cd0146785bb167dbbc7546190875a9ad99166518
# RESULTADO: OK - o hash corresponde à referência (integridade confirmada).

# R04 - assinar
python src/seguranca.py sign exemplos/certificado_ficticio.txt privada.pem certificado.sig

# R05 - verificar
python src/seguranca.py verify exemplos/certificado_ficticio.txt publica.pem certificado.sig
# RESULTADO: ASSINATURA VÁLIDA - ...
```

### Arquivos prontos em `exemplos/`

| Arquivo | Conteúdo |
|---------|----------|
| `certificado_ficticio.txt` | documento fictício, sem dados pessoais reais |
| `certificado_ficticio.sha256` | hash SHA-256 de referência do documento |
| `certificado_ficticio.sig` | assinatura Ed25519 (64 bytes) do documento |
| `chave_publica_exemplo.pem` | chave pública correspondente à assinatura |
| `demo.ps1` / `demo.sh` | demonstração completa: gera chaves, assina, adultera e verifica |

A chave privada usada para gerar `certificado_ficticio.sig` foi descartada e **não** está no repositório. Para verificar o exemplo:

```shell
python src/seguranca.py verify exemplos/certificado_ficticio.txt exemplos/chave_publica_exemplo.pem exemplos/certificado_ficticio.sig
```

Demonstração completa:

```shell
# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File exemplos\demo.ps1
# Linux/macOS/Git Bash
sh exemplos/demo.sh
```

## 6. Testes automatizados

```shell
python -m pytest -v
```

São 34 testes, divididos em dois arquivos:

- `tests/test_minimos.py`: os testes mínimos **TI01 a TI06** do enunciado, executados pela CLI real (subprocesso).
- `tests/test_adicionais.py`: vetores oficiais (SHA-256 FIPS 180 e Ed25519 RFC 8032), leitura binária, adulteração de 1 bit na assinatura, tamanho de assinatura inválido, arquivos inexistentes, diretórios, chave pública/privada trocadas, chave RSA, chave corrompida, proteção contra sobrescrita e interoperabilidade com o OpenSSL (o teste é ignorado se o `openssl` não estiver instalado).

As evidências das execuções estão em [`docs/evidencias/`](docs/evidencias/).

## 7. Estrutura do repositório

```text
trabalho-seguranca/
├── README.md
├── requirements.txt          # dependências
├── src/
│   ├── seguranca.py          # CLI (argparse, mensagens, códigos de saída)
│   └── cripto.py             # operações criptográficas e validações
├── tests/
│   ├── conftest.py
│   ├── test_minimos.py       # TI01–TI06
│   └── test_adicionais.py
├── exemplos/
└── docs/
    ├── RELATORIO_TECNICO.md
    └── evidencias/
```

## 8. Avisos de segurança

- A chave privada é gravada **sem senha**, como exige o contrato (PKCS#8 sem cifragem). Proteja o arquivo e nunca o publique. O `.gitignore` bloqueia arquivos `*privada*.pem` e `*private*.pem`.
- O `keygen` e o `sign` não sobrescrevem arquivos existentes, a menos que se use `--force`.
- O `sign` recusa gravar a assinatura sobre o próprio documento assinado ou sobre a chave privada, para não destruir esses arquivos.
- Esta é uma ferramenta didática. Veja as limitações na seção 5 do relatório técnico.
