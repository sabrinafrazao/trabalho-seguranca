# Relatório Técnico Simplificado: Trabalho Prático, Etapa 1

## 7.1 Identificação

| Item | Informação |
|------|------------|
| Integrantes | Sabrina Frazão · Marielle Mar |
| Linguagem | Python 3 (testado com 3.14) |
| Repositório | https://github.com/sabrinafrazao/trabalho-seguranca (tag `v1.0-entrega`) |

## 7.2 Descrição da Solução

**Bibliotecas:** `cryptography` (PyCA, construída sobre o OpenSSL) para Ed25519 e serialização PEM; `hashlib` (biblioteca padrão) para SHA-256; `hmac.compare_digest` para comparar hashes em tempo constante; `argparse` para a CLI; `pytest` para os testes.

**Organização:** `src/cripto.py` concentra as operações criptográficas e as validações de entrada, e sinaliza problemas com a exceção `ErroSeguranca`. `src/seguranca.py` é a CLI: interpreta os argumentos, exibe as mensagens e converte os resultados em códigos de saída (0 = sucesso, 1 = verificação falhou, 2 = erro).

**Principais decisões técnicas:**
- **Ed25519 puro**, sem pré-hash: a mensagem passada a `sign`/`verify` são os bytes integrais do arquivo, lidos em modo binário. O vetor de teste 1 da RFC 8032 é reproduzido byte a byte.
- **Formatos do contrato:** a chave privada é salva em PEM PKCS#8 e a pública em PEM SubjectPublicKeyInfo. A assinatura é gravada como binário de exatamente 64 bytes, e um arquivo `.sig` com outro tamanho é rejeitado.
- **Falha segura:** qualquer exceção resulta em código diferente de zero. Só `chave.verify()` sem exceção leva à mensagem "ASSINATURA VÁLIDA".
- **Erros compreensíveis:** a ferramenta detecta arquivo inexistente, diretório no lugar de arquivo, destino inexistente, chave pública usada no lugar da privada (e vice-versa), chave de outro algoritmo (por exemplo, RSA), PEM corrompido, hash de referência malformado e assinatura com tamanho errado.
- **Proteção da chave:** o `keygen` e o `sign` não sobrescrevem arquivos existentes sem `--force`, o `sign` recusa gravar a assinatura sobre o próprio documento ou sobre a chave privada, o `keygen` grava a chave privada com permissão `0600` (em POSIX) e o `.gitignore` bloqueia `*privada*.pem`.
- **Bytes preservados no Git:** o `.gitattributes` impede a conversão de quebras de linha no arquivo de exemplo, o que invalidaria o hash e a assinatura publicados.

## 7.3 Funcionalidades Implementadas

| ID | Requisito | Comando | Situação |
|----|-----------|---------|:--------:|
| R01 | Gerar par de chaves Ed25519 | `keygen` | ✅ |
| R02 | Calcular SHA-256 de qualquer arquivo | `hash` (leitura em blocos de 64 KiB) | ✅ |
| R03 | Comparar hash com referência | `check` (saída 0 se corresponde, 1 se diverge) | ✅ |
| R04 | Assinar arquivo com a chave privada | `sign` | ✅ |
| R05 | Verificar assinatura com a chave pública | `verify` (saída 0 se válida) | ✅ |
| R06 | Rejeitar assinaturas inválidas e adulterações | `verify` (saída 1 se inválida, 2 se malformada) | ✅ |

## 7.4 Testes Realizados

São 34 testes automatizados (`python -m pytest -v`), todos aprovados. Todos executam a CLI real como subprocesso e usam apenas arquivos fictícios.

| ID | Teste | Esperado | Obtido | Evidência |
|----|-------|----------|--------|-----------|
| TI01 | SHA-256 de um arquivo | Hash correto | ✅ Igual ao `hashlib` e aos vetores FIPS (`"abc"`, vazio) | `test_TI01_*`, `test_sha256_*` |
| TI02 | Modificar o arquivo e comparar com o hash original | Divergência | ✅ `check` retorna 1 e exibe "NÃO corresponde" | `test_TI02_*`, demo passo 7 |
| TI03 | Gerar par de chaves | PEM válidos | ✅ PKCS#8 e SPKI carregados como Ed25519, e as chaves formam um par | `test_TI03_*` |
| TI04 | Assinar e verificar o original | Válida | ✅ `.sig` com 64 bytes e `verify` retorna 0 | `test_TI04_*`, demo passo 5 |
| TI05 | Alterar o arquivo após assinar | Inválida | ✅ Basta 1 byte acrescentado para `verify` retornar 1 | `test_TI05_*`, demo passo 8 |
| TI06 | Verificar com outra chave pública | Inválida | ✅ `verify` retorna 1 | `test_TI06_*` |
| Extra | RFC 8032, adulteração de 1 bit na assinatura, assinatura de 0/63/65/128 bytes, erros de entrada, interoperabilidade com OpenSSL 3.5 | Rejeição ou erro claro | ✅ | `test_adicionais.py` |

As evidências estão em `docs/evidencias/`: `testes_automatizados.txt` (saída do pytest), `demonstracao_cli.txt` (fluxo completo com adulteração) e `tratamento_de_erros.txt` (mensagens de erro).

## 7.5 Análise Técnica e Conclusão

**Limitações:** a chave privada não é protegida por senha, porque o contrato exige PKCS#8 sem cifragem. Não há certificado X.509 nem infraestrutura de chaves públicas (ICP) vinculando a chave pública a uma identidade. A assinatura não tem carimbo de tempo, então não se prova quando foi feita. Não existe revogação de chaves. O `sign` carrega o arquivo inteiro na memória, porque o Ed25519 puro precisa da mensagem completa, o que limita o uso com arquivos muito grandes. A permissão `0600` não tem efeito no Windows.

**1. Por que um hash SHA-256 isolado não comprova a autoria?** O hash é calculado sem nenhum segredo: qualquer pessoa pode alterar o documento e calcular o novo hash. Ele só prova integridade em relação a um valor de referência confiável. Não diz quem produziu o documento, e quem adultera o arquivo pode substituir o hash junto.

**2. Qual é a função das chaves pública e privada?** A chave privada, que só o signatário possui, gera a assinatura. Por isso a assinatura comprova autoria e garante o não repúdio. A chave pública pode ser distribuída livremente e permite que qualquer pessoa verifique a assinatura, mas não permite gerar uma nova.

**3. Por que alterar um documento assinado invalida a assinatura?** A assinatura Ed25519 é calculada sobre todos os bytes do documento (internamente com SHA-512). Mudar um único bit altera completamente esse cálculo, e a equação de verificação deixa de ser satisfeita. Forjar uma assinatura válida para o conteúdo novo sem a chave privada é computacionalmente inviável.

**4. Cuidados adicionais para uso em produção:** guardar a chave privada em HSM, token ou cofre de chaves, ou ao menos cifrá-la com senha forte, com controle de acesso. Vincular a chave pública à instituição com certificado digital (por exemplo, ICP-Brasil), definir política de revogação e de rotação de chaves, aplicar carimbo de tempo confiável e manter registros de auditoria. Também seria preciso publicar a chave pública por um canal autêntico, manter as dependências atualizadas, adotar um formato de assinatura padronizado (CMS/PAdES) e validar o processo com testes de segurança e revisão de código.

**Conclusão:** a ferramenta atende aos requisitos R01 a R06 e ao contrato de interoperabilidade, o que foi comprovado pelos testes TI01 a TI06, pelos vetores oficiais e pela verificação cruzada com o OpenSSL. Ela só reporta uma assinatura como válida quando a verificação criptográfica é bem-sucedida.
