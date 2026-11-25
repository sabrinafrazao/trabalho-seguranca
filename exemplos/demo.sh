#!/usr/bin/env sh
# Demonstração completa da ferramenta (Linux/macOS/Git Bash).
# Uso, a partir da raiz do repositório:  sh exemplos/demo.sh
RAIZ="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-python3}"
"$PY" -c "" >/dev/null 2>&1 || PY=python
CLI="$PY $RAIZ/src/seguranca.py"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cp "$RAIZ/exemplos/certificado_ficticio.txt" "$TMP/doc.txt"
cd "$TMP" || exit 2

passo() { printf '\n=== %s ===\n' "$1"; }

passo "1. keygen";            $CLI keygen privada.pem publica.pem
passo "2. hash";              H="$($CLI hash doc.txt)"; echo "$H"
passo "3. check (original)";  $CLI check doc.txt "$H"; echo "codigo de saida: $?"
passo "4. sign";              $CLI sign doc.txt privada.pem doc.sig
passo "5. verify (original)"; $CLI verify doc.txt publica.pem doc.sig; echo "codigo de saida: $?"
passo "6. adulterando o documento (60 -> 600 horas)"
sed 's/60 (sessenta)/600 (seiscentas)/' doc.txt > doc2.txt && mv doc2.txt doc.txt
passo "7. check (adulterado)";  $CLI check doc.txt "$H"; echo "codigo de saida: $?"
passo "8. verify (adulterado)"; $CLI verify doc.txt publica.pem doc.sig; echo "codigo de saida: $?"
