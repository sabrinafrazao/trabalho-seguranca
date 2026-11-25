# Demonstração completa da ferramenta (Windows PowerShell).
# Uso, a partir da raiz do repositório:  powershell -ExecutionPolicy Bypass -File exemplos\demo.ps1
$ErrorActionPreference = "Continue"
$raiz = Split-Path -Parent $PSScriptRoot
$cli = Join-Path $raiz "src\seguranca.py"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("seguranca-demo-" + [guid]::NewGuid())
New-Item -ItemType Directory $tmp | Out-Null
Copy-Item (Join-Path $PSScriptRoot "certificado_ficticio.txt") (Join-Path $tmp "doc.txt")
Set-Location $tmp

function Passo($titulo) { Write-Host "`n=== $titulo ===" -ForegroundColor Cyan }

Passo "1. keygen";            python $cli keygen privada.pem publica.pem
Passo "2. hash";              $h = python $cli hash doc.txt; $h
Passo "3. check (original)";  python $cli check doc.txt $h; "codigo de saida: $LASTEXITCODE"
Passo "4. sign";              python $cli sign doc.txt privada.pem doc.sig
Passo "5. verify (original)"; python $cli verify doc.txt publica.pem doc.sig; "codigo de saida: $LASTEXITCODE"

Passo "6. adulterando o documento (60 -> 600 horas)"
$bytes = [System.IO.File]::ReadAllBytes("$tmp\doc.txt")
$texto = [System.Text.Encoding]::UTF8.GetString($bytes).Replace("60 (sessenta)", "600 (seiscentas)")
[System.IO.File]::WriteAllBytes("$tmp\doc.txt", [System.Text.Encoding]::UTF8.GetBytes($texto))
Passo "7. check (adulterado)";  python $cli check doc.txt $h; "codigo de saida: $LASTEXITCODE"
Passo "8. verify (adulterado)"; python $cli verify doc.txt publica.pem doc.sig; "codigo de saida: $LASTEXITCODE"

Set-Location $raiz
Remove-Item -Recurse -Force $tmp
