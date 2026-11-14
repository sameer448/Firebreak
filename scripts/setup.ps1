# One-time setup on Windows (PowerShell). Run from the repository root:
#   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1 [-SkipModels]
# Creates .venv, installs Python packages, pulls the Ollama models, builds the vector indexes
# for both example org packs, runs the tests, and finishes with `python -m capstone doctor`.
param([switch]$SkipModels, [string]$Python = "python")
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Run($exe, [string[]]$argv) {
    & $exe @argv
    if ($LASTEXITCODE -ne 0) { throw "Command failed: $exe $($argv -join ' ')" }
}

Step "Python: $(& $Python --version)"
& $Python -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"
if ($LASTEXITCODE -ne 0) { throw "Python 3.8+ required" }

Step "Virtual environment (.venv) and packages"
if (-not (Test-Path .venv)) { Run $Python @("-m", "venv", ".venv") }
$VPy = ".venv\Scripts\python.exe"
Run $VPy @("-m", "pip", "install", "--quiet", "--upgrade", "pip")
Run $VPy @("-m", "pip", "install", "--quiet", "-r", "requirements.txt")

if (-not $SkipModels) {
    if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
        throw "Ollama not found: install it from https://ollama.com, start it, and re-run"
    }
    Step "Ollama models (about 7 GB the first time)"
    Run ollama @("pull", "nomic-embed-text")
    Run ollama @("pull", "llama3.1:8b")
    Run ollama @("pull", "hf.co/Sgoyal16/soc-triage-llama3.2-3b-GGUF:Q4_K_M")
    Run ollama @("create", "soc-triage", "-f", "Modelfile")

    Step "Vector indexes for the example org packs"
    Run $VPy @("-m", "capstone", "--org", "demo-corp", "org", "ingest")
    Run $VPy @("-m", "capstone", "--org", "harbor-valley-health", "org", "ingest")
}

Step "Tests (no model calls)"
Run $VPy @("-m", "unittest", "discover", "-s", "tests")

Step "Environment check"
& $VPy -m capstone doctor
Write-Host ""
Write-Host "Start the console:  .venv\Scripts\python -m capstone.web --org demo-corp   ->  http://127.0.0.1:8765"
