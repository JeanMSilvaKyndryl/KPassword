$ErrorActionPreference = "Stop"

$project = $PSScriptRoot
$downloads = Join-Path $env:USERPROFILE "Downloads"
$keyFolder = Join-Path $downloads "KPassword-Updater-Key"
$privateKey = Join-Path $keyFolder "kpassword.key"
$publicKey = "$privateKey.pub"
$configPath = Join-Path $project "src-tauri\tauri.conf.json"
$placeholder = "__KPassword_UPDATER_PUBLIC_KEY__"

New-Item -ItemType Directory -Path $keyFolder -Force | Out-Null

Write-Host "Instalando e conferindo as dependencias do projeto..."
Push-Location $project
try {
    & npm.cmd install
    if ($LASTEXITCODE -ne 0) {
        throw "Nao foi possivel instalar as dependencias do projeto."
    }
} finally {
    Pop-Location
}

if (-not (Test-Path $privateKey) -or -not (Test-Path $publicKey)) {
    Write-Host "Gerando a chave exclusiva das atualizacoes do KPassword."
    Write-Host "Crie uma senha forte quando o Tauri solicitar e guarde essa senha."
    Push-Location $project
    try {
        & npm.cmd run tauri signer generate -- -w $privateKey
    } finally {
        Pop-Location
    }

    if ($LASTEXITCODE -ne 0) {
        throw "O Tauri nao conseguiu gerar a chave do atualizador."
    }
}

$publicKeyContent = (Get-Content -Path $publicKey -Raw).Trim()
$configContent = Get-Content -Path $configPath -Raw

if ($configContent.Contains($placeholder)) {
    $configContent = $configContent.Replace($placeholder, $publicKeyContent)
    [System.IO.File]::WriteAllText($configPath, $configContent, [System.Text.UTF8Encoding]::new($false))
    Write-Host "Chave publica configurada no aplicativo."
} else {
    Write-Host "O aplicativo ja possui uma chave publica configurada."
}

Write-Host ""
Write-Host "Configuracao concluida."
Write-Host "Chave privada: $privateKey"
Write-Host "Chave publica: $publicKey"
Write-Host ""
Write-Host "NAO envie a chave privada para o GitHub, por e-mail ou pelo chat."
Write-Host "Faca um backup seguro da pasta KPassword-Updater-Key."
