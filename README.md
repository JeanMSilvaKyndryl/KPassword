# KPassword

Cofre pessoal de credenciais para Windows. Os dados do cofre são criptografados e permanecem localmente no computador do usuário.

## Desenvolvimento local

```powershell
npm.cmd install
npm.cmd run tauri dev
```

## Atualizações

O KPassword 0.3.1 usa o atualizador assinado do Tauri, consulta as releases deste repositório e pode verificar novas versões automaticamente.

Antes do primeiro build, execute uma única vez:

```powershell
powershell -ExecutionPolicy Bypass -File .\CONFIGURAR-ATUALIZADOR.ps1
```

A chave privada gerada pelo script deve permanecer fora do repositório e ser guardada com segurança.
