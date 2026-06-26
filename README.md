# KPassword

Cofre pessoal de credenciais para Windows. Os dados do cofre são criptografados e permanecem localmente no computador do usuário.

## Desenvolvimento local

```powershell
npm.cmd install
npm.cmd run tauri dev
```

## Atualizações

O KPassword 0.4.0 usa o atualizador assinado do Tauri, consulta as releases deste repositório e pode verificar novas versões automaticamente.

Antes do primeiro build, execute uma única vez:

```powershell
powershell -ExecutionPolicy Bypass -File .\CONFIGURAR-ATUALIZADOR.ps1
```

A chave privada gerada pelo script deve permanecer fora do repositório e ser guardada com segurança.


## Versão 0.4.0

Inclui Central de Segurança, temas de aparência, bloqueio ao ocultar/suspender/bloquear o Windows, redução do ícone carregado no frontend e ajustes de desempenho visual.
