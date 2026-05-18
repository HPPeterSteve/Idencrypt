# Release Notes — FridgeVault (VaranusCore) v0.8.1

### Refinamentos v0.8.1
*   **Correção de Typos**: Sugestão automática de comandos via Levenshtein.
*   **Assistente de Path**: Validação e sugestão inteligente de caminhos de arquivos.
*   **Proteção Anti-Ransomware**: Sistema de bloqueio de escrita (Read-Only Lockdown) com detecção em tempo real via inotify.
*   **Shutdown Seguro**: Salva o catálogo binário automaticamente no Ctrl+C.
*   **Compatibilidade Linux**: Suporte a macros `sysmacros.h` para compilação estável no WSL/Ubuntu.

### Lista de Comandos
**Gestão de Cofres (Core C):**
*   `vault-create <nome> <path> <tipo>` (normal/protected)
*   `vault-list`: Lista todos os cofres e IDs.
*   `vault-encrypt <id>` / `vault-decrypt <id>`: AES-256 em massa.
*   `vault-sandbox <id>`: Abre shell isolada (Linux Sandbox v2).
*   `vault-rule <id> <falhas> [horas]`: Regras de bloqueio.
*   `vault-passwd <id>`: Altera senha do cofre.
*   `vault-scan <id>`: Verificação de integridade.

**Operações de Arquivo:**
*   `encrypt` / `decrypt <arquivo>`: Criptografia individual.
*   `secure-copy <origem> <cofre>`: Armazenamento protegido.
*   `safe-copy <origem> <destino>`: Cópia com verificação.
*   `status <id>`: Detalhes de proteção.

**Sistema:**
*   `system-information`: Status de hardware e processos ativos.
*   `list-process-status`: Lista processos ativos.
*   `derive-master-key`: Derivação de chaves mestre.
