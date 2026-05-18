# IdenVault — Vault Commands Manual (vault_*)

Resumo das operações "low-level" do subsistema Vault (core C). Use estes comandos quando precisar gerir diretamente cofres, investigar alertas ou automatizar via scripts.

Formato: `vault-<action> [args]`

- vault-list
  - Descrição: Lista todos os cofres registados no catálogo.
  - Uso: `vault-list`

- vault-create <name> <path> <type>
  - Descrição: Cria um novo cofre e regista no catálogo.
  - Parâmetros: `name` (string|auto), `path` (diretório), `type` = `normal`|`protected`.
  - Exemplo: `vault-create myvault /var/lib/myvault protected`

- vault-delete <id>
  - Descrição: Remove um cofre existente (requer confirmação/senha conforme tipo).
  - Uso: `vault-delete 3`

- vault-rename <id> <new_name>
  - Descrição: Renomeia cofre no catálogo.

- vault-unlock <id>
  - Descrição: Desbloqueia um cofre que entrou em lockout (pode pedir senha).

- vault-passwd <id>
  - Descrição: Altera a senha de um cofre protegido.

- vault-encrypt <id>
  - Descrição: Aplica criptografia persistente (AES-256) aos ficheiros do cofre.

- vault-decrypt <id>
  - Descrição: Reverte criptografia aplicada pelo engine (requer senha do cofre).

- vault-scan <id>
  - Descrição: Força uma varredura de integridade (cálculo de hash, deteção de modificações).
  - Uso: `vault-scan 2`

- vault-resolve <id>
  - Descrição: Marca um alerta como resolvido; limpa flags `modified` e restabelece read-only.

- vault-info <id>
  - Descrição: Imprime informação detalhada do cofre (status, último check, regras aplicadas).

- vault-files <id>
  - Descrição: Lista ficheiros atualmente rastreados pelo catálogo para o cofre.

- vault-sandbox <id>
  - Descrição: Abre um shell isolado apontado ao cofre (modo auditor / recuperação).

- vault-rule <id> <max_fails> [hour_from hour_to]
  - Descrição: Adiciona/atualiza regra de segurança para o cofre (p.ex. limitar tentativas).

- vault-export <id> <file> <dst>
  - Descrição: Exporta (e opcionalmente decripta) ficheiro do cofre para `dst`.

Observações:
- Logs e alertas são gerados pelo mecanismo central (`vault_log`) e pelo sistema de alertas; consulte o ficheiro de logs (`/var/log/vault_security.log`) para auditoria.
- Se pretende integração programática, use as funções FFI expostas (consulte `src/c_src/vault_ffi.c` and `vault_core.h`).
- Para ajuda rápida no terminal use: `help vault-scan` ou `help all` para ver a documentação completa.

Contribuições: atualize este ficheiro sempre que adicionar/alterar comandos `vault-*`.