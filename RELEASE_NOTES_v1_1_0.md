# IdenVault v1.1.0 "Kernel Sentinel" 🛡️🍷🗿

> *Da observação à intervenção: Bloqueio ativo de ameaças diretamente no Kernel do Linux.*

O **IdenVault v1.1.0** eleva o patamar de segurança da aplicação. Deixamos de apenas monitorar alterações e passamos a **interceptar e bloquear ativamente ameaças em tempo real**. Com a integração do subsistema **`fanotify`** do Kernel do Linux e um motor robusto de **Whitelist de PIDs**, o IdenVault agora é capaz de neutralizar ransomware e processos maliciosos antes mesmo que eles consigam ler ou alterar qualquer arquivo do cofre.

---

### 🚀 O que há de novo na v1.1.0?

* **🛡️ Interceptação Ativa com `fanotify`:** Substituição do monitoramento passivo (`inotify`) por interceptação ativa (`fanotify` com `FAN_CLASS_CONTENT`). Agora, qualquer tentativa de abertura/leitura de arquivos passa pela aprovação direta do motor de segurança do IdenVault em nível de Kernel.
* **🔑 Whitelist Dinâmica de PIDs (Anti-Malware):**
  * **Auto-Whitelist:** O próprio processo do `IdenVault` é auto-whitelistado no início.
  * **Herança Segura:** Processos filhos confiáveis (como um editor de texto aberto pelo usuário dentro da sessão do cofre) são automaticamente adicionados à lista de permissões (`vault_auth_pid_add_ffi`).
  * **Bloqueio Cirúrgico:** Qualquer PID não autorizado que tente acessar os arquivos sensíveis do cofre recebe um sinal de **`FAN_DENY`** instantâneo do Kernel, impedindo o acesso à chamada de sistema `open`.
* **🚨 Travamento Instantâneo (Instant Lock):** Na primeira tentativa de acesso não autorizado detectada, o cofre é imediatamente colocado em modo **`Strict Read-Only`** global, neutralizando qualquer ataque massivo (como ransomware de criptografia rápida).
* **🌐 Compatibilidade Multiplataforma:** As assinaturas de FFI e os stubs do Rust foram cuidadosamente blindados com condicionais de compilação (`cfg(target_os = "linux")`). O projeto compila e roda em Windows de forma limpa, mantendo a compatibilidade e estabilidade multiplataforma.

---

### 📦 CI/CD Atualizado
* O pipeline automatizado do GitHub Actions compilou com sucesso a versão **v1.1.0** para sistemas Linux/x86_64 com todas as otimizações de produção (`opt-level = "z"`, `lto = true`, `strip = true`).

---

### 🛠️ Como Executar com Proteção Ativa (Linux / Root)
Para que o `fanotify` consiga interceptar as chamadas do Kernel, o binário precisa de privilégios administrativos (ou a capability `CAP_SYS_ADMIN`):

```bash
# Executando com privilégios para habilitar o Monitor Sentinel
sudo ./IdenVault
```
*(Caso executado sem privilégios, o cofre iniciará normalmente com o restante das proteções, emitindo um aviso amigável de monitor desabilitado).*

*IdenVault: Sentinel ativo. Ameaças bloqueadas na porta do Kernel.* 🛡️🗿
