# IdenVault v1.0.0 "Gold Stable Release" 🍷🗿

> *De CRUD de garagem na v0.0.1 a um Bunker de Custódia Ativo na v1.0.0.*

O **IdenVault v1.0.0** está oficialmente pronto para guerra. Fundindo a segurança de baixo nível do **C** com a robustez e TUI moderna em **Rust**, entregamos proteção contra ransomware, sandboxing de processos e labirintos de ofuscação em um binário final de apenas **~546 KB** consumindo **~4.89 MB de RAM**.

---

### 🚀 O que mudou desde a v0.9.0?

* **🎨 Seletor Híbrido Nativo (`rfd`):** Transição para janelas gráficas nativas do OS na hora de escolher pastas/arquivos. Se rodar em WSL sem tela (headless), cai de forma inteligente e automática para o modo texto.
* **🚪 Rota de Fuga (`vault-export`):** Novo comando para resgatar arquivos. Ele decifra o cofre em RAM temporária (AES-GCM-256) on-the-fly com a senha fornecida e joga o arquivo limpo no seu Desktop, sem expor dados no disco.
* **🌀 FFI Hardening (Blindagem do Labirinto):** Novos hooks em C (`vault_get_real_path_ffi` e `vault_is_protected_ffi`) para o Rust saber o diretório físico real das pastas ocultas sob o Labyrinth (Engine 5) e prevenir vazamentos ou leituras de iscas.
* **📦 CI/CD Automatizado:** Pipeline no GitHub Actions (`release-build.yml`) que compila o binário de produção Linux instalando as dependências de interface visual de forma 100% autônoma.

---

### 🛠️ Como Executar no Linux / WSL

```bash
unzip IdenVault-Linux.zip
chmod +x IdenVault
./IdenVault
```

*IdenVault: Simples, leve, bruto e inquebrável.* 🍷🗿
