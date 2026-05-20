# IdenVault v1.2.0 - Release Notes

Esta versão introduz grandes melhorias de performance e a integração nativa aguardada no explorador de ficheiros GNOME no Linux.

## O que há de novo?

### 🚀 Performance & Core C
- **Fim do Loop Brute-force:** Substituímos o ineficiente loop no Rust que iterava as IDs de 1 a 100.000 para procurar o caminho dos cofres. 
- **Nova FFI de Bulk Listing:** Criada a função `vault_list_ids_ffi` no C (que retorna em O(1) o catálogo) com um wrapper seguro em Rust `vault_get_all_paths_pub()`, reduzindo drasticamente as chamadas IPC e carga de processamento na listagem e verificação de caminhos.

### 🐧 Integração Nativa GNOME (Nautilus)
- **Menu de Contexto Dinâmico:** Introduzida a extensão nativa de Python (`nautilus_idenvault.py`) para GNOME. Sem usar terminais invisíveis que poluem o ecrã, agora basta clicar com o botão direito num ficheiro para que apareça a opção "Adicionar ao IdenVault", que desdobra um submenu com todos os seus cofres vivos no instante.
- **Background Seguro:** Os comandos de proteção `add-file` são agora orquestrados no background.
- **Notificações do Sistema:** Adicionado suporte a `notify-send` pelo script Python para que receba pop-ups seguros confirmando o sucesso do isolamento do ficheiro, ou informando-o de eventuais erros sem precisar de abrir a consola.
- **Novo Comando `dump-vaults`:** Adicionámos o comando escondido de alta performance `dump-vaults` no `main.rs` para permitir que extensões externas (como a do Nautilus) façam o parsing da lista de cofres e identificadores instantaneamente.

### 🛠 Remendos
- Removido experimental code e ficheiros residuais `.reg`/`.ps1` que seriam pensados para Windows mas não faziam sentido no escopo do IdenVault (que tem dependências nativas ao kernel do Linux como o `fanotify`). O foco de desktop está cravado no Linux.
