import os
import subprocess
import shlex
import urllib.parse
from gi.repository import Nautilus, GObject

class IdenVaultExtension(GObject.GObject, Nautilus.MenuProvider):
    def __init__(self):
        super().__init__()
        # Determinar o caminho do executável IdenVault
        # Vamos assumir que está no PATH ou num local conhecido pós-instalação
        self.bin_path = "idenvault"
        
        # Tentar localizar o executável nas pastas de compilação locais se não estiver no PATH
        script_dir = os.path.dirname(os.path.realpath(__file__))
        possible_paths = [
            "idenvault",
            os.path.abspath(os.path.join(script_dir, "../../../../target/release/IdenVault")),
            os.path.abspath(os.path.join(script_dir, "../../../../target/debug/IdenVault")),
            "/usr/local/bin/idenvault",
            "/usr/bin/idenvault"
        ]
        
        for p in possible_paths:
            import shutil
            if shutil.which(p) or os.path.isfile(p):
                self.bin_path = p
                break

    def get_vaults(self):
        """Executa 'idenvault dump-vaults' e retorna uma lista de (ID, Path)"""
        vaults = []
        try:
            result = subprocess.run(
                [self.bin_path, "dump-vaults"],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if "|" in line:
                        vid, vpath = line.split("|", 1)
                        vaults.append((vid.strip(), vpath.strip()))
        except Exception:
            pass
        return vaults

    def add_to_vault_callback(self, menu, files, vault_id, vault_path):
        """Função chamada quando o utilizador clica num cofre do submenu"""
        for file in files:
            if file.is_gone():
                continue
                
            # O URI do GNOME vem como file:///path/to/file
            filepath = urllib.parse.unquote(file.get_uri()[7:])
            
            try:
                # Executa o comando silently
                result = subprocess.run(
                    [self.bin_path, "add-file", vault_path, filepath],
                    capture_output=True,
                    text=True
                )
                
                # Notificação nativa no Linux
                filename = os.path.basename(filepath)
                if result.returncode == 0:
                    subprocess.run(["notify-send", "-i", "security-high", "IdenVault", f"'{filename}' adicionado ao cofre {vault_id} com sucesso."])
                else:
                    subprocess.run(["notify-send", "-i", "dialog-error", "IdenVault Erro", f"Falha ao adicionar '{filename}':\n{result.stderr.strip()}"])
            except Exception as e:
                subprocess.run(["notify-send", "-i", "dialog-error", "IdenVault Erro", f"Erro fatal: {str(e)}"])

    def get_file_items(self, *args):
        # A API pode passar (window, files) ou apenas (files)
        files = args[-1]
        
        # Só mostrar se houver ficheiros selecionados e nenhum for uma pasta (o add-file atual não lida nativamente com pastas inteiras, assumindo ficheiros únicos, embora o isolate-directory lide com pastas)
        if not files:
            return []

        vaults = self.get_vaults()
        
        # O item principal
        main_item = Nautilus.MenuItem(
            name="IdenVaultExtension::Add",
            label="Adicionar ao IdenVault",
            tip="Escolha um cofre para proteger este ficheiro",
            icon="security-high"
        )

        if not vaults:
            # Se não houver cofres, desativar o botão ou mostrar mensagem
            main_item.set_property("sensitive", False)
            return [main_item]

        # Criar o submenu
        submenu = Nautilus.Menu()
        main_item.set_submenu(submenu)

        for vid, vpath in vaults:
            sub_item = Nautilus.MenuItem(
                name=f"IdenVaultExtension::Vault_{vid}",
                label=f"Cofre {vid}: {vpath}",
                tip=f"Adicionar ao cofre em {vpath}",
                icon="folder-saved-search"
            )
            # Ligar o sinal 'activate' (clique)
            sub_item.connect("activate", self.add_to_vault_callback, files, vid, vpath)
            submenu.append_item(sub_item)

        return [main_item]

    def get_background_items(self, *args):
        return []
