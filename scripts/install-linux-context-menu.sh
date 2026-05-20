#!/bin/bash
# install-linux-context-menu.sh
# Instala a extensão de menu de contexto "Adicionar ao IdenVault" no Linux

set -e

echo "========================================="
echo " Instalador IdenVault - Menu de Contexto "
echo "========================================="

# Descobre o caminho absoluto do binário atual (procura em release primeiro)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
BIN_PATH="$(realpath "$SCRIPT_DIR/../target/release/IdenVault" 2>/dev/null || echo "")"

if [ ! -f "$BIN_PATH" ]; then
    BIN_PATH="$(realpath "$SCRIPT_DIR/../target/debug/IdenVault" 2>/dev/null || echo "")"
fi

if [ ! -f "$BIN_PATH" ]; then
    echo "Erro: Binário 'IdenVault' não encontrado em target/release/ ou target/debug/."
    echo "Por favor, rode 'cargo build --release' primeiro."
    exit 1
fi

echo "✔ Binário encontrado em: $BIN_PATH"

# Descobre um terminal suportado (para o menu mostrar a interface CLI)
TERMINAL=""
for t in x-terminal-emulator gnome-terminal konsole xfce4-terminal terminator alacritty; do
    if command -v "$t" >/dev/null 2>&1; then
        TERMINAL="$t"
        break
    fi
done

if [ -z "$TERMINAL" ]; then
    echo "Erro: Nenhum emulador de terminal compatível encontrado."
    exit 1
fi

echo "✔ Terminal selecionado: $TERMINAL"

# O comando que será executado pelo botão direito
EXEC_CMD="$TERMINAL -e \"$BIN_PATH add-to-vault '%f'\""

echo "Instalando para os Gestores de Ficheiros disponíveis..."

# 1. KDE Dolphin (KServices5 / KIO)
KDE_DIR="$HOME/.local/share/kio/servicemenus"
if [ -d "$HOME/.local/share/kservices5/ServiceMenus" ]; then
    KDE_DIR="$HOME/.local/share/kservices5/ServiceMenus"
fi

mkdir -p "$KDE_DIR"
cat > "$KDE_DIR/idenvault-add.desktop" << EOF
[Desktop Entry]
Type=Service
ServiceTypes=KonqPopupMenu/Plugin
MimeType=all/all;
Actions=addToIdenVault;
X-KDE-Priority=TopLevel

[Desktop Action addToIdenVault]
Name=Adicionar ao IdenVault
Icon=security-high
Exec=$EXEC_CMD
EOF
echo "✔ KDE Dolphin configurado."

# 2. GNOME Nautilus (via nautilus-python para menus dinâmicos)
NAUTILUS_PYTHON_DIR="$HOME/.local/share/nautilus-python/extensions"
if command -v nautilus >/dev/null 2>&1; then
    echo "Configurando extensão dinâmica para GNOME Nautilus..."
    
    # Verificar dependência
    if ! dpkg -s python3-nautilus >/dev/null 2>&1 && ! rpm -q nautilus-python >/dev/null 2>&1 && ! pacman -Qs nautilus-python >/dev/null 2>&1; then
        echo "AVISO: O pacote 'python3-nautilus' (Ubuntu/Debian) ou 'nautilus-python' (Fedora/Arch) não parece estar instalado."
        echo "Por favor instale-o para que o menu dinâmico do Nautilus funcione."
    fi

    mkdir -p "$NAUTILUS_PYTHON_DIR"
    cp "$SCRIPT_DIR/nautilus_idenvault.py" "$NAUTILUS_PYTHON_DIR/"
    
    echo "✔ GNOME Nautilus configurado com extensão Python dinâmica."
    echo "  (Dica: Pode ser necessário correr 'nautilus -q' para reiniciar o Nautilus)"
fi

# 3. Nemo (Cinnamon / Linux Mint)
NEMO_DIR="$HOME/.local/share/nemo/actions"
if command -v nemo >/dev/null 2>&1; then
    mkdir -p "$NEMO_DIR"
    cat > "$NEMO_DIR/idenvault-add.nemo_action" << EOF
[Nemo Action]
Name=Adicionar ao IdenVault
Comment=Protege este ficheiro no IdenVault
Exec=$TERMINAL -e "$BIN_PATH add-to-vault \"%F\""
Icon-Name=security-high
Selection=S
Extensions=any;
EOF
    echo "✔ Nemo configurado."
fi

# 4. Thunar (XFCE) e outros que suportam a spec FileManager-Actions / Thunar custom actions
# O Thunar usa uca.xml. Não é seguro injetar XML via script sem um parser, por isso vamos ignorar o injetor automático para Thunar por agora, mas a infraestrutura base está lá.

echo "========================================="
echo " Instalação concluída com sucesso!       "
echo " Pode precisar reiniciar o seu gestor de"
echo " ficheiros (ex: 'nautilus -q' ou fechar  "
echo " as janelas do Dolphin).                 "
echo "========================================="
