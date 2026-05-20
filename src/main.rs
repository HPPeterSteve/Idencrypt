/*
 * main.rs
 *
 * IdenVault — ponto de entrada
 * Integra o core C (vault_security.c) via vault.rs
 *
 * Novos comandos adicionados (delegam ao core C):
 *   vault-list
 *   vault-create  <name> <path> <type>
 *   vault-delete  <id>
 *   vault-rename  <id> <new_name>
 *   vault-unlock  <id>
 *   vault-passwd  <id>
 *   vault-encrypt <id>
 *   vault-decrypt <id>
 *   vault-scan    <id>
 *   vault-resolve <id>
 *   vault-info    <id>
 *   vault-files   <id>
 *   vault-sandbox <id>
 *   vault-rule    <id> <max_fails> [hour_from hour_to]
 *
 * Levenshtein reintegrado: sugestão automática de comando para typos.
 * Nenhum bool, variável ou função existente foi renomeado.
 */

mod cli;
mod vault;
mod crypto;
mod log;
mod path_assistant;
mod sys_info;
mod manual;

use colored::*;
use inquire::{Password, Select};
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use std::io::{self, IsTerminal};
use std::path::PathBuf;

/* ─────────────────────────────────────────────────────────────────────────
 *  Lista canônica de todos os comandos — usada pelo Levenshtein
 * ───────────────────────────────────────────────────────────────────────── */
const ALL_COMMANDS: &[&str] = &[
    /* originais */
    "isolate-directory",
    "create-vault",
    "safe-copy",
    "allow-write",
    "read-directory",
    "add-file",
    "remove-file",
    "status",
    "encrypt",
    "decrypt",
    "secure-copy",
    "run-in-sandbox",
    "system-information",
    "list-process-status",
    "derive-master-key",
    "help",
    "exit",
    /* novos — core C */
    "vault-list",
    "vault-create",
    "vault-delete",
    "vault-rename",
    "vault-unlock",
    "vault-passwd",
    "vault-encrypt",
    "vault-decrypt",
    "vault-scan",
    "vault-resolve",
    "vault-info",
    "vault-files",
    "vault-sandbox",
    "vault-rule",
    "vault-export",
    "manual",
];

fn show_help() {
    println!(
        "{}",
        "Comandos disponíveis (resumido):\n\n  create-vault   add-file   read-directory   remove-file\n  safe-copy      secure-copy  allow-write   isolate-directory\n\n  vault-list     vault-create  vault-delete  vault-rename\n  vault-unlock   vault-passwd  vault-scan    vault-resolve\n  vault-info     vault-files   vault-export  vault-sandbox\n\n  system-information  list-process-status  derive-master-key\n\nUse 'help <comando>' para ver ajuda detalhada de um comando ou 'help all' para a ajuda completa."
            .cyan()
    );
}

fn show_help_for(cmd: &str) {
    match cmd {
        "all" => {
            /* Fallback: print the full detailed help (same content as before) */
            println!(
                "{}",
                "\nComandos disponíveis:\n\n── Operações de arquivo / diretório ──────────────────────────────────────\ncreate-vault <path>        → cria um cofre (diretório)\nadd-file <vault> <file>    → adiciona arquivo ao cofre\nsafe-copy <src> <dst>      → copia com segurança\nallow-write <file>         → libera escrita\nread-directory <dir>       → lista arquivos\nisolate-directory <dir>    → isola diretório\nsecure-copy <file> <vault> [pass] → protege e armazena (senha opcional)\nencrypt <file> [pass]      → criptografa arquivo (senha opcional)\ndecrypt <file> [pass]      → descriptografa arquivo (senha opcional)\nremove-file <vault> <file> → remove arquivo do cofre\nstatus <vault|id>          → mostra status do cofre\nrun-in-sandbox <dir>       → roda diretório em sandbox\n\n── Core C — Vault Security System ────────────────────────────────────────\nvault-list                             → lista todos os cofres (catálogo)\nvault-create <name> <path> <type>      → cria cofre no core C\n  type: normal | protected\nvault-delete  <id>                     → deleta cofre pelo ID\nvault-rename  <id> <new_name>          → renomeia cofre\nvault-unlock  <id>                     → desbloqueia cofre após lockout\nvault-passwd  <id>                     → troca senha do cofre\nvault-encrypt <id>                     → criptografa arquivos (AES-256)\nvault-decrypt <id>                     → descriptografa arquivos\nvault-scan    <id>                     → força varredura de integridade\nvault-resolve <id>                     → resolve alerta ativo\nvault-info    <id>                     → detalhes do cofre\nvault-files   <id>                     → lista arquivos rastreados\nvault-sandbox <id>                     → abre cofre em shell sandbox\nvault-rule    <id> <max_fails> [h_from h_to]  → adiciona regra de segurança\nvault-export  <id> <file> <dst>              → exporta arquivo do cofre\n\n── Sistema ───────────────────────────────────────────────────────────────\nsystem-information [cpu] [memory] [disks] [networks] [processes]\nlist-process-status        → lista status dos processos ativos\nderive-master-key          → deriva master key (senha + chave USB)\n\nmanual                     → manual de operação interativo\nhelp                       → esta ajuda\nexit                       → sair\n"
                    .cyan()
            );
        }
        _ => {
            println!("Ajuda detalhada para '{}':\n", cmd);
            println!("(Descrição detalhada ainda não disponível por comando; execute 'help all' para a ajuda completa.)");
        }
    }
}

fn get_password(prompt_text: &str, provided_pass: Option<&&str>) -> String {
    if let Some(pass) = provided_pass {
        return pass.to_string();
    }

    if !io::stdin().is_terminal() {
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            return input.trim().to_string();
        }
    }

    Password::new(prompt_text)
        .without_confirmation()
        .prompt()
        .unwrap_or_default()
}

/* ─────────────────────────────────────────────────────────────────────────
 *  MENU INTERATIVO TUI
 * ───────────────────────────────────────────────────────────────────────── */
fn interactive_menu() -> Option<String> {
    let options = vec![
        "Criar Novo Cofre",
        "Listar Todos os Cofres",
        "Ver Info de um Cofre",
        "Listar Arquivos do Cofre",
        "Exportar / Resgatar Arquivo",
        "Desbloquear Cofre",
        "Criptografar Cofre",
        "Descriptografar Cofre",
        "Mudar Senha",
        "Deletar Cofre",
        "Sair"
    ];

    let choice = Select::new("Selecione uma ação:", options).prompt();

    match choice {
        Ok("Criar Novo Cofre") => Some("vault-create".to_string()),
        Ok("Listar Todos os Cofres") => Some("vault-list".to_string()),
        Ok("Ver Info de um Cofre") => Some("vault-info".to_string()),
        Ok("Listar Arquivos do Cofre") => Some("vault-files".to_string()),
        Ok("Exportar / Resgatar Arquivo") => Some("vault-export".to_string()),
        Ok("Desbloquear Cofre") => Some("vault-unlock".to_string()),
        Ok("Criptografar Cofre") => Some("vault-encrypt".to_string()),
        Ok("Descriptografar Cofre") => Some("vault-decrypt".to_string()),
        Ok("Mudar Senha") => Some("vault-passwd".to_string()),
        Ok("Deletar Cofre") => Some("vault-delete".to_string()),
        Ok("Sair") => Some("exit".to_string()),
        _ => None,
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Levenshtein — reintegrado e conectado à sugestão de comandos
 * ───────────────────────────────────────────────────────────────────────── */
fn levenshtein_distance(a: &str, b: &str) -> usize {
    let mut costs = (0..=b.len()).collect::<Vec<_>>();

    for (i, ca) in a.chars().enumerate() {
        costs[0] = i + 1;
        let mut last_cost = i;
        for (j, cb) in b.chars().enumerate() {
            let new_cost = if ca == cb {
                last_cost
            } else {
                1 + last_cost.min(costs[j]).min(costs[j + 1])
            };
            last_cost = costs[j + 1];
            costs[j + 1] = new_cost;
        }
    }

    costs[b.len()]
}

/// Encontra o comando mais próximo pelo Levenshtein.
/// Retorna Some(sugestão) se distância ≤ threshold, None caso contrário.
fn suggest_command(unknown: &str) -> Option<&'static str> {
    const THRESHOLD: usize = 3;

    ALL_COMMANDS
        .iter()
        .map(|&cmd| (cmd, levenshtein_distance(unknown, cmd)))
        .filter(|&(_, d)| d <= THRESHOLD)
        .min_by_key(|&(_, d)| d)
        .map(|(cmd, _)| cmd)
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Helpers para parsing de ID e senha (comandos vault-*)
 * ───────────────────────────────────────────────────────────────────────── */
fn parse_id(s: Option<&&str>, cmd: &str) -> Option<u32> {
    match s {
        Some(v) => match v.parse::<u32>() {
            Ok(id) => Some(id),
            Err(_) => {
                eprintln!("{}", format!("✖ '{}': ID deve ser numérico, recebeu '{}'", cmd, v).red());
                None
            }
        },
        None => {
            eprintln!("{}", format!("✖ '{}': ID obrigatório", cmd).red());
            None
        }
    }
}

fn prompt_password(label: &str) -> String {
    Password::new(label)
        .without_confirmation()
        .prompt()
        .unwrap_or_default()
}

fn prompt_password_opt(label: &str) -> Option<String> {
    let p = prompt_password(label);
    if p.is_empty() { None } else { Some(p) }
}

/* 
 *  DISPATCHER DE COMANDOS
 *  */
fn handle_command(parts: Vec<&str>) {
    match parts[0] {

        /* ── originais ────────────────────────────────────────────────── */

        "isolate-directory" => {
            if let Some(dir) = path_assistant::ensure_path(parts.get(1), "Diretório para isolar:", true) {
                log::info(&format!("Isolando diretório: {:?}", dir));
                vault::isolate_directory(dir.to_str().unwrap());
            }
        }

        "create-vault" => {
            let path = if let Some(p) = parts.get(1) {
                PathBuf::from(p)
            } else {
                let input = inquire::Text::new("Caminho para o novo cofre:").prompt().unwrap_or_default();
                PathBuf::from(input)
            };

            if !path.as_os_str().is_empty() {
                log::info(&format!("Criando cofre em: {:?}", path));
                vault::create(path.to_str().unwrap());
                println!("{}", "✔ Cofre criado".green());
            }
        }

        "safe-copy" => {
            let src = path_assistant::ensure_path(parts.get(1), "Arquivo de origem:", false);
            let dst = if let Some(p) = parts.get(2) {
                Some(PathBuf::from(p))
            } else {
                let input = inquire::Text::new("Caminho de destino:").prompt().ok();
                input.map(PathBuf::from)
            };

            if let (Some(s), Some(d)) = (src, dst) {
                log::info(&format!("Cópia segura: {:?} -> {:?}", s, d));
                match vault::safe_copy(s.to_str().unwrap(), d.to_str().unwrap()) {
                    Ok(_) => println!("{}", "✔ Arquivo copiado".green()),
                    Err(e) => {
                        log::error(&format!("Erro em safe-copy: {}", e));
                        eprintln!("{}", format!("✖ Erro: {}", e).red());
                    }
                }
            }
        }

        "allow-write" => {
            if let Some(path) = path_assistant::ensure_path(parts.get(1), "Arquivo para liberar escrita:", false) {
                log::info(&format!("Liberando escrita: {:?}", path));
                vault::allow_write(path.to_str().unwrap());
                println!("{}", "✔ Escrita liberada".green());
            }
        }

        "read-directory" => {
            if let Some(dir) = path_assistant::ensure_path(parts.get(1), "Diretório para listar:", true) {
                let dir_str = dir.to_str().unwrap();
                log::info(&format!("Listando diretório: {}", dir_str));
                let files = vault::read_directory(dir_str);
                println!("{}", format!("📁 {}:", dir_str).blue());
                for f in files {
                    println!("  {}", format!("• {}", f).white());
                }
            }
        }

        "add-file" => {
            let vault_path = path_assistant::ensure_path(parts.get(1), "Caminho do cofre:", true);
            let file       = path_assistant::ensure_path(parts.get(2), "Arquivo para adicionar:", false);

            if let (Some(v), Some(f)) = (vault_path, file) {
                log::info(&format!("Adicionando arquivo {:?} ao cofre {:?}", f, v));
                match vault::add_file(v.to_str().unwrap(), f.to_str().unwrap()) {
                    Ok(_) => println!("{}", "✔ Arquivo adicionado".green()),
                    Err(e) => {
                        log::error(&format!("Erro em add-file: {}", e));
                        eprintln!("{}", format!("✖ Erro: {}", e).red());
                    }
                }
            }
        }

        "remove-file" => {
            let vault_path = path_assistant::ensure_path(parts.get(1), "Caminho do cofre:", true);
            let file = if let Some(f) = parts.get(2) {
                Some(f.to_string())
            } else {
                inquire::Text::new("Nome do arquivo no cofre:").prompt().ok()
            };

            if let (Some(v), Some(f)) = (vault_path, file) {
                log::info(&format!("Removendo arquivo {} do cofre {:?}", f, v));
                match vault::remove_file(v.to_str().unwrap(), &f) {
                    Ok(_) => println!("{}", "✔ Arquivo removido".green()),
                    Err(e) => {
                        log::error(&format!("Erro em remove-file: {}", e));
                        eprintln!("{}", format!("✖ Erro: {}", e).red());
                    }
                }
            }
        }

        "status" => {
            if let Some(vault_path) = path_assistant::ensure_path(parts.get(1), "Caminho ou ID do cofre:", true) {
                log::info(&format!("Verificando status do cofre: {:?}", vault_path));
                match vault::get_vault_status(vault_path.to_str().unwrap()) {
                    Ok(_)  => (),
                    Err(e) => {
                        log::error(&format!("Erro em status: {}", e));
                        eprintln!("{}", format!("✖ Erro: {}", e).red());
                    }
                }
            }
        }

        "encrypt" => {
            if let Some(file) = path_assistant::ensure_path(parts.get(1), "Arquivo para criptografar:", false) {
                let pass = get_password("Senha:", parts.get(2));
                if !pass.is_empty() {
                    log::info(&format!("Criptografando arquivo: {:?}", file));
                    match crypto::encrypt_file(&file, &pass) {
                        Ok(_) => println!("{}", "✔ Arquivo criptografado".green()),
                        Err(e) => {
                            log::error(&format!("Erro em encrypt: {}", e));
                            eprintln!("{}", format!("✖ Erro: {}", e).red());
                        }
                    }
                } else {
                    println!("{}", "✖ Senha vazia ou erro ao ler senha".red());
                }
            }
        }

        "decrypt" => {
            if let Some(file) = path_assistant::ensure_path(parts.get(1), "Arquivo para descriptografar:", false) {
                let pass = get_password("Senha:", parts.get(2));
                if !pass.is_empty() {
                    log::info(&format!("Descriptografando arquivo: {:?}", file));
                    match crypto::decrypt_file(&file, &pass) {
                        Ok(_) => println!("{}", "✔ Arquivo descriptografado".green()),
                        Err(e) => {
                            log::error(&format!("Erro em decrypt: {}", e));
                            eprintln!("{}", format!("✖ Erro: {}", e).red());
                        }
                    }
                } else {
                    println!("{}", "✖ Senha vazia ou erro ao ler senha".red());
                }
            }
        }

        "secure-copy" => {
            let file       = path_assistant::ensure_path(parts.get(1), "Arquivo de origem:", false);
            let vault_path = path_assistant::ensure_path(parts.get(2), "Caminho do cofre:", true);

            if let (Some(f), Some(v)) = (file, vault_path) {
                let pass = get_password("Defina uma senha para o cofre:", parts.get(3));
                if !pass.is_empty() {
                    log::info(&format!("Secure-copy: {:?} para {:?}", f, v));
                    vault::secure_store(f.to_str().unwrap(), v.to_str().unwrap(), &pass);
                    println!("{}", "✔ Arquivo protegido e armazenado no cofre".green());
                } else {
                    println!("{}", "✖ Senha vazia ou erro ao processar senha".red());
                }
            }
        }

        "run-in-sandbox" => {
            if let Some(dir) = path_assistant::ensure_path(parts.get(1), "Diretório para sandbox:", true) {
                log::info(&format!("Executando sandbox: {:?}", dir));
                vault::run_in_sandbox(dir.to_str().unwrap());
            }
        }

        "system-information" => {
            let options = sys_info::SystemOptions {
                cpu:       parts.contains(&"cpu"),
                memory:    parts.contains(&"memory"),
                disks:     parts.contains(&"disks"),
                networks:  parts.contains(&"networks"),
                processes: parts.contains(&"processes"),
            };
            sys_info::system_information(options);
        }

        "list-process-status" => {
            let options = sys_info::SystemOptions {
                cpu:       false,
                memory:    false,
                disks:     false,
                networks:  false,
                processes: true,
            };
            sys_info::list_process_status(&options);
        }

        "derive-master-key" => {
            let password = inquire::Password::new("Senha:").prompt().unwrap_or_default();
            let usb_key_input = inquire::Text::new("Chave USB (hex):").prompt().unwrap_or_default();
            let usb_key_bytes = match hex::decode(usb_key_input.trim()) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error(&format!("Erro ao decodificar chave USB: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                    return;
                }
            };

            match crypto::derive_master_key(&password, &usb_key_bytes) {
                Ok(master_key) => println!("{}", format!("Master Key derivada: {}", hex::encode(master_key)).green()),
                Err(e) => {
                    log::error(&format!("Erro em derive-master-key: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
        }


        "manual" => {
            manual::show_manual();
        }

        "help" => {
            if let Some(&cmd) = parts.get(1) {
                show_help_for(cmd);
            } else {
                show_help();
            }
        }

        "exit" => {
            log::info("Aplicação encerrada pelo usuário.");
            println!("{}", "Saindo...".yellow());
            std::process::exit(0);
        }

        /* ══ novos — core C ════════════════════════════════════════════ */

        /* vault-list */
        "vault-list" => {
            log::info("Listando cofres do catálogo (core C)");
            vault::vault_list();
        }

        "vault-create" => {
            let mut name_buf = String::new();
            let name = if let Some(&s) = parts.get(1) {
                Some(s)
            } else {
                let ans = inquire::Text::new("Nome do cofre (Enter para auto-gerar):").prompt().unwrap_or_default();
                if ans.trim().is_empty() { None } else {
                    name_buf = ans.trim().to_string();
                    Some(name_buf.as_str())
                }
            };

            let mut path_buf = String::new();
            let path = if let Some(&s) = parts.get(2) {
                Some(s)
            } else {
                let ans = Select::new("Onde salvar o cofre?", vec!["Local padrão (Catálogo)", "Escolher pasta..."]).prompt();
                if let Ok("Escolher pasta...") = ans {
                    if let Some(p) = path_assistant::ensure_path(None, "Selecione a pasta de destino", true) {
                        path_buf = p.to_string_lossy().to_string();
                        Some(path_buf.as_str())
                    } else { None }
                } else { None }
            };

            let mut vtype_str = "normal";
            if let Some(&s) = parts.get(3) {
                vtype_str = s;
            } else {
                if let Ok(ans) = Select::new("Tipo de cofre:", vec!["normal (sem senha)", "protected (com senha)"]).prompt() {
                    vtype_str = if ans.starts_with("normal") { "normal" } else { "protected" };
                }
            };

            let password = if vtype_str == "protected" {
                let p1 = prompt_password("Senha do cofre:");
                if p1.is_empty() {
                    eprintln!("{}", "✖ Senha obrigatória para cofre protegido.".red());
                    return;
                }
                let p2 = prompt_password("Confirme a senha:");
                if p1 != p2 {
                    eprintln!("{}", "✖ Senhas não coincidem.".red());
                    return;
                }
                Some(p1)
            } else {
                None
            };

            /* ── Engine de isolamento ── */
            println!("{}", "\nEscolha o engine de proteção:".cyan());
            println!("{}", "  [0] Sem engine (padrão)".white());
            println!("{}", "  [1] Engine 1 — 1 camada  + arquivos isca a-z".white());
            println!("{}", "  [2] Engine 2 — 3 camadas + arquivos isca a-z".white());
            println!("{}", "  [3] Engine 3 — 6 camadas + arquivos isca a-z".white());
            println!("{}", "  [4] Engine 4 — 16 camadas + binários falsos .enc".white());
            println!("{}", "  [5] Engine 5 — 20 camadas + binários falsos .enc".white());

            let engine_level: i32 = inquire::Text::new("Engine [0-5]:")
                .prompt()
                .unwrap_or_default()
                .trim()
                .parse::<i32>()
                .unwrap_or(0)
                .clamp(0, 5);

            println!("{}", format!("→ Engine {} selecionado.", engine_level).yellow());

            log::info(&format!("vault-create name={:?} path={:?} type={} engine={}",
                name, path, vtype_str, engine_level));

            match vault::vault_create(name, vtype_str, path, password.as_deref()) {
                Ok(_)  => {
                    println!("{}", "✔ Cofre criado no core C.".green());

                    /* Aplica engine se > 0 */
                    if engine_level > 0 {
                        match vault::vault_apply_engine(name, engine_level) {
                            Ok(_)  => println!("{}", format!("✔ Engine {} aplicado.", engine_level).green()),
                            Err(e) => {
                                log::error(&format!("vault_apply_engine: {}", e));
                                eprintln!("{}", format!("⚠ Engine não aplicado: {}", e).yellow());
                            }
                        }
                    }
                },
                Err(e) => {
                    log::error(&format!("vault-create: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
        }

        /* vault-delete <id> */
        "vault-delete" => {
            let Some(id) = parse_id(parts.get(1), "vault-delete") else { return };
            let pass = prompt_password_opt("Senha (Enter para pular):");

            log::info(&format!("vault-delete id={}", id));
            match vault::vault_delete(id, pass.as_deref()) {
                Ok(_)  => println!("{}", "✔ Cofre deletado.".green()),
                Err(e) => {
                    log::error(&format!("vault-delete: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
        }

        /* vault-rename <id> <new_name> */
        "vault-rename" => {
            let Some(id) = parse_id(parts.get(1), "vault-rename") else { return };
            let new_name = match parts.get(2) {
                Some(n) => *n,
                None => {
                    eprintln!("{}", "✖ vault-rename: novo nome obrigatório.".red());
                    return;
                }
            };
            let pass = prompt_password_opt("Senha (Enter para pular):");

            log::info(&format!("vault-rename id={} new_name={}", id, new_name));
            match vault::vault_rename(id, new_name, pass.as_deref()) {
                Ok(_)  => println!("{}", "✔ Cofre renomeado.".green()),
                Err(e) => {
                    log::error(&format!("vault-rename: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
        }

        /* vault-unlock <id> */
        "vault-unlock" => {
            let Some(id) = parse_id(parts.get(1), "vault-unlock") else { return };
            let pass = prompt_password("Senha:");
            if pass.is_empty() {
                eprintln!("{}", "✖ Senha obrigatória para desbloquear.".red());
                return;
            }

            log::info(&format!("vault-unlock id={}", id));
            match vault::vault_unlock(id, &pass) {
                Ok(_)  => println!("{}", "✔ Cofre desbloqueado.".green()),
                Err(e) => {
                    log::error(&format!("vault-unlock: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
        }

        /* vault-export <id> [file] */
        "vault-export" => {
            let id = if let Some(&s) = parts.get(1) {
                s.parse::<u32>().ok()
            } else {
                inquire::Text::new("ID do Cofre:").prompt().ok().and_then(|s| s.parse::<u32>().ok())
            };

            let Some(id) = id else {
                eprintln!("{}", "✖ ID do cofre inválido ou não fornecido.".red());
                return;
            };

            let real_path = match vault::vault_get_real_path(id) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{}", format!("✖ Erro ao obter diretório: {}", e).red());
                    return;
                }
            };

            let mut available_files = Vec::new();
            if let Ok(entries) = std::fs::read_dir(&real_path) {
                for entry in entries.flatten() {
                    if let Ok(file_type) = entry.file_type() {
                        if file_type.is_file() {
                            available_files.push(entry.file_name().to_string_lossy().to_string());
                        }
                    }
                }
            }

            if available_files.is_empty() {
                println!("{}", "O cofre está vazio!".yellow());
                return;
            }

            available_files.push(">> Todos os arquivos".to_string());
            available_files.push(">> Cancelar".to_string());

            let filename = match inquire::Select::new("Selecione o arquivo para resgatar:", available_files).prompt() {
                Ok(ans) if ans == ">> Cancelar" => return,
                Ok(ans) => ans,
                Err(_) => return,
            };

            println!("{}", "\n⚠ ADVERTÊNCIA: Os arquivos resgatados ficarão DESPROTEGIDOS no destino!".yellow());
            let confirm = inquire::Select::new("Você tem certeza disso?", vec!["Sim, resgatar", "Não, cancelar"]).prompt();
            if let Ok("Não, cancelar") | Err(_) = confirm {
                println!("{}", "Operação cancelada.".yellow());
                return;
            }

            println!("{}", "➜ Selecione a pasta de destino...".cyan());
            let dst_dir = if let Some(p) = rfd::FileDialog::new().pick_folder() {
                p
            } else {
                println!("{}", "✖ Nenhuma pasta selecionada. Operação cancelada.".red());
                return;
            };

            let is_protected = vault::vault_is_protected(id);
            let password = if is_protected {
                prompt_password("Senha do Cofre (necessária para decifrar):")
            } else {
                String::new()
            };

            if is_protected && password.is_empty() {
                eprintln!("{}", "✖ Senha é obrigatória para cofres protegidos.".red());
                return;
            }

            log::info(&format!("vault-export id={} file={} dest={:?}", id, filename, dst_dir));

            let files_to_export: Vec<String> = if filename == ">> Todos os arquivos" {
                let mut all = Vec::new();
                if let Ok(entries) = std::fs::read_dir(&real_path) {
                    for entry in entries.flatten() {
                        if let Ok(file_type) = entry.file_type() {
                            if file_type.is_file() {
                                all.push(entry.file_name().to_string_lossy().to_string());
                            }
                        }
                    }
                }
                all
            } else {
                vec![filename]
            };

            let mut success_count = 0;
            let mut fail_count = 0;

            for f in files_to_export {
                let mut final_dst = dst_dir.join(&f);
                if is_protected && f.ends_with(".enc") {
                    final_dst.set_extension("");
                }
                let dst_str = final_dst.to_string_lossy().to_string();

                let res = if is_protected {
                    vault::vault_export_and_decrypt(id, &f, &dst_str, &password)
                } else {
                    vault::vault_export_file(id, &f, &dst_str)
                };

                match res {
                    Ok(_) => {
                        println!("{}", format!("✔ {} resgatado com sucesso para {}", f, dst_str).green());
                        success_count += 1;
                    },
                    Err(e) => {
                        eprintln!("{}", format!("✖ Erro ao resgatar {}: {}", f, e).red());
                        fail_count += 1;
                    }
                }
            }

            println!("{}", format!("\nOperação de resgate concluída! {} sucessos, {} falhas. Obrigado!", success_count, fail_count).bright_green());
        }

        /* vault-passwd <id> */
        "vault-passwd" => {
            let Some(id) = parse_id(parts.get(1), "vault-passwd") else { return };
            let old_pass = prompt_password("Senha atual:");
            let new_pass = prompt_password("Nova senha:");
            let cnf_pass = prompt_password("Confirme nova senha:");

            if new_pass != cnf_pass {
                eprintln!("{}", "✖ Senhas não coincidem.".red());
                return;
            }
            if new_pass.is_empty() {
                eprintln!("{}", "✖ Nova senha não pode ser vazia.".red());
                return;
            }

            log::info(&format!("vault-passwd id={}", id));
            match vault::vault_change_password(id, &old_pass, &new_pass) {
                Ok(_)  => println!("{}", "✔ Senha alterada.".green()),
                Err(e) => {
                    log::error(&format!("vault-passwd: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
        }

        /* vault-encrypt <id> */
        "vault-encrypt" => {
            let Some(id) = parse_id(parts.get(1), "vault-encrypt") else { return };
            let pass = prompt_password("Senha do cofre:");
            if pass.is_empty() {
                eprintln!("{}", "✖ Senha obrigatória para criptografar.".red());
                return;
            }

            log::info(&format!("vault-encrypt id={}", id));
            match vault::vault_encrypt(id, &pass) {
                Ok(_)  => println!("{}", "✔ Arquivos criptografados (AES-256).".green()),
                Err(e) => {
                    log::error(&format!("vault-encrypt: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
        }

        /* vault-decrypt <id> */
        "vault-decrypt" => {
            let Some(id) = parse_id(parts.get(1), "vault-decrypt") else { return };
            let pass = prompt_password("Senha do cofre:");
            if pass.is_empty() {
                eprintln!("{}", "✖ Senha obrigatória para descriptografar.".red());
                return;
            }

            log::info(&format!("vault-decrypt id={}", id));
            match vault::vault_decrypt(id, &pass) {
                Ok(_)  => println!("{}", "✔ Arquivos descriptografados.".green()),
                Err(e) => {
                    log::error(&format!("vault-decrypt: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
        }

        /* vault-scan <id> */
        "vault-scan" => {
            let Some(id) = parse_id(parts.get(1), "vault-scan") else { return };
            log::info(&format!("vault-scan id={}", id));
            match vault::vault_scan(id) {
                Ok(_)  => println!("{}", "✔ Varredura concluída.".green()),
                Err(e) => {
                    log::error(&format!("vault-scan: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
        }

        /* vault-resolve <id> */
        "vault-resolve" => {
            let Some(id) = parse_id(parts.get(1), "vault-resolve") else { return };
            let pass = prompt_password_opt("Senha (Enter para pular):");

            log::info(&format!("vault-resolve id={}", id));
            match vault::vault_resolve(id, pass.as_deref()) {
                Ok(_)  => println!("{}", "✔ Alerta resolvido.".green()),
                Err(e) => {
                    log::error(&format!("vault-resolve: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
        }

        /* vault-info <id> */
        "vault-info" => {
            let Some(id) = parse_id(parts.get(1), "vault-info") else { return };
            log::info(&format!("vault-info id={}", id));
            vault::vault_info(id);
        }

        /* vault-files <id> */
        "vault-files" => {
            let Some(id) = parse_id(parts.get(1), "vault-files") else { return };
            log::info(&format!("vault-files id={}", id));
            vault::vault_files(id);
        }

        /* vault-sandbox <id> */
        "vault-sandbox" => {
            let Some(id) = parse_id(parts.get(1), "vault-sandbox") else { return };
            let pass = prompt_password_opt("Senha (Enter para pular):");

            log::info(&format!("vault-sandbox id={}", id));
            match vault::vault_sandbox(id, pass.as_deref()) {
                Ok(_)  => (),
                Err(e) => {
                    log::error(&format!("vault-sandbox: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
        }

        /* vault-rule <id> <max_fails> [hour_from hour_to] */
        "vault-rule" => {
            let Some(id) = parse_id(parts.get(1), "vault-rule") else { return };
            let max_fails: i32 = match parts.get(2) {
                Some(v) => match v.parse() {
                    Ok(n) => n,
                    Err(_) => {
                        eprintln!("{}", "✖ vault-rule: max_fails deve ser inteiro.".red());
                        return;
                    }
                },
                None => {
                    eprintln!("{}", "✖ vault-rule: max_fails obrigatório.".red());
                    return;
                }
            };

            let hour_from: Option<i32> = parts.get(3).and_then(|v| v.parse().ok());
            let hour_to:   Option<i32> = parts.get(4).and_then(|v| v.parse().ok());

            log::info(&format!(
                "vault-rule id={} max_fails={} hours={:?}-{:?}",
                id, max_fails, hour_from, hour_to
            ));
            match vault::vault_rule(id, max_fails, hour_from, hour_to) {
                Ok(_)  => println!("{}", "✔ Regra adicionada.".green()),
                Err(e) => {
                    log::error(&format!("vault-rule: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
            
        }

        
        /* ── comando desconhecido — Levenshtein sugere o mais próximo ── */
        unknown => {
            log::warn(&format!("Comando inválido: {}", unknown));

            match suggest_command(unknown) {
                Some(suggestion) => {
                    println!(
                        "{}",
                        format!("✖ Comando '{}' não existe.", unknown).red()
                    );
                    println!(
                        "{}",
                        format!("  Você quis dizer '{}'?", suggestion).yellow()
                    );
                }
                None => {
                    println!("{}", format!("✖ Comando '{}' não existe.", unknown).red());
                    println!("{}", "Digite 'help' para ver os comandos.".yellow());
                }
            }
        }
    }
}

/* 
 *  MAIN
 *  */
fn main() {
    let mut rl = DefaultEditor::new().unwrap();
    log::info("Aplicação iniciada.");

    /* ── Inicializa o core C: carrega catálogo do disco, inicia monitor ── */
    match vault::vault_init() {
        Ok(()) => log::info("Core C inicializado: catálogo carregado do disco."),
        Err(e) => {
            eprintln!(
                "{}",
                format!("⚠ Falha ao inicializar core C: {} (continuando sem persistência)", e)
                    .yellow()
            );
        }
    }

    println!(
        "{}",
        "IdenVault v1.2.0 iniciado!  Sub-sistema de Assistência de Caminhos ATIVO.
        todos os direitos reservados.
        Digite 'help'"
            .bright_green()
    );

    /* ── Ctrl+C: shutdown graceful — salva catálogo antes de sair ─────── */
    ctrlc::set_handler(|| {
        println!("\n{}", "^C — Salvando catálogo...".yellow());
        log::info("Ctrl+C recebido — executando shutdown graceful");

        /* Salva catálogo no disco e limpa memória sensível */
        match vault::vault_shutdown() {
            Ok(()) => log::info("Catálogo salvo com sucesso."),
            Err(e) => {
                eprintln!("⚠ Erro ao salvar catálogo: {}", e);
                log::error(&format!("Erro no shutdown: {}", e));
            }
        }

        log::info("Aplicação fechando (graceful)");
        std::process::exit(0);
    })
    .expect("Erro ao definir handler");

    loop {
        let readline = rl.readline(&"IdenVault> ".bright_blue().to_string());

        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str()).ok();
                let input = line.trim();
                let mut cmd_to_run = input.to_string();

                if input.is_empty() || input == "menu" {
                    if let Some(c) = interactive_menu() {
                        cmd_to_run = c;
                    } else {
                        continue;
                    }
                }

                /* Comando 'quit' / 'exit' → shutdown graceful */
                if cmd_to_run == "quit" || cmd_to_run == "exit" {
                    println!("{}", "Salvando catálogo e encerrando...".yellow());
                    match vault::vault_shutdown() {
                        Ok(()) => log::info("Catálogo salvo com sucesso."),
                        Err(e) => eprintln!("⚠ Erro ao salvar: {}", e),
                    }
                    log::info("Aplicação encerrada pelo usuário.");
                    break;
                }

                let parts: Vec<&str> = cmd_to_run.split_whitespace().collect();
                handle_command(parts);
            }

            Err(ReadlineError::Eof) => {
                println!("\n{}", "^D — Salvando catálogo...".yellow());
                match vault::vault_shutdown() {
                    Ok(()) => log::info("Catálogo salvo com sucesso (EOF)."),
                    Err(e) => eprintln!("⚠ Erro ao salvar: {}", e),
                }
                log::info("EOF detectado.");
                break;
            }

            Err(err) => {
                log::error(&format!("Erro na leitura: {:?}", err));
                /* Tenta salvar mesmo em erro */
                let _ = vault::vault_shutdown();
                break;
            }
        }
    }
}
