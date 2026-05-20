/*
 * vault.rs
 *
 * Integração Rust ↔ C (vault core — split modules)
 * Autor: Peter Steve
 *
 * Core C split em 5 arquivos:
 *   vault_crypto.c   — AES-256-GCM, PBKDF2, SHA-256, logging
 *   vault_catalog.c  — hashmap, catalog save/load, vault CRUD
 *   vault_monitor.c  — fanotify (PID-whitelist), alertas, rules, monitor thread
 *   vault_sandbox.c  — sandbox v2 (Linux) / stub (Windows)
 *   vault_ffi.c      — wrappers FFI + init/shutdown
 *
 * Expõe via FFI:
 *   - vault_ffi_init / vault_ffi_shutdown (lifecycle)
 *   - vault_create_ffi ... vault_rule_ffi (operations)
 *
 * As funções originais do Rust (isolate_directory, create, add_file,
 * safe_copy, secure_store, read_directory, allow_write, remove_file,
 * get_vault_status, run_in_sandbox) continuam existindo — as que têm
 * equivalente no core C delegam a ele via FFI; as demais permanecem
 * implementadas em Rust puro.
 *
 * Nenhum nome de bool, variável ou função existente foi alterado.
 */

use std::io::{Read, Write};
use std::{
    fs,
    io::{BufReader, BufWriter},
    path::{Path, PathBuf},
};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use libc;

use std::ffi::{c_char, c_int, c_uint, CString, CStr};

#[cfg(target_os = "windows")]
use windows::Win32::Security::PSID;

/* ─────────────────────────────────────────────────────────────────────────
 *  FFI — símbolos exportados por vault_security.c
 *  (o .c é compilado como biblioteca estática: libvault_security.a)
 * ───────────────────────────────────────────────────────────────────────── */
#[link(name = "vault_security", kind = "static")]
unsafe extern "C" {
    /* System lifecycle — MUST be called on startup/shutdown */
    fn vault_ffi_init() -> c_int;
    fn vault_ffi_shutdown() -> c_int;

    /* Vault lifecycle */
    fn vault_create_ffi(
        name:     *const c_char,
        vault_type: c_int,          /* 0 = NORMAL, 1 = PROTECTED */
        path:     *const c_char,
        password: *const c_char,
    ) -> c_int;                     /* VaultError (0 = OK) */

    fn vault_delete_ffi(id: c_uint, password: *const c_char) -> c_int;

    fn vault_rename_ffi(
        id:       c_uint,
        new_name: *const c_char,
        password: *const c_char,
    ) -> c_int;

    fn vault_unlock_ffi(id: c_uint, password: *const c_char) -> c_int;

    fn vault_change_password_ffi(
        id:       c_uint,
        old_pass: *const c_char,
        new_pass: *const c_char,
    ) -> c_int;

    /* Crypto */
    fn vault_encrypt_ffi(id: c_uint, password: *const c_char) -> c_int;
    fn vault_decrypt_ffi(id: c_uint, password: *const c_char) -> c_int;

    /* Monitor / integrity */
    fn vault_scan_ffi(id: c_uint) -> c_int;
    fn vault_scan_report_ffi(id: c_uint, out: *mut c_char, out_len: usize) -> c_int;
    fn vault_resolve_ffi(id: c_uint, password: *const c_char) -> c_int;

    /* Display (print to stdout inside C) */
    fn vault_info_ffi(id: c_uint);
    fn vault_list_ffi();
    fn vault_files_ffi(id: c_uint);

    /* Sandbox */
    fn vault_sandbox_ffi(id: c_uint, password: *const c_char) -> c_int;

    /* Rule engine */
    fn vault_rule_ffi(
        vault_id:  c_uint,
        max_fails: c_int,
        hour_from: c_int,   /* -1 = sem restrição */
        hour_to:   c_int,
    ) -> c_int;

    /* Vault status (retorna status code do vault: 0=OK,1=LOCKED,2=ALERT,3=DELETED) */
    fn vault_get_status_ffi(id: c_uint) -> c_int;
    fn vault_export_file_ffi(id: c_uint, filename: *const c_char, dst_path: *const c_char) -> c_int;
    fn vault_export_and_decrypt_file_ffi(id: c_uint, filename: *const c_char, dst_path: *const c_char, password: *const c_char) -> c_int;
    fn vault_get_real_path_ffi(id: c_uint, out_path: *mut c_char, out_len: usize) -> c_int;
    fn vault_is_protected_ffi(id: c_uint) -> c_int;

    /* Engine de isolamento */
    fn vault_apply_engine_ffi(name: *const c_char, engine_level: c_int) -> c_int;
    fn vault_validate_engine_ffi(id: c_uint) -> c_int;

    /* PID Whitelist — fanotify anti-malware (Linux only) */
    fn vault_auth_pid_add_ffi(pid: libc::pid_t);
    fn vault_auth_pid_remove_ffi(pid: libc::pid_t);
    fn vault_auth_pid_is_authorized_ffi(pid: libc::pid_t) -> c_int;

    /* Bulk vault listing (elimina loop 1..100_000) */
    fn vault_list_ids_ffi(out: *mut VaultIdPath, out_cap: c_uint, out_count: *mut c_uint) -> c_int;
    fn vault_count_ffi() -> c_uint;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Sandbox — Windows AppContainer (mantido igual ao original)
 * ───────────────────────────────────────────────────────────────────────── */
#[cfg(target_os = "windows")]
#[link(name = "sandbox", kind = "static")]
unsafe extern "C" {
    pub fn setup_app_container(container_name: *const c_char, pSid: *mut PSID) -> bool;
    pub fn try_hard_isolate(app_path: *const c_char) -> bool;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  VaultIdPath — struct para bulk listing de cofres (FFI)
 * ───────────────────────────────────────────────────────────────────────── */

const VAULT_PATH_MAX: usize = 512;

#[repr(C)]
struct VaultIdPath {
    id:   c_uint,
    path: [u8; VAULT_PATH_MAX],
}

impl Default for VaultIdPath {
    fn default() -> Self {
        Self { id: 0, path: [0u8; VAULT_PATH_MAX] }
    }
}

/// Retorna todos os (id, path) de cofres ativos do catálogo C.
/// Substitui o antigo loop brute-force 1..=100_000.
pub fn vault_get_all_paths_pub() -> Vec<(u32, String)> {
    let mut buf: Vec<VaultIdPath> = (0..2048).map(|_| VaultIdPath::default()).collect();
    let mut count: c_uint = 0;
    let code = unsafe {
        vault_list_ids_ffi(buf.as_mut_ptr(), buf.len() as c_uint, &mut count)
    };
    if code != 0 { return vec![]; }

    buf.truncate(count as usize);
    buf.iter().map(|e| {
        let cstr = unsafe { CStr::from_ptr(e.path.as_ptr() as *const c_char) };
        (e.id, cstr.to_string_lossy().into_owned())
    }).collect()
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Helpers internos
 * ───────────────────────────────────────────────────────────────────────── */

fn find_existing_ancestor(path: &Path) -> PathBuf {
    let mut current = path.to_path_buf();
    while !current.exists() {
        if let Some(parent) = current.parent() {
            current = parent.to_path_buf();
        } else {
            break;
        }
    }
    current
}

fn contains_symlink(path: &Path) -> bool {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        if let Ok(metadata) = fs::symlink_metadata(ancestor) {
            if metadata.file_type().is_symlink() {
                return true;
            }
        }
    }
    false
}

fn find_registered_vault_by_path(target_path: &Path) -> Result<PathBuf, String> {
    // 1. Check if any component in the target_path is a symlink
    if contains_symlink(target_path) {
        return Err("Acesso negado: Links simbólicos não são permitidos para evitar vulnerabilidades de Symlink.".to_string());
    }

    // 2. Find the first existing ancestor of the path
    let existing_ancestor = find_existing_ancestor(target_path);

    // 3. Check if the existing ancestor contains symlinks
    if contains_symlink(&existing_ancestor) {
        return Err("Acesso negado: Links simbólicos detectados no caminho resolvido.".to_string());
    }

    // 4. Canonicalize the existing ancestor
    let canonical_target = match fs::canonicalize(&existing_ancestor) {
        Ok(path) => path,
        Err(e) => return Err(format!("Erro de validação: Falha ao resolver o caminho '{}': {}", existing_ancestor.display(), e)),
    };

    // 5. Gather all registered vault paths using bulk listing (was: brute-force 1..=100_000)
    for (_id, path_str) in vault_get_all_paths_pub() {
        if path_str.is_empty() { continue; }
        let vault_path = Path::new(&path_str);
        if contains_symlink(vault_path) {
            // Skip vault if it has symlinks to protect integrity
            continue;
        }
        if let Ok(canonical_vault) = fs::canonicalize(vault_path) {
            if canonical_target.starts_with(&canonical_vault) {
                return Ok(canonical_vault);
            }
        }
    }

    Err("Acesso negado: O caminho especificado não reside dentro de nenhum cofre registrado e ativo no catálogo.".to_string())
}

/// Converte &str → CString; em caso de byte nulo retorna Err com mensagem.
fn to_cstring(s: &str, label: &str) -> Result<CString, String> {
    CString::new(s).map_err(|_| format!("Caminho/string inválido para FFI (byte nulo em '{}')", label))
}

/// Converte Option<&str> → ponteiro C:
///   Some(s) → CString válido  → .as_ptr()
///   None    → std::ptr::null()
///
/// ATENÇÃO: o CString deve viver enquanto o ponteiro for usado.
/// Por isso retornamos Option<CString> junto com o ponteiro.
fn optional_cstr(opt: Option<&str>) -> (Option<CString>, *const c_char) {
    match opt {
        Some(s) => {
            let cs = CString::new(s).unwrap_or_else(|_| CString::new("").unwrap());
            let ptr = cs.as_ptr();
            (Some(cs), ptr)
        }
        None => (None, std::ptr::null()),
    }
}

/// Traduz VaultError (int) do C para Result Rust.
fn c_err(code: c_int) -> Result<(), String> {
    match code {
        0  => Ok(()),
        -1 => Err("Argumentos inválidos".to_string()),
        -2 => Err("Sem memória".to_string()),
        -3 => Err("Erro de I/O".to_string()),
        -4 => Err("Erro criptográfico".to_string()),
        -5 => Err("Falha de autenticação".to_string()),
        -6 => Err("Cofre bloqueado".to_string()),
        -7 => Err("Cofre já existe".to_string()),
        -8 => Err("Cofre não encontrado".to_string()),
        -9 => Err("Permissão negada".to_string()),
        -10 => Err("Catálogo cheio (máx. 2048 cofres)".to_string()),
        -11 => Err("Caminho inválido".to_string()),
        -12 => Err("Senha obrigatória para cofre protegido".to_string()),
        -13 => Err("Violação de integridade".to_string()),
        -14 => Err("Erro de sistema".to_string()),
        n   => Err(format!("Erro desconhecido (código {})", n)),
    }
}

/* 
 *  SYSTEM LIFECYCLE — init/shutdown do core C
 *  */

/// Inicializa o subsistema C: carrega catálogo do disco, inicia monitor.
/// Deve ser chamado UMA VEZ antes de qualquer outra operação vault.
pub fn vault_init() -> Result<(), String> {
    let code = unsafe { vault_ffi_init() };
    c_err(code)
}

/// Encerra o subsistema C: salva catálogo no disco, para monitor, limpa memória.
/// Deve ser chamado antes de sair (exit, Ctrl+C).
pub fn vault_shutdown() -> Result<(), String> {
    let code = unsafe { vault_ffi_shutdown() };
    c_err(code)
}

/* ─────────────────────────────────────────────────────────────────────────
 *  PID WHITELIST — fanotify anti-malware (Linux only)
 * ───────────────────────────────────────────────────────────────────────── */

/// Whitelists a PID so the fanotify monitor will allow its file access.
/// Call this for every child process that should be trusted (e.g. a text editor
/// launched by the user from inside the vault session).
#[cfg(target_os = "linux")]
pub fn vault_auth_pid_add(pid: libc::pid_t) {
    unsafe { vault_auth_pid_add_ffi(pid) }
}

/// Removes a PID from the whitelist.  Call this when the trusted process exits.
#[cfg(target_os = "linux")]
pub fn vault_auth_pid_remove(pid: libc::pid_t) {
    unsafe { vault_auth_pid_remove_ffi(pid) }
}

/// Returns `true` if the given PID (or any ancestor) is in the whitelist.
/// The IdenVault process itself is always considered authorized.
#[cfg(target_os = "linux")]
pub fn vault_auth_pid_is_authorized(pid: libc::pid_t) -> bool {
    unsafe { vault_auth_pid_is_authorized_ffi(pid) == 1 }
}

// No-op stubs for non-Linux platforms so callers compile everywhere.
#[cfg(not(target_os = "linux"))]
pub fn vault_auth_pid_add(_pid: i32) {}
#[cfg(not(target_os = "linux"))]
pub fn vault_auth_pid_remove(_pid: i32) {}
#[cfg(not(target_os = "linux"))]
pub fn vault_auth_pid_is_authorized(_pid: i32) -> bool { true }

/* 
 *  WRAPPERS PÚBLICOS — core C via FFI
 *  */

/// Cria um cofre no core C.
/// `vault_type`: "normal" | "protected"
pub fn vault_create(
    name:       Option<&str>,
    vault_type: &str,
    path:       Option<&str>,
    password:   Option<&str>,
) -> Result<(), String> {
    let vtype: c_int = if vault_type == "protected" { 1 } else { 0 };

    let (_cs_name, p_name)  = optional_cstr(name);
    let (_cs_path, p_path)  = optional_cstr(path);
    let (_cs_pass, p_pass)  = optional_cstr(password);

    let code = unsafe { vault_create_ffi(p_name, vtype, p_path, p_pass) };
    c_err(code)
}

/// Deleta cofre pelo ID.
pub fn vault_delete(id: u32, password: Option<&str>) -> Result<(), String> {
    let (_cs, p) = optional_cstr(password);
    let code = unsafe { vault_delete_ffi(id, p) };
    c_err(code)
}

/// Renomeia cofre.
pub fn vault_rename(id: u32, new_name: &str, password: Option<&str>) -> Result<(), String> {
    let cs_name = to_cstring(new_name, "new_name")?;
    let (_cs_pass, p_pass) = optional_cstr(password);
    let code = unsafe { vault_rename_ffi(id, cs_name.as_ptr(), p_pass) };
    c_err(code)
}

/// Desbloqueia cofre após lockout.
pub fn vault_unlock(id: u32, password: &str) -> Result<(), String> {
    let cs = to_cstring(password, "password")?;
    let code = unsafe { vault_unlock_ffi(id, cs.as_ptr()) };
    c_err(code)
}

/// Troca senha do cofre.
pub fn vault_change_password(id: u32, old_pass: &str, new_pass: &str) -> Result<(), String> {
    let cs_old = to_cstring(old_pass, "old_pass")?;
    let cs_new = to_cstring(new_pass, "new_pass")?;
    let code = unsafe { vault_change_password_ffi(id, cs_old.as_ptr(), cs_new.as_ptr()) };
    c_err(code)
}

/// Criptografa todos os arquivos do cofre (AES-256-CBC).
pub fn vault_encrypt(id: u32, password: &str) -> Result<(), String> {
    let cs = to_cstring(password, "password")?;
    let code = unsafe { vault_encrypt_ffi(id, cs.as_ptr()) };
    c_err(code)
}

/// Descriptografa arquivos .enc do cofre.
pub fn vault_decrypt(id: u32, password: &str) -> Result<(), String> {
    let cs = to_cstring(password, "password")?;
    let code = unsafe { vault_decrypt_ffi(id, cs.as_ptr()) };
    c_err(code)
}

/// Força varredura de integridade no cofre.
pub fn vault_scan(id: u32) -> Result<(), String> {
    let code = unsafe { vault_scan_ffi(id) };
    c_err(code)
}

/// Run a scan and return (issues_count, textual_report)
pub fn vault_scan_report(id: u32) -> Result<(usize, String), String> {
    let mut buf = vec![0u8; 8192];
    let code = unsafe { vault_scan_report_ffi(id, buf.as_mut_ptr() as *mut c_char, buf.len()) };
    if code < 0 {
        // translate C error
        return Err(c_err(code).err().unwrap_or_else(|| format!("Unknown error (code {})", code)));
    }
    let s = unsafe { CStr::from_ptr(buf.as_ptr() as *const c_char) }.to_string_lossy().into_owned();
    Ok((code as usize, s))
}

/// Resolve alerta ativo no cofre.
pub fn vault_resolve(id: u32, password: Option<&str>) -> Result<(), String> {
    let (_cs, p) = optional_cstr(password);
    let code = unsafe { vault_resolve_ffi(id, p) };
    c_err(code)
}

pub fn vault_get_real_path(id: u32) -> Result<String, String> {
    let mut buf = vec![0u8; 4096];
    let code = unsafe { vault_get_real_path_ffi(id, buf.as_mut_ptr() as *mut c_char, buf.len()) };
    if code != 0 {
        return Err(format!("Erro ao recuperar caminho real do cofre (código: {})", code));
    }
    let cstr = unsafe { CStr::from_ptr(buf.as_ptr() as *const c_char) };
    Ok(cstr.to_string_lossy().into_owned())
}

pub fn vault_is_protected(id: u32) -> bool {
    let code = unsafe { vault_is_protected_ffi(id) };
    code == 1
}

pub fn vault_export_and_decrypt(id: u32, filename: &str, dst_path: &str, password: &str) -> Result<(), String> {
    let cs_file = to_cstring(filename, "filename")?;
    let cs_dst = to_cstring(dst_path, "dst_path")?;
    let cs_pass = to_cstring(password, "password")?;
    let code = unsafe { vault_export_and_decrypt_file_ffi(id, cs_file.as_ptr(), cs_dst.as_ptr(), cs_pass.as_ptr()) };
    c_err(code)
}

pub fn vault_export_file(id: u32, filename: &str, dst_path: &str) -> Result<(), String> {
    let cs_file = to_cstring(filename, "filename")?;
    let cs_dst = to_cstring(dst_path, "dst_path")?;
    let code = unsafe { vault_export_file_ffi(id, cs_file.as_ptr(), cs_dst.as_ptr()) };
    c_err(code)
}

/// Exibe informações detalhadas de um cofre (saída no C via printf).
pub fn vault_info(id: u32) {
    unsafe { vault_info_ffi(id) }
}

/// Lista todos os cofres do catálogo (saída no C via printf).
pub fn vault_list() {
    unsafe { vault_list_ffi() }
}

/// Lista arquivos rastreados em um cofre.
pub fn vault_files(id: u32) {
    unsafe { vault_files_ffi(id) }
}

/// Abre cofre em shell sandbox (chroot/chdir no C).
pub fn vault_sandbox(id: u32, password: Option<&str>) -> Result<(), String> {
    let (_cs, p) = optional_cstr(password);
    let code = unsafe { vault_sandbox_ffi(id, p) };
    c_err(code)
}

/// Adiciona regra de segurança a um cofre.
/// `hour_from` / `hour_to`: None = sem restrição de horário.
pub fn vault_rule(
    vault_id:  u32,
    max_fails: i32,
    hour_from: Option<i32>,
    hour_to:   Option<i32>,
) -> Result<(), String> {
    let hf: c_int = hour_from.unwrap_or(-1);
    let ht: c_int = hour_to.unwrap_or(-1);
    let code = unsafe { vault_rule_ffi(vault_id, max_fails, hf, ht) };
    c_err(code)
}

/// Exporta um arquivo do cofre para um destino externo via Core C (que chama o callback Rust).
/* 
 *  FUNÇÕES ORIGINAIS RUST — mantidas integralmente, sem renomear nada
 *  */

/// Função que o main.rs está tentando chamar (Windows AppContainer sandbox).
pub fn run_in_sandbox(path: &str) {
    println!("🛡️ IdenVault: Iniciando isolamento para {}", path);

    let c_path = match CString::new(path) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("❌ Falha ao converter caminho para CString: {}", path);
            return;
        }
    };

    #[cfg(target_os = "windows")]
    unsafe {
        let container_name = format!("IdenVault_Sandbox_{}", std::process::id());
        let c_container_name = match CString::new(container_name.clone()) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("❌ Falha ao criar nome do AppContainer");
                return;
            }
        };

        let mut sid = PSID(std::ptr::null_mut());

        if setup_app_container(c_container_name.as_ptr(), &mut sid) {
            println!("✅ AppContainer '{}' configurado com sucesso", container_name);
            println!("SID do AppContainer: {:?}", sid);

            if try_hard_isolate(c_path.as_ptr()) {
                println!("✅ Processo isolado com sucesso (Sandbox + Firewall + Desktop)");
            } else {
                eprintln!("❌ Falha ao aplicar isolamento de segurança.");
            }
        } else {
            eprintln!("❌ Falha ao configurar AppContainer '{}'", container_name);
        }
    }

    /* Em Linux o sandbox é tratado pelo vault_sandbox() via core C (chroot/fork). */
    #[cfg(not(target_os = "windows"))]
    {
        eprintln!(
            "ℹ️  run_in_sandbox: no Linux use 'sandbox <id>' para isolamento via core C (chroot/fork)."
        );
        let _ = c_path; /* evita warning de variável não usada */
    }
}

pub fn isolate_directory(directory: &str) {
    let home_dir = home::home_dir().unwrap_or_default();
    let sandbox_path = home_dir.join("IdenVault").join("sandbox");

    let files = read_directory(directory);
    let dir_sandbox = Path::new(&sandbox_path);

    if !dir_sandbox.exists() {
        if let Err(e) = std::fs::create_dir_all(&sandbox_path) {
            eprintln!("Falha ao criar diretório sandbox: {}", e);
            return;
        }
    }

    let full_path = dir_sandbox.join(directory);
    if !full_path.exists() {
        if let Err(e) = std::fs::create_dir_all(&full_path) {
            eprintln!("Falha ao criar subdiretório sandbox: {}", e);
            return;
        }
    }

    let c_path = match CString::new(directory) {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Caminho inválido para FFI (contém byte nulo?)");
            return;
        }
    };

    println!("Tentando isolamento avançado (mount namespace + readonly)...");

    /* No Linux delegamos ao core C */
    #[cfg(not(target_os = "windows"))]
    let isolated = {
        /* vault_sandbox_ffi com id=0 não faz sentido; isolate_directory mantém
         * sua lógica Rust original — apenas tenta via try_hard_isolate se disponível.
         * Como no Linux não temos AppContainer, simplesmente prosseguimos com
         * o fallback readonly abaixo. */
        let _ = c_path;
        false
    };

    #[cfg(target_os = "windows")]
    let isolated = unsafe { try_hard_isolate(c_path.as_ptr()) };

    if isolated {
        println!("Isolamento forte aplicado (namespace + readonly)");
    } else {
        println!("Isolamento namespace falhou (provável falta de privilégio)");
        println!("Aplicando isolamento básico (readonly)...");
    }

    println!("Isolando diretório {}", directory);
    println!("Arquivos encontrados:");

    for file in files {
        println!(" - {}", file);
    }

    if let Ok(metadata) = fs::metadata(directory) {
        let mut permission = metadata.permissions();
        permission.set_readonly(true);
        if let Err(e) = fs::set_permissions(directory, permission) {
            eprintln!("Falha ao aplicar permissão readonly: {}", e);
        } else {
            println!("Permissão readonly aplicada com sucesso (fallback)");
        }
    } else {
        eprintln!("Não foi possível ler metadados do diretório");
    }
}

pub fn create(dir: &str) {
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("Erro ao criar cofre: {}", e);
    } else {
        println!("Cofre criado com sucesso em {}", dir);
    }
}

pub fn add_file(vault: &str, file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = Path::new(vault);
    let file_path  = Path::new(file);

    // Confinement validation for vault path
    find_registered_vault_by_path(vault_path)?;

    // Reject symlinks for source file
    if contains_symlink(file_path) {
        return Err("Acesso negado: Links simbólicos não são permitidos para o arquivo de origem.".to_string().into());
    }

    if !vault_path.exists() {
        eprintln!("Cofre não encontrado: {}", vault);
        return Ok(());
    }

    if !file_path.exists() || !file_path.is_file() {
        eprintln!("Arquivo inválido: {}", file);
        return Ok(());
    }

    let file_name   = file_path.file_name().ok_or("Falha ao obter nome do arquivo")?;
    let destination: PathBuf = vault_path.join(file_name);

    // Confinement validation for destination path
    find_registered_vault_by_path(&destination)?;

    if destination.exists() {
        eprintln!("Arquivo já existe no cofre: {}", destination.display());
        return Ok(());
    }

    // Use safe_copy to ensure secure copying and rejection of symlinks
    safe_copy(file_path, &destination)?;

    Ok(())
}

pub fn safe_copy<P: AsRef<Path>>(src: P, dstn: P) -> Result<(), Box<dyn std::error::Error>> {
    let source_path      = src.as_ref();
    let destination_path = dstn.as_ref();
    let temporary_path   = destination_path.with_extension("tmp_copy");

    // Reject symlinks for source and destination paths to avoid symlink-traversal attacks
    let sm = source_path.symlink_metadata()?;
    if sm.file_type().is_symlink() {
        return Err(format!("Refusing to copy from symlink source: {}", source_path.display()).into());
    }
    if destination_path.exists() {
        let dm = destination_path.symlink_metadata()?;
        if dm.file_type().is_symlink() {
            return Err(format!("Refusing to write to symlink destination: {}", destination_path.display()).into());
        }
    }

    // Open source with O_NOFOLLOW to atomically refuse symlinks
    #[cfg(unix)]
    let source_file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source_path)?;

    #[cfg(not(unix))]
    let source_file = fs::OpenOptions::new()
        .read(true)
        .open(source_path)?;

    let mut origin_file = BufReader::new(source_file);

    // Create temporary file using O_NOFOLLOW and create_new to avoid TOCTOU
    #[cfg(unix)]
    let temporary_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary_path)?;

    #[cfg(not(unix))]
    let temporary_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_path)?;

    let mut writer = BufWriter::new(temporary_file);

    let mut buffer = [0u8; 65536];
    loop {
        let bytes_read = origin_file.read(&mut buffer)?;
        if bytes_read == 0 { break; }
        writer.write_all(&buffer[..bytes_read])?;
    }
    writer.flush()?;

    fs::rename(&temporary_path, destination_path)?;
    Ok(())
}

pub fn secure_store(src: &str, vault: &str, password: &str) {
    let source     = Path::new(src);
    let vault_path = Path::new(vault);

    // Reject symlink sources
    if contains_symlink(source) {
        eprintln!("Refusing to operate on symlink source: {}", src);
        return;
    }

    // Confinement validation for vault path
    if let Err(e) = find_registered_vault_by_path(vault_path) {
        eprintln!("🛡️ ALERTA DE SEGURANÇA: Tentativa de operação fora de cofre registrado! Detalhes: {}", e);
        return;
    }

    if !source.exists() {
        eprintln!("Erro: Arquivo de origem não existe: {}", src);
        return;
    }
    if !vault_path.exists() {
        eprintln!("Erro: Cofre (diretório) não existe: {}", vault);
        return;
    }

    let file_name = match source.file_name() {
        Some(name) => name,
        None => return,
    };
    let destination = vault_path.join(file_name);

    // Confinement validation for destination path
    if let Err(e) = find_registered_vault_by_path(&destination) {
        eprintln!("🛡️ ALERTA DE SEGURANÇA: Caminho de destino fora do cofre! Detalhes: {}", e);
        return;
    }

    if let Err(e) = safe_copy(source, &destination) {
        eprintln!("Erro ao copiar arquivo para o cofre: {}", e);
        return;
    }
    let destination_in_vault = destination;

    if let Err(e) = crate::crypto::encrypt_file(&destination_in_vault, password) {
        eprintln!("Erro ao criptografar arquivo no cofre: {}", e);
        return;
    }
    let _ = fs::remove_file(&destination_in_vault);
    let _ = fs::remove_file(source);
}

pub fn read_directory(directory: &str) -> Vec<String> {
    let mut files = Vec::new();
    let path = Path::new(directory);

    // Confinement validation
    if let Err(e) = find_registered_vault_by_path(path) {
        eprintln!("🛡️ ALERTA DE SEGURANÇA: Bloqueada tentativa de listagem fora do cofre! Detalhes: {}", e);
        return files;
    }

    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("Erro ao ler diretório {}: {}", directory, e);
            return files;
        }
    };

    for entry in entries.flatten() {
        if let Ok(file_type) = entry.file_type() {
            if file_type.is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    files.push(name.to_string());
                }
            }
        }
    }

    println!("Total de arquivos: {}", files.len());

    if files.is_empty() {
        eprintln!("Nenhum arquivo encontrado em: {}", directory);
    }

    files
}

/* ─────────────────────────────────────────────────────────────────────────
 *  REVERSE FFI — Funções Rust chamadas pelo Core C
 * ───────────────────────────────────────────────────────────────────────── */

/// Copia um arquivo usando a lógica Rust (safe_copy).
/// Chamada pelo C para exportar arquivos do cofre ou adicionar arquivos externos.
#[no_mangle]
pub extern "C" fn rust_vault_copy_file(src: *const c_char, dst: *const c_char) -> c_int {
    if src.is_null() || dst.is_null() { return -1; }

    let s_src = unsafe { std::ffi::CStr::from_ptr(src) }.to_string_lossy();
    let s_dst = unsafe { std::ffi::CStr::from_ptr(dst) }.to_string_lossy();

    let path_src = Path::new(s_src.as_ref());
    let path_dst = Path::new(s_dst.as_ref());

    // Validate that either source or destination resides strictly inside a registered vault
    let src_ok = find_registered_vault_by_path(path_src).is_ok();
    let dst_ok = find_registered_vault_by_path(path_dst).is_ok();

    if !src_ok && !dst_ok {
        eprintln!("❌ [RUST CALLBACK] Bloqueado: Tentativa de cópia fora de cofre registrado!");
        return -9; // ERR_PERM_DENIED (-9)
    }

    match safe_copy(s_src.as_ref(), s_dst.as_ref()) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("❌ [RUST CALLBACK] Erro em safe_copy: {}", e);
            -3 // ERR_IO
        }
    }
}

/// Remove um arquivo usando fs::remove_file.
#[no_mangle]
pub extern "C" fn rust_vault_remove_file(path: *const c_char) -> c_int {
    if path.is_null() { return -1; }
    let s_path = unsafe { std::ffi::CStr::from_ptr(path) }.to_string_lossy();

    let file_path = Path::new(s_path.as_ref());
    if let Err(e) = find_registered_vault_by_path(file_path) {
        eprintln!("❌ [RUST CALLBACK] Bloqueado: Tentativa de remoção fora de cofre registrado! Detalhes: {}", e);
        return -9; // ERR_PERM_DENIED (-9)
    }

    match fs::remove_file(s_path.as_ref()) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("❌ [RUST CALLBACK] Erro em remove_file: {}", e);
            -3 // ERR_IO
        }
    }
}

#[allow(dead_code)]
pub fn allow_write(path: &str) {
    let file_exists = Path::new(path);

    if let Err(e) = find_registered_vault_by_path(file_exists) {
        eprintln!("🛡️ ALERTA DE SEGURANÇA: Bloqueada tentativa de alteração fora do cofre! Detalhes: {}", e);
        return;
    }

    if !file_exists.exists() {
        println!("Arquivo não encontrado: {}", path);
        return;
    }

    if let Ok(metadata) = fs::metadata(file_exists) {
        let mut permission = metadata.permissions();
        permission.set_readonly(false);
        if let Err(e) = fs::set_permissions(path, permission) {
            eprintln!("Falha ao setar permissão de escrita: {}", e);
        }
    }
}

pub fn remove_file(vault: &str, file_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = Path::new(vault);
    let file_path  = vault_path.join(file_name);

    // Confinement validation for vault path
    find_registered_vault_by_path(vault_path)?;

    // Confinement validation for file path
    find_registered_vault_by_path(&file_path)?;

    if !file_path.exists() {
        return Err(format!(
            "Arquivo '{}' não encontrado no cofre '{}'",
            file_name, vault
        ).into());
    }

    fs::remove_file(file_path)?;
    println!("✔ Arquivo '{}' removido do cofre '{}'", file_name, vault);
    Ok(())
}

/// Retorna status textual do cofre consultando o core C.
/// Se o id não for numérico, cai no fallback Rust original (verifica caminho).
pub fn get_vault_status(vault: &str) -> Result<(), Box<dyn std::error::Error>> {
    /* Tenta interpretar o argumento como ID numérico primeiro */
    if let Ok(id) = vault.parse::<u32>() {
        let status_code = unsafe { vault_get_status_ffi(id) };
        let status_str = match status_code {
            0 => "OK",
            1 => "LOCKED",
            2 => "ALERT",
            3 => "DELETED",
            _ => "DESCONHECIDO",
        };
        println!("\n--- Status do Cofre (id={}) ---", id);
        println!("Status: {}", status_str);

        /* Lista arquivos via core C também */
        unsafe { vault_files_ffi(id) }
        return Ok(());
    }

    /* Fallback: caminho Rust original */
    let vault_path = Path::new(vault);
    if !vault_path.exists() {
        return Err(format!("Cofre '{}' não encontrado", vault).into());
    }

    let files = read_directory(vault);
    let mut total_size = 0;
    for file in &files {
        let path = vault_path.join(file);
        if let Ok(metadata) = fs::metadata(path) {
            total_size += metadata.len();
        }
    }

    println!("\n--- Status do Cofre: {} ---", vault);
    println!("Total de arquivos: {}", files.len());
    println!("Tamanho total: {:.2} KB", total_size as f64 / 1024.0);
    Ok(())
}

/* ─────────────────────────────────────────────────────────────────────────
 *  ENGINE DE ISOLAMENTO — Honeyfile Labyrinth
 * ───────────────────────────────────────────────────────────────────────── */

/// Aplica o engine de isolamento ao vault recém-criado.
/// `name`: nome do vault (usado para localizar no catálogo C).
/// `engine_level`: 1-5 (0 = sem engine, não deve ser chamado).
pub fn vault_apply_engine(name: Option<&str>, engine_level: i32) -> Result<(), String> {
    let name_str = name.unwrap_or("");
    if name_str.is_empty() {
        return Err("Nome do vault obrigatório para aplicar engine".to_string());
    }
    if !(1..=5).contains(&engine_level) {
        return Err(format!("Engine inválido: {} (válido: 1-5)", engine_level));
    }

    let cs_name = to_cstring(name_str, "vault_apply_engine/name")?;

    let code = unsafe { vault_apply_engine_ffi(cs_name.as_ptr(), engine_level) };
    c_err(code)
}

/// Valida a integridade do labirinto de um vault pelo ID.
/// Retorna Err se o labirinto estiver comprometido.
pub fn vault_validate_engine(id: u32) -> Result<(), String> {
    let code = unsafe { vault_validate_engine_ffi(id) };
    c_err(code)
}
