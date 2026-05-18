// build.rs
//
// Compiles the vault security C modules into libvault_security.a
// and links them into the Rust binary.
//
// New structure (split from diamondVaults.c):
//   vault_core.h      — header (structs, enums, constants)
//   vault_crypto.c    — logging, sanitisation, SHA-256, PBKDF2, AES-256-GCM
//   vault_catalog.c   — hashmap, catalog save/load, vault CRUD, globals
//   vault_monitor.c   — inotify, alerts, rules, monitor thread
//   vault_sandbox.c   — sandbox v2 (Linux) / stub (Windows)
//   vault_ffi.c       — FFI wrappers + init/shutdown

use std::process::Command;

fn main() {
    // ====================== ÍCONE DO EXECUTÁVEL (Windows) ======================
    #[cfg(target_os = "windows")]
    {
        let mut res = winresource::WindowsResource::new();
        
        // ←←← MUDE AQUI para o caminho correto da sua logo
        res.set_icon("img/VaranusCore.ico");    
        
        res.set("FileDescription", "IdenVault - Vault Security System");
        res.set("ProductName", "IdenVault");
        res.set("CompanyName", "Pedrão Projects");
        res.set("LegalCopyright", "© 2026 Pedrão");
        res.set("FileVersion", env!("CARGO_PKG_VERSION"));
        res.set("ProductVersion", env!("CARGO_PKG_VERSION"));
        
        res.compile().unwrap();
    }

    // ====================== COMPILAÇÃO DOS ARQUIVOS C ======================
    let out_dir = std::env::var("OUT_DIR").unwrap();

    // List of C source files to compile
    let c_sources = [
        "c_src/vault_crypto.c",
        "c_src/vault_catalog.c",
        "c_src/vault_monitor.c",
        "c_src/vault_sandbox.c",
        "c_src/vault_engine.c",
        "c_src/vault_ffi.c",
    ];

    let mut object_files: Vec<String> = Vec::new();

    for src in &c_sources {
        // Extract base name for the .o file
        let base = std::path::Path::new(src)
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap();

        let obj_path = format!("{}/{}.o", out_dir, base);

        let mut gcc_args = vec![
            "-Os".to_string(), // Otimiza para tamanho
            "-fdata-sections".to_string(), // Seções de dados individuais
            "-ffunction-sections".to_string(), // Seções de funções individuais
            "-Wall".to_string(),
            "-Wextra".to_string(),
            "-DVAULT_FFI_BUILD".to_string(),
            "-fPIC".to_string(),
            "-c".to_string(),
            "-I".to_string(),
            "c_src".to_string(),
            src.to_string(),
            "-o".to_string(),
            obj_path.clone(),
        ];

        // On Linux, add include paths for OpenSSL, seccomp, etc.
        if cfg!(target_os = "linux") {
            gcc_args.push("-pthread".to_string());
        }

        let status = Command::new("gcc")
            .args(&gcc_args)
            .status()
            .unwrap_or_else(|e| panic!("Failed to compile {}: {}", src, e));

        assert!(status.success(), "Compilation of {} failed", src);

        object_files.push(obj_path);
    }

    // Create static library from all object files
    let lib_path = format!("{}/libvault_security.a", out_dir);

    let mut ar_args = vec!["rcs".to_string(), lib_path];
    ar_args.extend(object_files);

    let status = Command::new("ar")
        .args(&ar_args)
        .status()
        .expect("Failed to create libvault_security.a");

    assert!(status.success(), "Static library creation failed");

    // Link to Rust
    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=vault_security");
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");

    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=seccomp");
        println!("cargo:rustc-link-lib=cap");
    }

    // Recompile if C sources change
    println!("cargo:rerun-if-changed=c_src/vault_core.h");
    for src in &c_sources {
        println!("cargo:rerun-if-changed={}", src);
    }
}