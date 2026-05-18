
#[allow(dead_code)]

#[cfg(windows)]
use windows::Win32::Security::PSID;

use sysinfo::{
     Disks, Networks, System,
};

#[cfg(windows)]
unsafe extern "C" {
    fn setup_app_container(container_name: *const i8, pSid: *mut PSID) -> bool;
    fn try_hard_isolate(executable_path: *const i8) -> bool;
}
/// Lista todos os processos ativos com detalhes de consumo e status de isolamento
pub fn list_process_status(options: &SystemOptions) {
    let mut sys = System::new_all();
    sys.refresh_all();

    println!("\n{:<10} {:<25} {:<12} {:<15}", "PID", "PROCESSO", "MEMÓRIA", "STATUS");
    println!("{:-<62}", "");

    for (pid, process) in sys.processes() {
        let pid_u32 = pid.as_u32();
        
        // Converte bytes para MB (1024 * 1024)
        let mem_mb = process.memory() as f64 / 1_048_576.0;

        // Lógica de status: se o sandbox.c já isolou, aqui você apenas reporta o estado atual
        let status = if process.cpu_usage() > 0.0 { 
            "ISOLADO/ATIVO" 
        } else { 
            "ISOLADO/IDLE" 
        };

        // Filtro opcional: mostra apenas se o usuário pediu ou se o processo está ativo
        if options.processes {
            println!(
                "{:<10} {:<25} {:<12.2} MB {:<15}",
                pid_u32,
                process.name().to_string_lossy(),
                mem_mb,
                status
            );
        }
    }
}
#[cfg(windows)]
pub fn check_setup_app_container_and_try_hard_isolate() {
    let container_name = format!("IdenVault_Sandbox_{}", std::process::id());
    let mut sid = PSID(std::ptr::null_mut());

    unsafe {
        if setup_app_container(container_name.as_ptr() as *const i8, &mut sid) {
            println!("✅ AppContainer '{}' configurado com sucesso", container_name);
            println!("SID do AppContainer: {:?}", sid);
        } else {
            eprintln!("❌ Falha ao configurar AppContainer '{}'", container_name);
        }
    }
    
    let try_hard_isolate_result =  format!("Resultado de try_hard_isolate: {}", 
    unsafe { try_hard_isolate(container_name.as_ptr() as *const i8) });
    println!("{}", try_hard_isolate_result);
}

#[cfg(not(windows))]
pub fn check_setup_app_container_and_try_hard_isolate() {
    println!("⚠️  AppContainer é específico do Windows. Executando em Linux.");
}

// Função utilitária para converter MB → KB
fn mb_to_kb_binary(mb: f64) -> f64 {
    mb * 1024.0
}

// Estrutura de opções para escolher quais infos mostrar
pub struct SystemOptions {
    pub cpu: bool,
    pub memory: bool,
    pub disks: bool,
    pub networks: bool,
    pub processes: bool,
}

// Função principal para mostrar informações do sistema
pub fn system_information(options: SystemOptions) {
    // System cuida de CPU, Memória e Processos
    let mut sys_info = System::new_all();
    sys_info.refresh_all();

    println!("--- System IdenVault ---");

    // CPU
    if options.cpu {
        println!("CPU:");
        for cpu in sys_info.cpus() {
            println!("  - {}: {:.2}% usage", cpu.name(), cpu.cpu_usage());
        }
    }

    // Memória
    if options.memory {
        println!("Memory:");
        // sysinfo retorna bytes. Convertendo para MB primeiro, depois para KB como no seu utilitário
        let total_mem_mb = sys_info.total_memory() as f64 / 1_048_576.0;
        let used_mem_mb = sys_info.used_memory() as f64 / 1_048_576.0;
        let free_mem_mb = sys_info.free_memory() as f64 / 1_048_576.0;

        println!("  - Total: {:.2} MB", total_mem_mb);
        println!("  - Used: {:.2} KB", mb_to_kb_binary(used_mem_mb));
        println!("  - Free: {:.2} KB", mb_to_kb_binary(free_mem_mb));
    }

    if options.disks {
        println!("Disks:");
        let disks = Disks::new_with_refreshed_list();
        for disk in &disks {
            println!(
                "  - {:?}: {:.2} GB total, {:.2} GB available",
                disk.name(),
                disk.total_space() as f64 / 1_073_741_824.0,
                disk.available_space() as f64 / 1_073_741_824.0
            );
        }
    }

    
    if options.networks {
        println!("Networks:");
        let networks = Networks::new_with_refreshed_list();
        for (interface_name, network) in &networks {
            println!(
                "  - {}: {} bytes transmitted, {} bytes received",
                interface_name,
                network.transmitted(),
                network.received()
            );
        }
    }

    // Processos
    if options.processes {
        println!("Processes:");
        for (pid, process) in sys_info.processes() {
            println!(
                "  - {:?} (PID {}): {:.2}% CPU, {:.2} MB memory",
                process.name(),
                pid,
                process.cpu_usage(),
                process.memory() as f64 / 1_048_576.0
            );
        }
    }
}