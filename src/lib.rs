use jni::{JNIEnv, JavaVM};
use jni::objects::JString;
use jni::sys::{jstring, JavaVM as RawJavaVM};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::{
    os::fd::{AsFd, AsRawFd},
    time::Duration,
};
use log::{warn, error, info, debug};
use zygisk_rs::{Api, AppSpecializeArgs, Module, ServerSpecializeArgs, register_zygisk_module};
mod art_runtime;
mod dex_parser;
mod dex_scanner;

const LOG_TAG: &str = "RustDexUnpacker";

struct SendableVmPtr(usize);
unsafe impl Send for SendableVmPtr {}

struct MyModule {
    api: Api,
    vm: JavaVM,
    should_scan: bool,
    force_resolve: bool,
}

impl Module for MyModule {
    fn new(api: Api, env: *mut jni_sys::JNIEnv) -> Self {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Info)
                .with_tag(LOG_TAG),
        );
        let env = unsafe { JNIEnv::from_raw(env.cast()).unwrap() };
        let vm = env.get_java_vm().expect("Failed to get JavaVM");
        let should_scan: bool = false;
        let force_resolve: bool = false;
        Self {
            api,
            vm,
            should_scan,
            force_resolve,
        }
    }

    fn pre_app_specialize(&mut self, args: &mut AppSpecializeArgs) {
        let module_dir_fd = match self.api.get_module_dir() {
            Some(fd) => fd,
            None => {
                warn!("Can not get module dir");
                self.api.set_option(zygisk_rs::ModuleOption::ForceDenylistUnmount);
                return;
            }
        };

        let mut env = self.vm.get_env().expect("Failed to get JNIEnv for pre_app_specialize");

        let fd_num = module_dir_fd.as_fd().as_raw_fd();
        let whitelist_path = std::path::PathBuf::from(format!("/proc/self/fd/{}/whitelist.txt", fd_num));
        match std::fs::File::open(&whitelist_path) {
            Ok(file) => {
                let reader = BufReader::new(file);
                let whitelist: std::collections::HashSet<String> = reader
                    .lines()
                    .filter_map(|line| line.ok())
                    .map(|line| line.trim().to_string())
                    .filter(|line| !line.is_empty() && !line.starts_with('#'))
                    .collect();

                let package_name = unsafe { JString::from_raw(*args.nice_name as jstring) };
                
                let package_name = env
                    .get_string(&package_name)
                    .map(|java_str| java_str.to_string_lossy().into_owned())
                    .unwrap_or_else(|e| {
                        error!("Failed to get package name: {:?}", e);
                        "unknown".to_string()
                    });

                if whitelist.contains(&package_name.to_string()) {
                    info!("Package {} in whitelist, Setting scan flag to true", package_name);
                    self.should_scan = true;
                } else {
                    self.should_scan = false;
                }
            }
            Err(e) => {
                debug!("Whitelist parsing error {:?}: {}", whitelist_path, e);
            }
        }

        let force_resolve_settings_path  = std::path::PathBuf::from(format!("/proc/self/fd/{}/force_resolve.txt", fd_num));
        match std::fs::File::open(&force_resolve_settings_path) {
            Ok(_file) => {
                self.force_resolve = true;
            }
            Err(_e) => {
                self.force_resolve = false;
            }
        }
        self.api.set_option(zygisk_rs::ModuleOption::ForceDenylistUnmount);
    }

    fn post_app_specialize(&mut self, args: &AppSpecializeArgs) {
        if !self.should_scan {
            self.api.set_option(zygisk_rs::ModuleOption::DlcloseModuleLibrary);
            return;
        }

        let mut env = self.vm.get_env().expect("Failed to get JNIEnv for post_app_specialize");
        let package_name = unsafe { JString::from_raw(*args.nice_name as jstring) };
        let package_name = env
            .get_string(&package_name)
            .map(|java_str| java_str.to_string_lossy().into_owned())
            .unwrap_or_else(|e| {
                error!("Failed to get package name: {:?}", e);
                "unknown".to_string()
            });

        info!("Dump dex for {}, Spawning scanner thread...", package_name);

        let vm_ptr: *mut RawJavaVM = self.vm.get_java_vm_pointer();
        
        // Cast the pointer to usize before wrapping
        let sendable_vm_ptr = SendableVmPtr(vm_ptr as usize);
        let should_force_resolve = self.force_resolve;
        std::thread::spawn(move || {
            info!("--- Starting DEX Scan for {} (Waiting 10s & Deep Search: true) ---", package_name);
            std::thread::sleep(Duration::from_secs(10));

            let vm_ptr = sendable_vm_ptr.0 as *mut RawJavaVM;
            let vm = match unsafe { JavaVM::from_raw(vm_ptr) } {
                Ok(vm) => vm,
                Err(e) => {
                    error!("[ScannerThread] Failed to re-create JavaVM: {:?}", e);
                    return;
                }
            };
            
            let dump_dir = format!("/data/data/{}/files/rust_dumps", package_name);
            match std::fs::remove_dir_all(&dump_dir) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(_e) => {}
            }

            match dex_scanner::scan_memory(true) {
                Ok(results) => {
                    if results.is_empty() {
                        info!("No DEX files found in suspicious memory regions");
                    } else {
                        info!("Found {} potential DEX files:", results.len());

                        match std::fs::create_dir_all(&dump_dir) {
                            Ok(_) => {
                                for (i, dex) in results.iter().enumerate() {
                                    info!("Found dex [{}]: Address=0x{:x}, Size=0x{:.x} ({}), Version: {}, Source: {}", i, dex.addr, dex.size, dex.size, dex.version, dex.source);
                                    let pid = std::process::id() as libc::pid_t;
                                    match dex_parser::parse_dex_at(pid, dex.addr) {
                                        Ok(dex_file) => {
                                            if !dex_file.methods.is_empty() {
                                                info!( "Parsed DEX #{} ({} methods), triggering method resolution...", i, dex_file.methods.len());
                                                if should_force_resolve {
                                                    art_runtime::force_resolve_methods(&vm, &dex_file.methods);
                                                }
                                            } else {
                                                info!("Parsed DEX #{} has no methods, skipping resolution.", i);
                                            }
                                            
                                            if let Err(e) =
                                                dump_dex_to_file(&dump_dir, i, dex.addr, dex.size)
                                            {
                                                error!("Failed to save DEX #{}, error: {}", i, e);
                                            }
                                        }
                                        Err(e) => {
                                            error!("Failed to parse DEX #{}, error: {}", i, e);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to create DEX save dir {} error: {}", dump_dir, e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to scan DEX, error: {}", e);
                }
            }
            
            info!("--- DEX Scan Finished for {}  ---", package_name);
        });
    }

    fn pre_server_specialize(&mut self, _args: &mut ServerSpecializeArgs) {}

    fn post_server_specialize(&mut self, _args: &ServerSpecializeArgs) {}
}

register_zygisk_module!(MyModule);

fn dump_dex_to_file(dump_dir: &str, index: usize, addr: usize, size: usize) -> std::io::Result<()> {
    let file_path = format!("{}/dex_{}_{:x}.dex", dump_dir, index, addr);

    let data_slice = unsafe { std::slice::from_raw_parts(addr as *const u8, size) };

    let mut file = File::create(&file_path)?;
    file.write_all(data_slice)?;

    info!("Dex saved to {}", file_path);
    Ok(())
}