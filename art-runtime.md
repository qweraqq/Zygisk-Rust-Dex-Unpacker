You are both an Rust specialist and an Android Zygisk module specialist.
I hava developed a zygisk module.
The module can dump dex from memroy.
I have verified that the module works.
Please add a new feature to this module.
**Actively call `GetCodeItem` on each method**

Do not modify dex_parser.rs and dex_scanner.rs.
Add a new file art_runtime.rs and implement the `GetCodeItem` logic in art_runtime.rs.
Illustrate how to call the logic in lib.rs.

Provide full code of art_runtime.rs.

- lib.rs
```rust
use jni::{JNIEnv, JavaVM};
use jni::objects::JString;
use jni::sys::jstring;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::{
    os::fd::{AsFd, AsRawFd},
    time::Duration,
};
use zygisk_rs::{Api, AppSpecializeArgs, Module, ServerSpecializeArgs, register_zygisk_module};
mod dex_parser;
mod dex_scanner;


const LOG_TAG: &str = "RustDexUnpacker";

struct MyModule {
    api: Api,
    vm: JavaVM,
    should_scan: bool,
}

impl Module for MyModule {
    fn new(api: Api, env: *mut jni_sys::JNIEnv) -> Self {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Info)
                .with_tag(LOG_TAG),
        );
        let env = unsafe { JNIEnv::from_raw(env.cast()).unwrap() };
        let vm = env.get_java_vm().expect("Failed to get JavaVM"); // 获取 VM
        let should_scan: bool = false;
        Self {
            api,
            vm,
            should_scan,
        }
    }

    fn pre_app_specialize(&mut self, args: &mut AppSpecializeArgs) {
        let module_dir_fd = match self.api.get_module_dir() {
            Some(fd) => fd,
            None => {
                log::warn!("Can not get module dir");
                self.api
                    .set_option(zygisk_rs::ModuleOption::ForceDenylistUnmount);
                return;
            }
        };

        let fd_num = module_dir_fd.as_fd().as_raw_fd();
        let whitelist_path =
            std::path::PathBuf::from(format!("/proc/self/fd/{}/whitelist.txt", fd_num));
        match std::fs::File::open(&whitelist_path) {
            Ok(file) => {
                let reader = BufReader::new(file);
                let whitelist: std::collections::HashSet<String> = reader
                    .lines()
                    .filter_map(|line| line.ok())
                    .map(|line| line.trim().to_string())
                    .filter(|line| !line.is_empty() && !line.starts_with('#'))
                    .collect();

                // log::info!("Loading whitelist, {} items in whitelist", whitelist.len());
                let package_name = unsafe { JString::from_raw(*args.nice_name as jstring) };
                let mut env = self.vm.get_env().expect("Failed to get JNIEnv");
                let package_name = env
                    .get_string(&package_name)
                    .map(|java_str| java_str.to_string_lossy().into_owned())
                    .unwrap_or_else(|e| {
                        log::error!("Failed to get package name: {:?}", e);
                        "unknown".to_string()
                    });

                if whitelist.contains(&package_name.to_string()) {
                    log::info!(
                        "Package {} in whitelist, Setting scan flag to true",
                        package_name
                    );
                    self.should_scan = true;
                } else {
                    // log::info!("Package {} not in whitelist, setting scan flag to false", package_name);
                    self.should_scan = false;
                }
            }
            Err(_e) => {
                // log::warn!("Whitelist parsing error {:?}: {}", whitelist_path, e);
            }
        }

        self.api
            .set_option(zygisk_rs::ModuleOption::ForceDenylistUnmount);
    }

    fn post_app_specialize(&mut self, args: &AppSpecializeArgs) {
        if !self.should_scan {
            self.api
                .set_option(zygisk_rs::ModuleOption::DlcloseModuleLibrary);
            return;
        }

        let package_name = unsafe { JString::from_raw(*args.nice_name as jstring) };
        let mut env = self.vm.get_env().expect("Failed to get JNIEnv");
        let package_name = env
            .get_string(&package_name)
            .map(|java_str| java_str.to_string_lossy().into_owned())
            .unwrap_or_else(|e| {
                log::error!("Failed to get package name: {:?}", e);
                "unknown".to_string()
            });

        log::info!("Dump dex for {}, Spawning scanner thread...", package_name);
        std::thread::spawn(move || {
            log::info!(
                "--- Starting DEX Scan for {} (Waiting 60s & Deep Search: true) ---",
                package_name
            );
            std::thread::sleep(Duration::from_secs(10));

            match dex_scanner::scan_memory(true) {
                Ok(results) => {
                    if results.is_empty() {
                        log::info!("No DEX files found in suspicious memory regions");
                    } else {
                        log::info!("Found {} potential DEX files:", results.len());
                        let dump_dir = format!("/data/data/{}/files/rust_dumps", package_name);
                        match std::fs::remove_dir_all(&dump_dir) {
                            Ok(_) => {},
                            Err(e) if e.kind() == io::ErrorKind::NotFound => {},
                            Err(_e) => {},
                        }
                        match std::fs::create_dir_all(&dump_dir) {
                            Ok(_) => {
                                for (i, dex) in results.iter().enumerate() {
                                    log::info!(
                                        "Save dex [{}] to {}: Address=0x{:x}, Size=0x{:.x} ({}), Version: {}, Source: {}",
                                        i,
                                        dump_dir,
                                        dex.addr,
                                        dex.size,
                                        dex.size,
                                        dex.version,
                                        dex.source
                                    );
                                    let pid = std::process::id() as libc::pid_t;
                                    match dex_parser::parse_dex_at(pid, dex.addr) {
                                        Ok(dex_file) => {
                                            // TODO
                                            for _method in &dex_file.methods {
                                                // log::info!("class {}; method {}, signature {}", method.class_name, method.method_name, method.signature);
                                            }
                        
                                            if let Err(e) =
                                                dump_dex_to_file(&dump_dir, i, dex.addr, dex.size)
                                            {
                                                log::error!("Failed to save DEX #{}, error: {}", i, e);
                                            }
                                        },
                                        Err(e) => { 
                                            log::error!("Failed to parse DEX #{}, error: {}", i, e);
                                        }
                                    }


                                }
                            }
                            Err(e) => {
                                log::error!(
                                    "Falied to create DEX save dir {} error: {}",
                                    dump_dir,
                                    e
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    log::error!("Failed to scan DEX, error: {}", e);
                }
            }
            log::info!("--- DEX Scan Finished for {}  ---", package_name);
        });
    }

    fn pre_server_specialize(&mut self, _args: &mut ServerSpecializeArgs) {}

    fn post_server_specialize(&mut self, _args: &ServerSpecializeArgs) {}
}

register_zygisk_module!(MyModule);

fn dump_dex_to_file(dump_dir: &str, index: usize, addr: usize, size: usize) -> std::io::Result<()> {
    // /data/data/com.example/files/rust_dumps/dex_0_7f123456.dex
    let file_path = format!("{}/dex_{}_{:x}.dex", dump_dir, index, addr);

    let data_slice = unsafe { std::slice::from_raw_parts(addr as *const u8, size) };

    let mut file = File::create(&file_path)?;
    file.write_all(data_slice)?;

    log::info!("Dex saved to {}", file_path);
    Ok(())
}

```

- dex_parser.rs
```rust
// dex_parser.rs

use bytemuck;
use std::collections::HashMap;
use super::dex_scanner::safe_read_memory;
use std::io::{Error, ErrorKind};
use std::mem::size_of;

// --- Public Structs (Moved from scanner) ---

/// Holds the complete parsed data from a DexFile found in memory.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ParsedDexFile {
    pub base_addr: usize,
    pub header: dex_structs::Header,

    // --- Raw Data Sections ---
    pub string_ids: Vec<dex_structs::StringId>,
    pub type_ids: Vec<dex_structs::TypeId>,
    pub proto_ids: Vec<dex_structs::ProtoId>,
    pub field_ids: Vec<dex_structs::FieldId>,
    pub method_ids: Vec<dex_structs::MethodId>,
    pub class_defs: Vec<dex_structs::ClassDef>,

    // --- Processed & Usable Data ---
    
    /// Map of `string_id_index` -> `String`
    pub strings: HashMap<u32, String>,
    
    /// Map of `type_id_index` -> `String` (e.g., "Ljava/lang/String;")
    pub type_names: HashMap<u32, String>,
    
    /// Fully parsed method information
    pub methods: Vec<ParsedMethod>,
}

/// Represents a single, fully resolved method.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ParsedMethod {
    pub id: dex_structs::MethodId,
    pub class_name: String,
    pub method_name: String,
    
    /// Full method signature, e.g., "(Ljava/lang/String;)V"
    pub signature: String,
    
    /// Parsed code item, if the method is not abstract/native
    pub code_item: Option<dex_structs::CodeItem>,
}

// --- AOSP Struct Definitions ---
pub mod dex_structs {
    use bytemuck::{Pod, Zeroable};
    use std::fmt;

    // --- Header ---
    #[repr(C)]
    #[derive(Clone, Copy, Pod, Zeroable)]
    pub struct Header {
        pub magic: [u8; 8],
        pub checksum: u32,
        pub signature: [u8; 20],
        pub file_size: u32,
        pub header_size: u32,
        pub endian_tag: u32,
        pub link_size: u32,
        pub link_off: u32,
        pub map_off: u32,
        pub string_ids_size: u32,
        pub string_ids_off: u32,
        pub type_ids_size: u32,
        pub type_ids_off: u32,
        pub proto_ids_size: u32,
        pub proto_ids_off: u32,
        pub field_ids_size: u32,
        pub field_ids_off: u32,
        pub method_ids_size: u32,
        pub method_ids_off: u32,
        pub class_defs_size: u32,
        pub class_defs_off: u32,
        pub data_size: u32,
        pub data_off: u32,
    }

    impl fmt::Debug for Header {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Header")
                .field("magic", &String::from_utf8_lossy(&self.magic))
                .field("file_size", &self.file_size)
                .field("header_size", &self.header_size)
                .field("map_off", &self.map_off)
                .field("string_ids_size", &self.string_ids_size)
                .field("string_ids_off", &self.string_ids_off)
                // ... (rest of fields)
                .finish()
        }
    }
    
    // --- MapList / MapItem ---
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    pub struct MapItem {
        pub type_: u16,
        pub unused_: u16,
        pub size: u32,
        pub offset: u32,
    }

    #[allow(dead_code)]
    #[derive(Debug, Clone)]
    pub struct MapList {
        pub size: u32,
        pub list: Vec<MapItem>,
    }

    // --- Dex File Data Structs ---
    #[repr(C)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Pod, Zeroable)]
    pub struct StringId {
        pub string_data_off: u32, // Offset from beginning of file
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    pub struct TypeId {
        pub descriptor_idx: u32, // Index into StringId list
    }
    
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    pub struct ProtoId {
        pub shorty_idx: u32,     // Index into StringId list (short descriptor)
        pub return_type_idx: u32, // Index into TypeId list
        pub parameters_off: u32, // Offset to TypeList
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    pub struct FieldId {
        pub class_idx: u16, // Index into TypeId list (defining class)
        pub type_idx: u16,  // Index into TypeId list (field type)
        pub name_idx: u32,  // Index into StringId list (field name)
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    pub struct MethodId {
        pub class_idx: u16, // Index into TypeId list (defining class)
        pub proto_idx: u16, // Index into ProtoId list (method prototype)
        pub name_idx: u32,  // Index into StringId list (method name)
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    pub struct ClassDef {
        pub class_idx: u32,      // Index into TypeId list (this class)
        pub access_flags: u32,
        pub superclass_idx: u32, // Index into TypeId list (superclass)
        pub interfaces_off: u32, // Offset to TypeList
        pub source_file_idx: u32, // Index into StringId list
        pub annotations_off: u32, // Offset to annotations_directory_item
        pub class_data_off: u32, // Offset to class_data_item
        pub static_values_off: u32, // Offset to encoded_array_item
    }

    // --- Code Item ---
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    pub struct CodeItemHeader {
        pub registers_size: u16,
        pub ins_size: u16,
        pub outs_size: u16,
        pub tries_size: u16,
        pub debug_info_off: u32,
        pub insns_size_in_code_units: u32, // size of "insns" in u16 units
    }

    #[allow(dead_code)]
    #[derive(Debug, Clone)]
    pub struct CodeItem {
        pub header: CodeItemHeader,
        pub insns: Vec<u16>, // Instructions
    }
}



// --- Parser Implementation ---

/// This is the main public entry point for the parser module.
/// The scanner will call this function after it has found and
/// verified a DEX header.
pub fn parse_dex_at(
    pid: libc::pid_t,
    base_addr: usize,
) -> Result<ParsedDexFile, Error> {
    let mut header_buf = [0u8; size_of::<dex_structs::Header>()];
    if safe_read_memory(pid, base_addr, &mut header_buf).is_err() {
        ()
    }
    let header: dex_structs::Header = *bytemuck::from_bytes(&header_buf);

    let parser_helper = DexParserHelper::new(pid, base_addr);
    parser_helper.parse(&header)
}

/// A private helper struct to manage parsing state.
/// This is identical to your old `DexParser` struct.
struct DexParserHelper {
    pid: libc::pid_t,
    base_addr: usize,
}

impl DexParserHelper {
    fn new(pid: libc::pid_t, base_addr: usize) -> Self {
        Self { pid, base_addr }
    }

    /// Main parsing orchestration function.
    fn parse(
        &self,
        header: &dex_structs::Header
    ) -> Result<ParsedDexFile, Error> {
        let mut strings = HashMap::new();
        let mut type_names = HashMap::new();
        let mut methods = Vec::new();

        // 1. Read StringIDs
        let string_ids = self.read_struct_vec_at_offset::<dex_structs::StringId>(
            header.string_ids_off as usize,
            header.string_ids_size as usize,
        )?;

        // 2. Read actual Strings
        for (i, id) in string_ids.iter().enumerate() {
            if id.string_data_off != 0 {
                if let Ok((s, _)) = self.read_string_data(id.string_data_off as usize) {
                    strings.insert(i as u32, s);
                }
            }
        }

        // 3. Read TypeIDs
        let type_ids = self.read_struct_vec_at_offset::<dex_structs::TypeId>(
            header.type_ids_off as usize,
            header.type_ids_size as usize,
        )?;

        // 4. Map TypeIDs to Strings
        for (i, id) in type_ids.iter().enumerate() {
            if let Some(s) = strings.get(&id.descriptor_idx) {
                type_names.insert(i as u32, s.clone());
            }
        }

        // 5. Read ProtoIDs
        let proto_ids = self.read_struct_vec_at_offset::<dex_structs::ProtoId>(
            header.proto_ids_off as usize,
            header.proto_ids_size as usize,
        )?;

        // 6. Read FieldIDs
        let field_ids = self.read_struct_vec_at_offset::<dex_structs::FieldId>(
            header.field_ids_off as usize,
            header.field_ids_size as usize,
        )?;

        // 7. Read MethodIDs
        let method_ids = self.read_struct_vec_at_offset::<dex_structs::MethodId>(
            header.method_ids_off as usize,
            header.method_ids_size as usize,
        )?;

        // 8. Read ClassDefs
        let class_defs = self.read_struct_vec_at_offset::<dex_structs::ClassDef>(
            header.class_defs_off as usize,
            header.class_defs_size as usize,
        )?;

        // 9. Parse Methods (Names and Signatures)
        for (_method_idx, m_id) in method_ids.iter().enumerate() {
            let class_name = type_names
                .get(&(m_id.class_idx as u32))
                .cloned()
                .unwrap_or_else(|| "??".to_string());
            let method_name = strings
                .get(&m_id.name_idx)
                .cloned()
                .unwrap_or_else(|| "??".to_string());

            let signature = if let Some(proto) = proto_ids.get(m_id.proto_idx as usize) {
                self.get_proto_string(proto, &type_names)
            } else {
                "()?".to_string()
            };

            methods.push(ParsedMethod {
                id: *m_id,
                class_name,
                method_name,
                signature,
                code_item: None, // Will be filled in by ClassData pass
            });
        }
        
        // 10. Parse ClassData (to find CodeItems)
        let mut method_code_map = HashMap::new(); // map method_idx -> CodeItem
        for def in &class_defs {
            if def.class_data_off == 0 { continue; }

            if let Ok(()) = self.parse_class_data(def.class_data_off as usize, &mut method_code_map) {
                // successfully parsed this class's data
            }
        }
        
        // 11. Link CodeItems to ParsedMethods
        for (method_idx, p_method) in methods.iter_mut().enumerate() {
            if let Some(code) = method_code_map.remove(&(method_idx as u32)) {
                p_method.code_item = Some(code);
            }
        }

        // 12. Build final struct
        Ok(ParsedDexFile {
            base_addr: self.base_addr,
            header: *header,
            string_ids,
            type_ids,
            proto_ids,
            field_ids,
            method_ids,
            class_defs,
            strings,
            type_names,
            methods,
        })
    }
    
    /// Parses the `class_data_item` for a ClassDef.
    fn parse_class_data(&self, offset: usize, method_code_map: &mut HashMap<u32, dex_structs::CodeItem>) -> Result<(), Error> {
        let mut current_offset = offset;
        let (static_fields_size, _) = self.read_uleb128_and_size(&mut current_offset)?;
        let (instance_fields_size, _) = self.read_uleb128_and_size(&mut current_offset)?;
        let (direct_methods_size, _) = self.read_uleb128_and_size(&mut current_offset)?;
        let (virtual_methods_size, _) = self.read_uleb128_and_size(&mut current_offset)?;

        // Skip fields
        for _ in 0..static_fields_size {
            self.read_uleb128_and_size(&mut current_offset)?; // field_idx_diff
            self.read_uleb128_and_size(&mut current_offset)?; // access_flags
        }
        for _ in 0..instance_fields_size {
            self.read_uleb128_and_size(&mut current_offset)?; // field_idx_diff
            self.read_uleb128_and_size(&mut current_offset)?; // access_flags
        }

        // Parse direct methods
        let mut last_method_idx = 0;
        for _ in 0..direct_methods_size {
            let (method_idx_diff, _) = self.read_uleb128_and_size(&mut current_offset)?;
            let (_access_flags, _) = self.read_uleb128_and_size(&mut current_offset)?;
            let (code_off, _) = self.read_uleb128_and_size(&mut current_offset)?;
            
            last_method_idx += method_idx_diff;
            if code_off != 0 {
                if let Ok(code_item) = self.parse_code_item(code_off as usize) {
                    method_code_map.insert(last_method_idx, code_item);
                }
            }
        }

        // Parse virtual methods
        last_method_idx = 0;
        for _ in 0..virtual_methods_size {
            let (method_idx_diff, _) = self.read_uleb128_and_size(&mut current_offset)?;
            let (_access_flags, _) = self.read_uleb128_and_size(&mut current_offset)?;
            let (code_off, _) = self.read_uleb128_and_size(&mut current_offset)?;
            
            last_method_idx += method_idx_diff;
            if code_off != 0 {
                if let Ok(code_item) = self.parse_code_item(code_off as usize) {
                    method_code_map.insert(last_method_idx, code_item);
                }
            }
        }
        Ok(())
    }

    /// Parses a `CodeItem` at a given offset.
    fn parse_code_item(&self, offset: usize) -> Result<dex_structs::CodeItem, Error> {
        let header = self.read_struct_at_offset::<dex_structs::CodeItemHeader>(offset)?;
        let insns_offset = offset + size_of::<dex_structs::CodeItemHeader>();
        let insns_size_bytes = header.insns_size_in_code_units as usize * 2; // 2 bytes per u16
        
        let insns_bytes = self.read_bytes(insns_offset, insns_size_bytes)?;
        let insns: Vec<u16> = bytemuck::cast_slice::<u8, u16>(&insns_bytes).to_vec();

        Ok(dex_structs::CodeItem { header, insns })
    }
    
    /// Resolves a ProtoId into a readable signature string.
    fn get_proto_string(&self, proto: &dex_structs::ProtoId, types: &HashMap<u32, String>) -> String {
        let ret_type = types.get(&proto.return_type_idx).cloned().unwrap_or("?".to_string());
        
        let mut params_str = "()".to_string();
        if proto.parameters_off != 0 {
            if let Ok(param_list) = self.parse_type_list(proto.parameters_off as usize) {
                let p: Vec<String> = param_list.iter()
                    .map(|type_idx| types.get(&(*type_idx as u32)).cloned().unwrap_or("?".to_string()))
                    .collect();
                params_str = format!("({})", p.join("")); // Descriptors are concatenated
            }
        }
        
        format!("{}{}", params_str, ret_type)
    }

    /// Parses a `TypeList` at a given offset.
    fn parse_type_list(&self, offset: usize) -> Result<Vec<u16>, Error> {
        let size = self.read_struct_at_offset::<u32>(offset)? as usize;
        if size > 0xFFFF { // Sanity check
            return Err(Error::new(ErrorKind::InvalidData, "TypeList size too large"));
        }
        let list_offset = offset + 4; // after size
        let list_bytes = self.read_bytes(list_offset, size * 2)?; // u16
        let list: Vec<u16> = bytemuck::cast_slice::<u8, u16>(&list_bytes).to_vec();
        Ok(list)
    }

    // --- Memory Read Helpers ---

    /// Reads raw bytes from `base_addr + offset`.
    fn read_bytes(&self, offset: usize, size: usize) -> Result<Vec<u8>, Error> {
        if size == 0 { return Ok(Vec::new()); }
        let mut buf = vec![0u8; size];
        safe_read_memory(self.pid, self.base_addr + offset, &mut buf)?;
        Ok(buf)
    }

    /// Reads raw bytes into an existing buffer.
    fn read_bytes_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize, Error> {
        safe_read_memory(self.pid, self.base_addr + offset, buf)
    }

    /// Reads a struct T from `base_addr + offset`.
    fn read_struct_at_offset<T: bytemuck::Pod>(&self, offset: usize) -> Result<T, Error> {
        let mut buf = vec![0u8; size_of::<T>()];
        self.read_bytes_at(offset, &mut buf)?;
        Ok(*bytemuck::from_bytes::<T>(&buf))
    }

    /// Reads a `count` number of structs T from `base_addr + offset`.
    fn read_struct_vec_at_offset<T: bytemuck::Pod>(&self, offset: usize, count: usize) -> Result<Vec<T>, Error> {
        let total_size = size_of::<T>().checked_mul(count).ok_or_else(|| Error::new(ErrorKind::InvalidData, "Struct vector size overflow"))?;
        if total_size == 0 {
            return Ok(Vec::new());
        }
        if total_size > 100 * 1024 * 1024 { // 100MB sanity limit
            return Err(Error::new(ErrorKind::InvalidData, "Struct vector size too large"));
        }
        let bytes = self.read_bytes(offset, total_size)?;
        Ok(bytemuck::cast_slice::<u8, T>(&bytes).to_vec())
    }
    
    /// Reads a ULEB128-encoded value and returns it and the number of bytes read.
    fn read_uleb128_and_size(&self, offset: &mut usize) -> Result<(u32, usize), Error> {
        let mut result: u32 = 0;
        let mut shift = 0;
        let mut byte_buf = [0u8; 1];
        let start_offset = *offset;

        loop {
            self.read_bytes_at(*offset, &mut byte_buf)?;
            *offset += 1;
            let byte = byte_buf[0];

            result |= ((byte & 0x7F) as u32) << shift;
            if (byte & 0x80) == 0 {
                break;
            }
            shift += 7;
            if shift > 28 { // 5 bytes max for u32
                return Err(Error::new(ErrorKind::InvalidData, "Invalid ULEB128"));
            }
        }
        Ok((result, *offset - start_offset))
    }

    /// Reads a MUTF-8 string.
    fn read_string_data(&self, offset: usize) -> Result<(String, usize), Error> {
        let mut current_offset = offset;
        let (utf16_len, len_bytes_read) = self.read_uleb128_and_size(&mut current_offset)?;
        
        let mut str_bytes = Vec::new();
        let mut byte_buf = [0u8; 1];
        let mut bytes_read_for_str = 0;
        loop {
            self.read_bytes_at(current_offset, &mut byte_buf)?;
            current_offset += 1;
            bytes_read_for_str += 1;
            
            if byte_buf[0] == 0 {
                break;
            }
            str_bytes.push(byte_buf[0]);
            
            if bytes_read_for_str > (utf16_len as usize * 3 + 10) { 
                 return Err(Error::new(ErrorKind::InvalidData, "MUTF-8 string too long"));
            }
        }
    
        // Simple MUTF-8 (C0 80 -> 00) replacement
        let mut i = 0;
        let mut utf8_bytes = Vec::with_capacity(str_bytes.len());
        while i < str_bytes.len() {
            if str_bytes[i] == 0xC0 && i + 1 < str_bytes.len() && str_bytes[i+1] == 0x80 {
                utf8_bytes.push(0x00);
                i += 2;
            } else {
                utf8_bytes.push(str_bytes[i]);
                i += 1;
            }
        }

        let s = String::from_utf8_lossy(&utf8_bytes).to_string();
        let total_bytes_read = len_bytes_read + bytes_read_for_str;
        Ok((s, total_bytes_read))
    }
}
```

- dex_scanner.rs
```rust
use proc_maps::{get_process_maps, MapRange};
use std::cmp::Ordering;
use std::mem::size_of;
use std::io;

#[derive(Debug, Clone)]
pub struct DexFileResult {
    pub addr: usize,
    pub size: usize,
    pub version: String,
    pub source: String,
}

// --- Constants ---
const CHUNK_SIZE: usize = 1024 * 1024; // 1MB chunk
const MAX_DEX_SIZE: usize = 200 * 1024 * 1024; // 200MB limit
const MIN_DEX_SIZE: usize = 0x70;

/* 
  struct Header {                     type     size   offset
    Magic magic_ = {};           //  uint8_t[8]  8      0x00
    uint32_t checksum_ = 0;      //  uint32_t,   4      0x08
    Sha1 signature_ = {};        //  uint8_t[20] 20     0x0C 
    uint32_t file_size_ = 0;     //  uint32_t    4      0x20
    uint32_t header_size_ = 0;   //  uint32_t    4      0x24
    uint32_t endian_tag_ = 0;    //  uint32_t    4      0x28
    uint32_t link_size_ = 0;     //  uint32_t    4      0x2c
    uint32_t link_off_ = 0;      //  uint32_t    4      0x30
    uint32_t map_off_ = 0;       //  uint32_t    4      0x34
    uint32_t string_ids_size_ = 0; //uint32_t    4      0x38
    uint32_t string_ids_off_ = 0; // uint32_t    4      0x3C
    uint32_t type_ids_size_ = 0;  // number of TypeIds, we don't support more than 65535
    uint32_t type_ids_off_ = 0;  // file offset of TypeIds array
    uint32_t proto_ids_size_ = 0;  // number of ProtoIds, we don't support more than 65535
    uint32_t proto_ids_off_ = 0;  // file offset of ProtoIds array
    uint32_t field_ids_size_ = 0;  // number of FieldIds
    uint32_t field_ids_off_ = 0;  // file offset of FieldIds array
    uint32_t method_ids_size_ = 0;  // number of MethodIds
    uint32_t method_ids_off_ = 0;  // file offset of MethodIds array
    uint32_t class_defs_size_ = 0;  // number of ClassDefs
    uint32_t class_defs_off_ = 0;  // file offset of ClassDef array
    uint32_t data_size_ = 0;  // size of data section
    uint32_t data_off_ = 0;  // file offset of data section
    ...
  }
*/


const OFF_FILE_SIZE: usize = 0x20; 
const OFF_HEADER_SIZE: usize = 0x24;
const OFF_ENDIAN_TAG: usize = 0x28;
const OFF_MAP_OFF: usize = 0x34;
const OFF_STRING_IDS_OFF: usize = 0x3C;

const ENDIAN_CONSTANT: u32 = 0x12345678;
const REVERSE_ENDIAN_CONSTANT: u32 = 0x78563412;

pub fn safe_read_memory(pid: libc::pid_t, addr: usize, buf: &mut [u8]) -> Result<usize, io::Error> {
    let local_iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let remote_iov = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: buf.len(),
    };

    let nread = unsafe {
        libc::process_vm_readv(
            pid,
            &local_iov,
            1,
            &remote_iov,
            1,
            0
        )
    };

    if nread == -1 {
        // no panic when EFAULT (Bad address)
        return Err(io::Error::last_os_error());
    }

    Ok(nread as usize)
}

pub fn scan_memory(deep_search: bool) -> Result<Vec<DexFileResult>, std::io::Error> {
    let pid = std::process::id() as libc::pid_t;
    
    let mut ranges = get_process_maps(pid)?;
    ranges.sort_by(|a, b| a.start().cmp(&b.start()));

    let mut results = Vec::new();

    for range in &ranges {
        if !range.is_read() { continue; }
        
        if let Some(path) = range.filename() {
            let s = path.to_string_lossy();
            if s.starts_with("/dev/") && !s.contains("ashmem") && !s.contains("zero") {
                continue;
            }
        }

        scan_map_chunked(pid, range, &ranges, &mut results, deep_search);
    }

    results.sort_by_key(|r| r.addr);
    results.dedup_by_key(|r| r.addr);
    
    Ok(results)
}

fn scan_map_chunked(
    pid: libc::pid_t,
    range: &MapRange,
    all_ranges: &[MapRange],
    results: &mut Vec<DexFileResult>,
    deep_search: bool
) {
    let mut offset = 0;
    let map_size = range.size();
    let start_addr = range.start();

    let mut buf = vec![0u8; CHUNK_SIZE];

    while offset < map_size {
        let to_read = std::cmp::min(CHUNK_SIZE, map_size - offset);
        let current_chunk_addr = start_addr + offset;
        
        match safe_read_memory(pid, current_chunk_addr, &mut buf[..to_read]) {
            Ok(n) if n > 0 => {
                let valid_buf = &buf[..n];
                scan_buffer_magic(valid_buf, current_chunk_addr, pid, all_ranges, results);

                if deep_search && size_of::<usize>() == 8 {
                    scan_buffer_pointers(valid_buf, current_chunk_addr, pid, all_ranges, results);
                }
            }
            _ => break, 
        }
        offset += to_read;
    }
}

fn scan_buffer_magic(
    buf: &[u8],
    base_addr: usize,
    pid: libc::pid_t,
    all_ranges: &[MapRange],
    results: &mut Vec<DexFileResult>
) {
    let mut i = 0;
    while i + 8 <= buf.len() {
        let is_dex = &buf[i..i+4] == b"dex\n";
        let is_cdex = &buf[i..i+4] == b"cdex";

        if is_dex || is_cdex {
            let candidate_addr = base_addr + i;
            if let Some(res) = verify_and_parse(pid, candidate_addr, all_ranges, false) {
                let mut r = res;
                r.source = "MagicScan".to_string();
                results.push(r);
            }
        }
        i += 4;
    }
}

fn scan_buffer_pointers(
    buf: &[u8],
    _base_addr: usize,
    pid: libc::pid_t,
    all_ranges: &[MapRange],
    results: &mut Vec<DexFileResult>
) {
    let step = 8;
    let mut i = 0;
    while i + 8 <= buf.len() {
        let ptr_val = u64::from_le_bytes(buf[i..i+8].try_into().unwrap()) as usize;

        if ptr_val == 0 || ptr_val % 4 != 0 {
            i += step;
            continue;
        }

        if let Some(_target_map) = find_map_binary(all_ranges, ptr_val) {
            // valid pointer to memory -> verify
            if let Some(res) = verify_and_parse(pid, ptr_val, all_ranges, true) {
                let mut r = res;
                r.source = "PointerScan".to_string();
                results.push(r);
            }
        }
        i += step;
    }
}

fn verify_and_parse(
    pid: libc::pid_t,
    addr: usize,
    all_ranges: &[MapRange],
    allow_missing_magic: bool
) -> Option<DexFileResult> {
    let mut header = [0u8; 0x70];
    if safe_read_memory(pid, addr, &mut header).is_err() {
        return None;
    }

    // Magic
    let mut version = String::new();
    let has_magic = if &header[0..4] == b"dex\n" {
        version = String::from_utf8_lossy(&header[4..7]).to_string();
        true
    } else if &header[0..4] == b"cdex" {
        version = "cdex".to_string();
        true
    } else {
        false
    };

    if !has_magic && !allow_missing_magic {
        return None;
    }

    // parsing
    let file_size = u32::from_le_bytes(header[OFF_FILE_SIZE..OFF_FILE_SIZE+4].try_into().unwrap()) as usize;
    let header_size = u32::from_le_bytes(header[OFF_HEADER_SIZE..OFF_HEADER_SIZE+4].try_into().unwrap()) as usize;
    let endian_tag = u32::from_le_bytes(header[OFF_ENDIAN_TAG..OFF_ENDIAN_TAG+4].try_into().unwrap());
    let map_off = u32::from_le_bytes(header[OFF_MAP_OFF..OFF_MAP_OFF+4].try_into().unwrap()) as usize;
    
    // deep_search verify
    if !has_magic {
        if endian_tag != ENDIAN_CONSTANT && endian_tag != REVERSE_ENDIAN_CONSTANT { return None; }
        if header_size < 0x40 || header_size > 0x200 { return None; } // relax 0x70
        if file_size < MIN_DEX_SIZE || file_size > MAX_DEX_SIZE { return None; }
        if map_off < header_size || map_off >= file_size { return None; }
        
        let string_ids_off = u32::from_le_bytes(header[OFF_STRING_IDS_OFF..OFF_STRING_IDS_OFF+4].try_into().unwrap()) as usize;
        if string_ids_off < header_size || string_ids_off >= file_size { return None; }
        
        version = "unknown(wiped)".to_string();
    } else {
        if file_size < MIN_DEX_SIZE || file_size > MAX_DEX_SIZE { return None; }
    }

    // Verify MapList
    let map_abs_addr = addr + map_off;
    if find_map_binary(all_ranges, map_abs_addr).is_none() {
        return None;
    }

    /*
    struct MapList {
        uint32_t size_;
        MapItem list_[1];
        size_t Size() const { return sizeof(uint32_t) + (size_ * sizeof(MapItem)); }
        private:
        DISALLOW_COPY_AND_ASSIGN(MapList);
    };
     */
    let mut map_size_buf = [0u8; 4]; // uint32_t size_;
    if safe_read_memory(pid, map_abs_addr, &mut map_size_buf).is_err() {
        return None;
    }
    let map_list_size = u32::from_le_bytes(map_size_buf) as usize;
    
    if map_list_size == 0 || map_list_size > 1000 {
        return None;
    }

    Some(DexFileResult {
        addr,
        size: file_size,
        version,
        source: "Unknown".to_string(),
    })
}

fn find_map_binary(ranges: &[MapRange], addr: usize) -> Option<&MapRange> {
    ranges.binary_search_by(|range| {
        if addr < range.start() {
            Ordering::Greater
        } else if addr >= range.start() + range.size() {
            Ordering::Less
        } else {
            Ordering::Equal
        }
    }).ok().map(|idx| &ranges[idx])
}
```
