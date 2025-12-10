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