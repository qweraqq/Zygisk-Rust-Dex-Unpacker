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