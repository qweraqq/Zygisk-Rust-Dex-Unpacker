# Zygisk-Rust-Dex-Unpacker

## How to use
```bash
# adb shell
# su
echo "<target-package-name>" >> /data/adb/modules/zygisk-rust-dex-unpacker/whitelist.txt

# wait and pull file from /data/data/<target-package-name>/files/rust_dumps 
```


## How to build

- Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

- Add Android Support
```bash
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
```

- cargo-ndk & just
```bash
cargo install just
cargo install cargo-ndk
```

- export ANDROID_NDK_HOME `export ANDROID_NDK_HOME="PATH-TO/android-ndk-r27d`

- Build
```bash
just package
```

## Why it works
- **Pure memory scan**

### Magic Scan
- `dex\n035` or `cdex`
- Android Packer will remove these Magic

### Deep Search
- **DexFile always exists**

- We only care about DexFile in Memory
- Scan for all potential pointers to valid memory range -> verify valid dex ?

- **Rules** **You may read AOSP source code and custom your rules**
1. file_size > header_size && file_size < MAX_LIMIT
2. 0x40 <= header_size  <= 0x200
3. endian tag: 0x12345678/0x78563412
4. map_off > header_size && map_off < file_size
5. same as 4: class_defs_off / type_ids_off 
5. maplist count reasonable

- class DexFile [https://android.googlesource.com/platform/art/+/refs/tags/android-16.0.0_r3/libdexfile/dex/dex_file.h](https://android.googlesource.com/platform/art/+/refs/tags/android-16.0.0_r3/libdexfile/dex/dex_file.h)
- DexFile::DexFile init [https://android.googlesource.com/platform/art/+/refs/tags/android-16.0.0_r3/libdexfile/dex/dex_file.cc](https://android.googlesource.com/platform/art/+/refs/tags/android-16.0.0_r3/libdexfile/dex/dex_file.cc)
- struct MapList [https://android.googlesource.com/platform/art/+/refs/tags/android-16.0.0_r3/libdexfile/dex/dex_file_structs.h](https://android.googlesource.com/platform/art/+/refs/tags/android-16.0.0_r3/libdexfile/dex/dex_file_structs.h)

Picture from Gemini

```
[ RAM Region 1: The C++ Object (Heap) ]      [ RAM Region 2: The Raw File (mmap) ]
+-----------------------+                    +----------------------------+ <--- begin_
| class DexFile         |                    | struct Header {            |
|                       |                    |   magic: "dex\n039";       |
|  begin_  = 0xA000  ------+                 |   string_ids_off: 112;     |
|  size_   = 2MB        |  |                 |   ...                      |
|  data_begin_ = ...    |  |                 | }                          |
+-----------------------+  |                 +----------------------------+
                           |                 | String ID Table            |
                           +---------------->| (Index 0)                  |
                                             | (Index 1)                  |
                                             +----------------------------+
                                             | ...                        |
```

- The Anchor: `begin_` This variable `begin_` is the absolute memory address where the Dex file starts.
  + dex_file.cc: `header_(reinterpret_cast<const Header*>(base)),`

```cpp
// art/libdexfile/dex/dex_file.h

protected:
  // The base address of the memory mapping.
  const uint8_t* const begin_;


// art/libdexfile/dex/dex_file.cc
DexFile::DexFile(const uint8_t* base,
                 const std::string& location,
                 uint32_t location_checksum,
                 const OatDexFile* oat_dex_file,
                 std::shared_ptr<DexFileContainer> container)
    : begin_(base),
      data_(GetDataRange(base, container.get())),
      location_(location),
      location_checksum_(location_checksum),
      header_(reinterpret_cast<const Header*>(base)),
      string_ids_(GetSection<StringId>(&header_->string_ids_off_, container.get())),
      type_ids_(GetSection<TypeId>(&header_->type_ids_off_, container.get())),
      field_ids_(GetSection<FieldId>(&header_->field_ids_off_, container.get())),
      method_ids_(GetSection<MethodId>(&header_->method_ids_off_, container.get())),
      proto_ids_(GetSection<ProtoId>(&header_->proto_ids_off_, container.get())),
      class_defs_(GetSection<ClassDef>(&header_->class_defs_off_, container.get())),
      method_handles_(nullptr),
      num_method_handles_(0),
      call_site_ids_(nullptr),
      num_call_site_ids_(0),
      hiddenapi_class_data_(nullptr),
      oat_dex_file_(oat_dex_file),
      container_(std::move(container)),
      hiddenapi_domain_(hiddenapi::Domain::kApplication) {
  CHECK(begin_ != nullptr) << GetLocation();
  // Check base (=header) alignment.
  // Must be 4-byte aligned to avoid undefined behavior when accessing
  // any of the sections via a pointer.
  CHECK_ALIGNED(begin_, alignof(Header));
  if (DataSize() < sizeof(Header)) {
    // Don't go further if the data doesn't even contain a header.
    return;
  }
  InitializeSectionsFromMapList();
}
```


```cpp
// Owns the physical storage that backs one or more DexFiles (that is, it can be shared).
// It frees the storage (e.g. closes file) when all DexFiles that use it are all closed.
//
// The memory range must include all data used by the DexFiles including any shared data.
//
// It might also include surrounding non-dex data (e.g. it might represent vdex file).
class DexFileContainer {}

MemoryDexFileContainer {
 ...
 private:
  const uint8_t* const begin_;
  const uint8_t* const end_;
  DISALLOW_COPY_AND_ASSIGN(MemoryDexFileContainer);
}

// Dex file is the API that exposes native dex files (ordinary dex files).
// The dex file format used by ART is mostly the same as APKs, but this
// abstraction is present to allow ART internal dex files.
class DexFile {
  ...
  struct Header {
    Magic magic_ = {};
    uint32_t checksum_ = 0;  // See also location_checksum_
    Sha1 signature_ = {};
    uint32_t file_size_ = 0;  // size of entire file
    uint32_t header_size_ = 0;  // offset to start of next section
    uint32_t endian_tag_ = 0;
    uint32_t link_size_ = 0;  // unused
    uint32_t link_off_ = 0;  // unused
    uint32_t map_off_ = 0;  // map list offset from data_off_
    uint32_t string_ids_size_ = 0;  // number of StringIds
    uint32_t string_ids_off_ = 0;  // file offset of StringIds array
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

  ...

  // Read MapItems and validate/set remaining offsets.
  const dex::MapList* GetMapList() const {
    return reinterpret_cast<const dex::MapList*>(DataBegin() + header_->map_off_);
  }
  
  ...

  // The base address of the memory mapping.
  const uint8_t* const begin_;
  size_t unused_size_ = 0;  // Preserve layout for DRM (b/305203031).


  // Data memory range: Most dex offsets are relative to this memory range.
  // Standard dex: same as (begin_, size_).
  // Dex container: all dex files (starting from the first header).
  // Compact: shared data which is located after all non-shared data.
  //
  // This is different to the "data section" in the standard dex header.
  ArrayRef<const uint8_t> const data_;

  // The full absolute path to the dex file, if it was loaded from disk.
  //
  // Can also be a path to a multidex container (typically apk), followed by
  // DexFileLoader.kMultiDexSeparator (i.e. '!') and the file inside the
  // container.
  //
  // On host this may not be an absolute path.
  //
  // On device libnativeloader uses this to determine the location of the java
  // package or shared library, which decides where to load native libraries
  // from.
  //
  // The ClassLinker will use this to match DexFiles the boot class
  // path to DexCache::GetLocation when loading from an image.
  const std::string location_;

  const uint32_t location_checksum_;

  // Points to the header section.
  const Header* const header_;
  // Points to the base of the string identifier list.
  const dex::StringId* const string_ids_;
  // Points to the base of the type identifier list.
  const dex::TypeId* const type_ids_;
  // Points to the base of the field identifier list.
  const dex::FieldId* const field_ids_;
  // Points to the base of the method identifier list.
  const dex::MethodId* const method_ids_;
  // Points to the base of the prototype identifier list.
  const dex::ProtoId* const proto_ids_;
  // Points to the base of the class definition list.
  const dex::ClassDef* const class_defs_;
  // Points to the base of the method handles list.
  const dex::MethodHandleItem* method_handles_;
  // Number of elements in the method handles list.
  size_t num_method_handles_;
  // Points to the base of the call sites id list.
  const dex::CallSiteIdItem* call_site_ids_;
  // Number of elements in the call sites list.
  size_t num_call_site_ids_;
  // Points to the base of the hiddenapi class data item_, or nullptr if the dex
  // file does not have one.
  const dex::HiddenapiClassData* hiddenapi_class_data_;
  // If this dex file was loaded from an oat file, oat_dex_file_ contains a
  // pointer to the OatDexFile it was loaded from. Otherwise oat_dex_file_ is
  // null.
  mutable const OatDexFile* oat_dex_file_;
  // Manages the underlying memory allocation.
  std::shared_ptr<DexFileContainer> container_;
  // If the dex file is a compact dex file. If false then the dex file is a standard dex file.
  const bool is_compact_dex_;
}
```

## Credits
- [https://github.com/hluwa/frida-dexdump](https://github.com/hluwa/frida-dexdump)
- [https://github.com/ri-char/zygisk-dump-dex](https://github.com/ri-char/zygisk-dump-dex)
- [https://github.com/Tools-cx-app/zygisk-rs](https://github.com/Tools-cx-app/zygisk-rs)
- [https://github.com/Kr328/zygisk-rs](https://github.com/Kr328/zygisk-rs)
