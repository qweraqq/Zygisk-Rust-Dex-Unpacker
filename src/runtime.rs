use jni::{
    objects::{JObject, JString, JValue, JClass},
    // Import the `JavaType` struct, which is the correct type for signatures
    signature::JavaType,
    JNIEnv,
};
use std::str::FromStr; // Required for JavaType::from_str

// Import the real structs from your parser
use super::dex_parser::{ClassDefItem, DexParser, EncodedMethod};

/// 获取当前应用的 ClassLoader
fn get_app_class_loader<'a>(env: &'a mut JNIEnv) -> jni::errors::Result<JObject<'a>> {
    // 1. 获取当前线程
    let thread_class = env.find_class("java/lang/Thread")?;
    let current_thread_mid =
        env.get_static_method_id(thread_class, "currentThread", "()Ljava/lang/Thread;")?;

    // We must provide the return signature: Ljava/lang/Thread;
    let ret_sig = JavaType::from_str("Ljava/lang/Thread;").unwrap();
    let current_thread = unsafe { env.call_static_method_unchecked(
        thread_class,
        current_thread_mid,
        ret_sig,
        &[] // No arguments
    ) }?.l()?; // .l()? unwraps the JValue to a JObject

    // 2. 获取 context ClassLoader
    let get_ccl_mid = env.get_method_id(
        thread_class,
        "getContextClassLoader",
        "()Ljava/lang/ClassLoader;",
    )?;

    // We must provide the return signature: Ljava/lang/ClassLoader;
    let ret_sig = JavaType::from_str("Ljava/lang/ClassLoader;").unwrap();
    let app_loader = unsafe { env.call_method_unchecked(
        &current_thread,
        get_ccl_mid,
        ret_sig,
        &[] // No arguments
    ) }?.l()?; // .l()? unwraps the JValue to a JObject
    
    Ok(app_loader)
}

/// 创建一个 DexClassLoader，它加载指定目录中的 .dex 文件
pub fn create_dex_class_loader<'a>(
    env: &'a mut JNIEnv,
    dex_dump_dir: &str,
) -> jni::errors::Result<JObject<'a>> {
    let app_loader = get_app_class_loader(env)?;

    let dex_path = env.new_string(dex_dump_dir)?;
    let optimized_dir = JObject::null();
    let library_path = JObject::null();

    let dex_loader_class = env.find_class("dalvik/system/DexClassLoader")?;
    let constructor_mid = env.get_method_id(
        dex_loader_class,
        "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V",
    )?;

    // Use `new_object` (not new_object_id) for constructors
    let dex_loader = env.new_object(
        dex_loader_class,
        constructor_mid,
        &[
            JValue::Object(&dex_path.into()),
            JValue::Object(&optimized_dir),
            JValue::Object(&library_path),
            JValue::Object(&app_loader),
        ],
    )?;

    log::info!("DexClassLoader created for path: {}", dex_dump_dir);
    Ok(dex_loader)
}

/// 核心：强制 ART 解析一个方法
pub fn force_resolve_method(
    env: &mut JNIEnv,
    parser: &DexParser,
    dex_loader: &JObject,
    class_name: &str, // Java 风格: "com.example.MyClass"
    class_def: &ClassDefItem, // Pass the ClassDefItem
    method: &EncodedMethod,
) {
    if method.code_off == 0 {
        return; // 抽象或 Native 方法，没有 CodeItem
    }

    // 1. 加载类 (这会强制 ART 解析 ClassDef)
    let class_name_str = match env.new_string(class_name) {
        Ok(s) => s,
        Err(_) => return,
    };

    let class_loader_class = env.find_class("java/lang/ClassLoader").unwrap();
    let load_class_mid = env
        .get_method_id(
            class_loader_class,
            "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;",
        )
        .unwrap();

    // Use `call_method_unchecked` and provide the return signature
    let ret_sig = JavaType::from_str("Ljava/lang/Class;").unwrap();
    let class_obj = match unsafe { env.call_method_unchecked(
        dex_loader,
        load_class_mid,
        ret_sig,
        &[JValue::Object(&class_name_str.into())],
    ) } {
        Ok(val) => { // val is JValue
            match val.l() { // .l() extracts JObject from JValue
                Ok(obj) => obj, // This is the JObject we want
                Err(e) => {
                    log::warn!("JNI: JValue to JObject conversion failed: {:?}", e);
                    return;
                }
            }
        },
        Err(e) => { // JNI call itself failed
            let parsed_name = parser.get_class_name(class_def).unwrap_or_default();
            log::warn!("JNI: Failed to load class {} (parsed name: {}): {:?}", class_name, parsed_name, e);
            return;
        }
    };

    // 2. 获取方法 (这会强制 ART 解析 MethodDef 和 CodeItem)
    // This is the step that "calls" the internal GetCodeItem logic
    let jclass: JClass = class_obj.into();

    let method_name = match parser.get_method_name(method.method_idx) {
        Some(name) => name,
        None => return,
    };

    let signature = match parser.get_method_signature(method.method_idx) {
        Some(sig) => sig,
        None => return,
    };

    // 静态方法
    if (method.access_flags & 0x0008) != 0 {
        // ACC_STATIC
        match env.get_static_method_id(&jclass, &method_name, &signature) {
            Ok(_) => {
                log::info!("Resolved static method: {}.{}{}", class_name, method_name, signature);
            }
            Err(e) => {
                log::info!("Failed to resolve static {}.{}{}: {:?}", class_name, method_name, signature, e);
            }
        }
    } else {
        // 实例方法
        match env.get_method_id(&jclass, &method_name, &signature) {
            Ok(_) => {
                log::info!("Resolved method: {}.{}{}", class_name, method_name, signature);
            }
            Err(e) => {
                log::info!("Failed to resolve {}.{}{}: {:?}", class_name, method_name, signature, e);
            }
        }
    }
}