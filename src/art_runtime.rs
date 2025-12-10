// src/art_runtime.rs
use super::dex_parser::ParsedMethod;
use jni::objects::{GlobalRef, JClass, JObject, JValue};
use jni::JavaVM;
use log::{debug, error, info};
use std::collections::HashSet;

fn get_system_classloader<'a>(env: &mut jni::JNIEnv<'a>) -> anyhow::Result<JObject<'a>> {
    let class_loader_cls = env.find_class("java/lang/ClassLoader")?;
    let loader = env.call_static_method(
        class_loader_cls,
        "getSystemClassLoader",
        "()Ljava/lang/ClassLoader;",
        &[]
    )?.l()?;
    
    if loader.is_null() {
        anyhow::bail!("getSystemClassLoader returned null");
    }
    Ok(loader)
}

fn get_app_classloader<'a>(env: &mut jni::JNIEnv<'a>) -> anyhow::Result<JObject<'a>> {
    let at = env.find_class("android/app/ActivityThread")?;

    let current = env
        .call_static_method(at, "currentActivityThread", "()Landroid/app/ActivityThread;", &[])?
        .l()?;

    if current.is_null() {
        anyhow::bail!("ActivityThread.currentActivityThread() returned null");
    }

    let app = env
        .call_method(current, "getApplication", "()Landroid/app/Application;", &[])?
        .l()?;

    if app.is_null() {
        anyhow::bail!("ActivityThread.getApplication() returned null");
    }

    let cl = env
        .call_method(app, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?
        .l()?;

    if cl.is_null() {
        anyhow::bail!("Application.getClassLoader() returned null");
    }

    Ok(cl)
}

/// Helper to safely create a global ref and add it to the loaders list.
/// Returns true if a fatal error occurred.
fn add_loader_to_list(
    env: &mut jni::JNIEnv, // <-- FIX: Made mutable for exception_clear
    loaders: &mut Vec<GlobalRef>,
    loader_obj: JObject,
) -> bool {
    if !loader_obj.is_null() {
        match env.new_global_ref(loader_obj) {
            Ok(g) => loaders.push(g),
            Err(_) => {
                // Failed to create global ref
                if env.exception_clear().is_err() {
                    error!("[ArtRuntime] Fatal JNI error creating global ref. Aborting.");
                    return true; // Signal fatal
                }
            }
        }
    }
    false // Not fatal
}

/// Returns true if the class belongs to system/framework packages 
/// that we generally don't need to unpack or resolve.
fn should_skip_class(binary_name: &str) -> bool {
    // List of prefixes to ignore.
    // You can add "com.google." or others if your target app uses them heavily
    // and you don't care about them.
    const SKIP_PREFIXES: &[&str] = &[
        "android.",
        "com.android.",
        "androidx.",
        "java.",
        "javax.",
        "dalvik.",
        "sun.",
        "libcore.",
        "kotlin.",
        "kotlinx.",
        "org.json.",
        "org.xml.",
        "org.w3c.",
        // "com.google.gson.", // Optional: Skip common libraries if desired
    ];

    for prefix in SKIP_PREFIXES {
        if binary_name.starts_with(prefix) {
            return true;
        }
    }
    false
}

// --- Main Function ---

/// Iterates through a list of parsed methods and attempts to resolve them using JNI.
/// This forces the ART runtime to load and prepare the method, often triggering
/// `GetCodeItem` and causing lazy-compiled code to be fully unpacked.
pub fn force_resolve_methods(vm: &JavaVM, methods: &Vec<ParsedMethod>) {
    // FILTER: Only resolve methods that actually have code to unpack.
    // This skips imported methods (references to other DEX files) which cause
    // most ClassNotFound errors.
    let target_methods: Vec<&ParsedMethod> = methods.iter()
        .filter(|m| m.code_item.is_some()) 
        .collect();
    if target_methods.is_empty() {
        info!("[ArtRuntime] No methods with CodeItems found to resolve.");
        return;
    }
    info!("[ArtRuntime] Attaching to VM to resolve {} defined methods (out of {} total refs)...", target_methods.len(), methods.len());

    let mut env = match vm.attach_current_thread_as_daemon() {
        Ok(env) => env,
        Err(e) => {
            error!("[ArtRuntime] Failed to attach to JNIEnv: {:?}", e);
            return;
        }
    };

    // --- Get java.lang.Class (needed for Class.forName) ---
    let cls_java_lang_class = match env.find_class("java/lang/Class") {
        Ok(cls) => Some(cls),
        Err(_) => {
            if env.exception_clear().is_err() {
                error!("[ArtRuntime] Fatal JNI error finding java.lang.Class. Aborting.");
            } else {
                error!("[ArtRuntime] Cannot find java.lang.Class. Aborting.");
            }
            return;
        }
    };

    // --- Prepare a list of candidate classloaders ---
    let mut loaders: Vec<GlobalRef> = Vec::new();

    // ClassLoader
    match get_app_classloader(&mut env) {
        Ok(loader) => {
            if add_loader_to_list(&mut env, &mut loaders, loader) {
                return; // Fatal error
            }
        }
        Err(_) => {
            if env.exception_clear().is_err() {
                error!("[ArtRuntime] Fatal JNI error getting system loader. Aborting.");
                return;
            }
        }
    }

    match get_system_classloader(&mut env) {
        Ok(loader) => {
            if add_loader_to_list(&mut env, &mut loaders, loader) {
                return; // Fatal error
            } 
        }
        Err(_) => {
            if env.exception_clear().is_err() {
                error!("[ArtRuntime] Fatal JNI error getting system loader. Aborting.");
                return;
            }
        }
    }

    info!("[ArtRuntime] Found {} classloaders to try.", loaders.len());

    // --- Main Method Resolution Loop ---
    let mut skipped_system_count: u32 = 0;
    let mut resolved_count:u32 = 0;
    let mut class_not_found_count:u32 = 0;
    let mut class_not_found_simple_count:u32 = 0;
    let mut method_not_found_count:u32 = 0;
    let mut seen = HashSet::<(String, String, String)>::new();

    for (i, method) in target_methods.iter().enumerate() {
        if (i + 1) % 1000 == 0 {
            info!(
                "[ArtRuntime] Progress: {}/{} methods processed...",
                i + 1,
                target_methods.len()
            );
        }

        // Deduplicate identical (class, name, sig) entries
        let triple = (
            method.class_name.clone(),
            method.method_name.clone(),
            method.signature.clone(),
        );
        if !seen.insert(triple) {
            continue;
        }

        // *** FIX: Use the descriptor_to_binary_name function correctly ***
        if let Some(class_name_jni) = descriptor_to_binary_name(&method.class_name) {
            if should_skip_class(&class_name_jni) {
                skipped_system_count += 1;
                continue; 
            }
            // --- Try to find the class via several strategies ---
            let mut found_jclass: Option<JClass> = None;

            // 1) Try env.find_class (fast, but only for current loader)
            // Note: find_class needs "java/lang/String", not "java.lang.String"
            let class_descriptor_name = class_name_jni.replace('.', "/");
            match env.find_class(&class_descriptor_name) {
                Ok(cls) => {
                    found_jclass = Some(cls);
                }
                Err(_) => {
                    if env.exception_clear().is_err() {
                        error!("[ArtRuntime] Fatal JNI error in find_class. Aborting.");
                        return;
                    }
                    class_not_found_simple_count += 1;
                }
            };

            // 2) If not found, try loader.loadClass(name)
            // Note: loadClass needs "java.lang.String" (which is class_name_jni)
            if found_jclass.is_none() {
                'loader_loop: for loader_opt in &loaders {
                    let gref = loader_opt;
                    let jname = match env.new_string(&class_name_jni) {
                        Ok(s) => s,
                        Err(_) => {
                            if env.exception_clear().is_err() { return; }
                            continue;
                        }
                    };
                    
                    let args = &[JValue::from(&jname)];
                    
                    match env.call_method(
                        gref.as_obj(),
                        "loadClass",
                        "(Ljava/lang/String;)Ljava/lang/Class;",
                        args,
                    ) {
                        Ok(ret) => {
                            if let Ok(cls_obj) = ret.l() {
                                if !cls_obj.is_null() {
                                    found_jclass = Some(JClass::from(cls_obj));
                                    break 'loader_loop;
                                }
                            }
                        }
                        Err(_) => {
                            if env.exception_clear().is_err() { return; }
                        }
                    }
                }
            }

            // 3) If still not found, try Class.forName(name, true, loader)
            // Note: forName also needs "java.lang.String"
            if found_jclass.is_none() {
                if let Some(cls_class) = &cls_java_lang_class {
                    'loader_loop_2: for loader_opt in &loaders {
                        let jname = match env.new_string(&class_name_jni) {
                            Ok(s) => s,
                            Err(_) => {
                                if env.exception_clear().is_err() { return; }
                                continue;
                            }
                        };
                        
                        let loader_arg = JValue::Object(loader_opt.as_obj());

                        // No deadlocks / no static initializer execution
                        // Setting this to true runs the <clinit> (static block). While this is better for unpacking, 
                        // it is risky in a Zygisk module because the static block might try to load native libraries (so/dll) that crash because the context is slightly wrong, 
                        // or it might contain anti-tamper checks. false is the safer default
                        let init_arg = JValue::Bool(0); // initialize = false

                        let args = &[JValue::from(&jname), init_arg, loader_arg];
                        
                        match env.call_static_method(
                            cls_class,
                            "forName",
                            "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;",
                            args,
                        ) {
                            Ok(ret) => {
                                if let Ok(cls_obj) = ret.l() {
                                    if !cls_obj.is_null() {
                                        found_jclass = Some(JClass::from(cls_obj));
                                        break 'loader_loop_2;
                                    }
                                }
                            }
                            Err(_) => {
                                if env.exception_clear().is_err() { return; }
                            }
                        }
                    }
                }
            }

            if found_jclass.is_none() {
                debug!("[ArtRuntime] class not found for descriptor {} (binary {})", method.class_name, class_name_jni);
                class_not_found_count += 1;
                continue;
            }

            // --- Now we have jclass; attempt to resolve method ---
            let jclass = found_jclass.unwrap();

            // Try instance method
            match env.get_method_id(&jclass, &method.method_name, &method.signature) {
                Ok(_) => {
                    resolved_count += 1;
                    continue; // Found it, we're done.
                }
                Err(_) => {
                    if env.exception_clear().is_err() {
                        error!("[ArtRuntime] Fatal JNI error in get_method_id. Aborting.");
                        return;
                    }
                }
            }

            // Try static method
            match env.get_static_method_id(&jclass, &method.method_name, &method.signature) {
                Ok(_) => {
                    resolved_count += 1;
                    if env.exception_clear().is_err() {
                        error!("[ArtRuntime] Fatal JNI error after get_static_method_id. Aborting.");
                        return;
                    }
                }
                Err(_) => {
                    if env.exception_clear().is_err() {
                        error!("[ArtRuntime] Fatal JNI error in get_static_method_id. Aborting.");
                        return;
                    }
                    method_not_found_count += 1;
                }
            }
        } else {
             // descriptor_to_binary_name returned None
            class_not_found_count += 1;
        }
    }

    info!("[ArtRuntime] --- Method Resolution Complete ---");
    info!("[ArtRuntime] Succeeded: {}", resolved_count);
    info!("[ArtRuntime] Class System Skipped: {}, Class Not Found (Skipped): {}, Class Not Found by env-findclass {}", skipped_system_count ,class_not_found_count, class_not_found_simple_count);
    info!("[ArtRuntime] Method Not Found (Skipped): {}", method_not_found_count);
}


/// Convert a DEX descriptor to a binary class name suitable for Class.forName or loadClass:
/// - "Ljava/lang/String;" -> "java.lang.String"
/// - "[Ljava/lang/String;" -> "[Ljava.lang.String;"
/// - "[I" -> "[I" (primitive array, leave as-is)
fn descriptor_to_binary_name(descriptor: &str) -> Option<String> {
    if descriptor.is_empty() {
        return None;
    }

    // Array types start with '['
    if descriptor.starts_with('[') {
        // Find 'L' if it's an object array
        if let Some(pos) = descriptor.find('L') {
            if descriptor.ends_with(';') {
                let lead = &descriptor[..pos]; 
                let inner = &descriptor[pos + 1..descriptor.len() - 1];
                let dot_inner = inner.replace('/', ".");
                
                let result = format!("{}L{};", lead, dot_inner);
                return Some(result);
            } else {
                return None; // Malformed
            }
        } else {
            // Primitive array like "[I" or "[B" -> return as-is
            return Some(descriptor.to_string());
        }
    }

    // Non-array object descriptor: must be like "Ljava/lang/String;"
    if descriptor.starts_with('L') && descriptor.ends_with(';') {
        let inner = &descriptor[1..descriptor.len() - 1];
        let dot = inner.replace('/', ".");
        Some(dot)
    } else {
        // Primitive (e.g., "I") or malformed
        None
    }
}