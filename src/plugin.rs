use libloading::{Library, Symbol};
use std::collections::HashMap;
use std::ffi::{CString, c_char, c_int};
use std::sync::{Arc, Mutex};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct PluginResult {
    pub name: String,
    pub version: String,
    pub output: String,
}

pub trait PluginAnalyzer: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn analyze(&self, binary_data: &[u8], function_name: &str) -> anyhow::Result<String>;
}

type PluginCreateFn = unsafe fn() -> *mut dyn PluginAnalyzer;

pub struct PluginInstance {
    #[allow(dead_code)]
    library: Library,
    analyzer: Arc<dyn PluginAnalyzer>,
}

pub struct PluginManager {
    plugins: Mutex<HashMap<String, PluginInstance>>,
}

impl PluginManager {
    pub fn new() -> Self {
        PluginManager {
            plugins: Mutex::new(HashMap::new()),
        }
    }

    pub fn load_plugin(&self, path: &str) -> anyhow::Result<String> {
        unsafe {
            let library = Library::new(path)?;
            let create: Symbol<PluginCreateFn> = library.get(b"create_plugin")?;
            let raw_ptr = create();
            let analyzer: Arc<dyn PluginAnalyzer> = Arc::from_raw(raw_ptr);
            let name = analyzer.name().to_string();

            let instance = PluginInstance { library, analyzer };
            self.plugins.lock().unwrap().insert(name.clone(), instance);
            Ok(name)
        }
    }

    pub fn unload_plugin(&self, name: &str) -> anyhow::Result<()> {
        self.plugins
            .lock()
            .unwrap()
            .remove(name)
            .ok_or_else(|| anyhow::anyhow!("Plugin not found: {}", name))?;
        Ok(())
    }

    pub fn list_plugins(&self) -> Vec<(String, String)> {
        self.plugins
            .lock()
            .unwrap()
            .values()
            .map(|p| (p.analyzer.name().to_string(), p.analyzer.version().to_string()))
            .collect()
    }

    pub fn analyze(
        &self,
        plugin_name: &str,
        binary_data: &[u8],
        function_name: &str,
    ) -> anyhow::Result<PluginResult> {
        let plugins = self.plugins.lock().unwrap();
        let plugin = plugins
            .get(plugin_name)
            .ok_or_else(|| anyhow::anyhow!("Plugin not found: {}", plugin_name))?;

        let output = plugin.analyzer.analyze(binary_data, function_name)?;

        Ok(PluginResult {
            name: plugin.analyzer.name().to_string(),
            version: plugin.analyzer.version().to_string(),
            output,
        })
    }
}

// C FFI interface for plugins written in other languages
#[no_mangle]
pub extern "C" fn ghostbin_plugin_alloc(size: usize) -> *mut u8 {
    let mut buf = vec![0u8; size];
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

#[no_mangle]
pub extern "C" fn ghostbin_plugin_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn ghostbin_plugin_version() -> c_int {
    1
}

// Helper macro for Rust plugin authors
#[macro_export]
macro_rules! define_plugin {
    ($type:ty) => {
        #[no_mangle]
        pub extern "C" fn create_plugin() -> *mut dyn $crate::plugin::PluginAnalyzer {
            let plugin: Box<dyn $crate::plugin::PluginAnalyzer> = Box::new(<$type>::new());
            Box::into_raw(plugin)
        }
    };
}
