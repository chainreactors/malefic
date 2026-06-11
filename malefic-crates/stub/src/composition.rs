use malefic_common::errors::MaleficError;
use malefic_manager::manager::{MaleficManager, ModuleRegister};

pub fn register_builtin_bundles(manager: &mut MaleficManager) -> Result<(), MaleficError> {
    manager.register_bundle(
        "origin",
        malefic_modules::register_modules as ModuleRegister,
    );
    #[cfg(feature = "malefic-3rd")]
    manager.register_bundle("3rd", malefic_3rd::register_3rd as ModuleRegister);
    manager.refresh_module()
}

pub fn default_manager() -> Result<MaleficManager, MaleficError> {
    let mut manager = MaleficManager::new();
    register_builtin_bundles(&mut manager)?;
    Ok(manager)
}
