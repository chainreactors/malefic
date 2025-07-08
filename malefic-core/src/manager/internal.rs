use strum_macros::{EnumString, Display}; // 确保正确导入 Display 宏

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(EnumString, Display)]
pub enum InternalModule {
    #[strum(serialize = "ping")]
    Ping,
    #[strum(serialize = "init")]
    Init,
    #[strum(serialize = "refresh_module")]
    RefreshModule,
    #[strum(serialize = "list_module")]
    ListModule,
    #[strum(serialize = "load_module")]
    LoadModule,
    #[strum(serialize = "load_addon")]
    LoadAddon,
    #[strum(serialize = "list_addon")]
    ListAddon,
    #[strum(serialize = "execute_addon")]
    ExecuteAddon,
    #[strum(serialize = "refresh_addon")]
    RefreshAddon,
    #[strum(serialize = "clear")]
    Clear,
    #[strum(serialize = "cancel_task")]
    CancelTask,
    #[strum(serialize = "query_task")]
    QueryTask,
    #[strum(serialize = "list_task")]
    ListTask,
    #[strum(serialize = "sleep")]
    Sleep,
    #[strum(serialize = "suicide")]
    Suicide,
    #[strum(serialize = "switch")]
    Switch,
}

impl InternalModule {
    pub fn all() -> Vec<String> {
        vec![
            InternalModule::Ping,
            InternalModule::Init,
            InternalModule::RefreshModule,
            InternalModule::ListModule,
            #[cfg(target_family = "windows")]
            InternalModule::LoadModule,
            InternalModule::LoadAddon,
            InternalModule::ListAddon,
            InternalModule::ExecuteAddon,
            InternalModule::RefreshAddon,
            InternalModule::Clear,
            InternalModule::CancelTask,
            InternalModule::QueryTask,
            InternalModule::ListTask,
            InternalModule::Sleep,
            InternalModule::Suicide,
            InternalModule::Switch,
        ]
            .iter()
            .map(|m| m.to_string()) // Display 自动提供 to_string() 方法
            .collect()
    }
}