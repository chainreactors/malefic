use std::path::PathBuf;
use std::time::Duration;
use windows::core::{Error, Interface, Result, BSTR, HRESULT, VARIANT};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CLSCTX_ALL, COINIT_MULTITHREADED,
};
use windows::Win32::System::TaskScheduler::{
    IActionCollection, IExecAction, IRegisteredTask, IRunningTaskCollection, ITaskDefinition,
    ITaskFolder, ITaskService, ITrigger, TaskScheduler, TASK_ACTION_EXEC, TASK_CREATE_OR_UPDATE,
    TASK_LOGON_NONE, TASK_STATE, TASK_TRIGGER_BOOT, TASK_TRIGGER_DAILY, TASK_TRIGGER_LOGON,
    TASK_TRIGGER_MONTHLY, TASK_TRIGGER_TYPE2, TASK_TRIGGER_WEEKLY,
};
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaskTriggerType {
    Daily,
    Weekly,
    Monthly,
    AtLogon,
    AtStartup,
}

impl From<&TaskTriggerType> for TASK_TRIGGER_TYPE2 {
    fn from(tt: &TaskTriggerType) -> Self {
        match tt {
            TaskTriggerType::Daily => TASK_TRIGGER_DAILY,
            TaskTriggerType::Weekly => TASK_TRIGGER_WEEKLY,
            TaskTriggerType::Monthly => TASK_TRIGGER_MONTHLY,
            TaskTriggerType::AtLogon => TASK_TRIGGER_LOGON,
            TaskTriggerType::AtStartup => TASK_TRIGGER_BOOT,
        }
    }
}

impl From<&TaskTriggerType> for u32 {
    fn from(tt: &TaskTriggerType) -> Self {
        match tt {
            TaskTriggerType::Daily => 2,
            TaskTriggerType::Weekly => 3,
            TaskTriggerType::Monthly => 4,
            TaskTriggerType::AtLogon => 9,
            TaskTriggerType::AtStartup => 8,
        }
    }
}

impl TryFrom<u32> for TaskTriggerType {
    type Error = Error;
    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        match value {
            2 => Ok(TaskTriggerType::Daily),
            3 => Ok(TaskTriggerType::Weekly),
            4 => Ok(TaskTriggerType::Monthly),
            9 => Ok(TaskTriggerType::AtLogon),
            8 => Ok(TaskTriggerType::AtStartup),
            _ => Err(Error::new(
                HRESULT(-1),
                &format!("Invalid TaskTriggerType value: {}", value),
            )),
        }
    }
}

impl TaskTriggerType {
    pub fn to_win32(&self) -> TASK_TRIGGER_TYPE2 {
        self.into()
    }

    pub fn to_int(&self) -> u32 {
        self.into()
    }

    pub fn from_int(value: u32) -> Result<Self> {
        value.try_into()
    }
}

#[derive(Debug, Clone)]
pub struct TaskConfig {
    pub name: String,
    pub path: String,
    pub description: String,
    pub executable_path: PathBuf,
    pub trigger_type: TaskTriggerType,
    pub duration: Duration,
    pub start_boundary: String,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct TaskStatus {
    pub state: TASK_STATE,
    pub last_run_time: Option<String>,
    pub next_run_time: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct TaskSchedule {
    pub config: TaskConfig,
    pub status: TaskStatus,
}

/// Parse an ISO 8601 duration string (e.g., "PT1H30M", "PT45S") into a Duration.
/// Only supports the time portion (PT prefix). Returns Duration::ZERO for invalid input.
pub fn parse_iso8601_duration(s: &str) -> Duration {
    let s = s.trim();
    if !s.starts_with("PT") && !s.starts_with("pt") {
        return Duration::ZERO;
    }
    let mut total_secs: u64 = 0;
    let mut num_buf = String::new();
    for c in s[2..].chars() {
        match c {
            'H' | 'h' => {
                total_secs += num_buf.parse::<u64>().unwrap_or(0) * 3600;
                num_buf.clear();
            }
            'M' | 'm' => {
                total_secs += num_buf.parse::<u64>().unwrap_or(0) * 60;
                num_buf.clear();
            }
            'S' | 's' => {
                total_secs += num_buf.parse::<u64>().unwrap_or(0);
                num_buf.clear();
            }
            _ => num_buf.push(c),
        }
    }
    Duration::from_secs(total_secs)
}

pub struct TaskSchedulerManager {
    task_service: ITaskService,
}

impl TaskSchedulerManager {
    pub fn initialize() -> Result<Self> {
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);

            let task_service: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_ALL)?;
            task_service.Connect(None, None, None, None)?;
            Ok(TaskSchedulerManager { task_service })
        }
    }

    pub fn create_task(&self, config: TaskConfig) -> Result<TaskConfig> {
        unsafe {
            let task_folder: ITaskFolder =
                self.task_service.GetFolder(&BSTR::from(&config.path))?;
            let task_definition: ITaskDefinition = self.task_service.NewTask(0)?;

            // Set description via RegistrationInfo
            if !config.description.is_empty() {
                let reg_info = task_definition.RegistrationInfo()?;
                reg_info.SetDescription(&BSTR::from(&config.description))?;
            }

            // Set trigger
            let trigger_collection = task_definition.Triggers()?;
            let trigger = trigger_collection
                .Create(config.trigger_type.to_win32())?
                .cast::<ITrigger>()?;
            trigger.SetStartBoundary(&BSTR::from(&config.start_boundary))?;

            // Set repetition if duration is non-zero
            if config.duration.as_secs() > 0 {
                let repetition = trigger.Repetition()?;
                let hours = config.duration.as_secs() / 3600;
                let minutes = (config.duration.as_secs() % 3600) / 60;
                let seconds = config.duration.as_secs() % 60;
                let interval_str = format!("PT{}H{}M{}S", hours, minutes, seconds);
                repetition.SetInterval(&BSTR::from(interval_str))?;
            }

            // Set enabled state via Settings
            let settings = task_definition.Settings()?;
            settings.SetEnabled(windows::Win32::Foundation::VARIANT_BOOL::from(
                config.enabled,
            ))?;

            // Set execution action
            let action_collection: IActionCollection = task_definition.Actions()?;
            let action = action_collection.Create(TASK_ACTION_EXEC)?;
            let exec_action: IExecAction = action.cast()?;
            exec_action.SetPath(&BSTR::from(
                config.executable_path.to_string_lossy().as_ref(),
            ))?;

            // Register task
            task_folder.RegisterTaskDefinition(
                &BSTR::from(&config.name),
                &task_definition,
                TASK_CREATE_OR_UPDATE.0,
                None,
                None,
                TASK_LOGON_NONE,
                None,
            )?;

            Ok(config)
        }
    }

    pub fn run_task(&self, path: &str, task_name: &str) -> Result<()> {
        unsafe {
            // Get task folder at specified path
            let task_folder: ITaskFolder = self.task_service.GetFolder(&BSTR::from(path))?;
            // Find specified task
            let task: IRegisteredTask = task_folder.GetTask(&BSTR::from(task_name))?;
            // Run task immediately
            task.Run(None)?;
            Ok(())
        }
    }

    pub fn start_task(&self, path: &str, task_name: &str) -> Result<()> {
        self.run_task(path, task_name)
    }

    pub fn stop_task(&self, path: &str, task_name: &str) -> Result<()> {
        unsafe {
            let task_folder: ITaskFolder = self.task_service.GetFolder(&BSTR::from(path))?;
            let task: IRegisteredTask = task_folder.GetTask(&BSTR::from(task_name))?;
            let running_tasks: IRunningTaskCollection = task.GetInstances(0)?;
            let count = running_tasks.Count()?;
            for i in 0..count {
                // COM collections are 1-indexed
                let index = VARIANT::from(i + 1);
                let running_task = running_tasks.get_Item(&index)?;
                running_task.Stop()?;
            }
            Ok(())
        }
    }

    pub fn delete_task(&self, path: &str, task_name: &str) -> Result<()> {
        unsafe {
            let task_folder: ITaskFolder = self.task_service.GetFolder(&BSTR::from(path))?;
            task_folder.DeleteTask(&BSTR::from(task_name), 0)?;
            Ok(())
        }
    }

    pub fn query_task(&self, path: &str, task_name: &str) -> Result<TaskSchedule> {
        unsafe {
            let task_folder: ITaskFolder = self.task_service.GetFolder(&BSTR::from(path))?;
            let task: IRegisteredTask = task_folder.GetTask(&BSTR::from(task_name))?;
            self.get_task(&task)
        }
    }

    fn get_task(&self, task: &IRegisteredTask) -> Result<TaskSchedule> {
        unsafe {
            // Get task definition
            let task_definition: ITaskDefinition = task.Definition()?;
            let triggers = task_definition.Triggers()?;

            // Configure TaskConfig
            let mut trigger_type = TaskTriggerType::Daily;
            let mut start_boundary = "N/A".to_string();
            let mut duration = Duration::new(0, 0);

            let mut trigger_count = 0;
            triggers.Count(&mut trigger_count)?;
            if trigger_count > 0 {
                // COM collections are 1-indexed
                let trigger = triggers.get_Item(1)?;
                let mut trigger_start: BSTR = BSTR::new();
                trigger.StartBoundary(&mut trigger_start)?;
                start_boundary = trigger_start.to_string();

                let mut interval_bstr: BSTR = BSTR::new();
                trigger.Repetition()?.Interval(&mut interval_bstr)?;
                let interval_str = interval_bstr.to_string();
                duration = parse_iso8601_duration(&interval_str);

                let mut trigger_type_value = TASK_TRIGGER_TYPE2(0);
                trigger.Type(&mut trigger_type_value)?;
                trigger_type = TaskTriggerType::from_int(trigger_type_value.0 as u32)
                    .unwrap_or(TaskTriggerType::Daily);
            }

            let action_collection = task_definition.Actions()?;
            // COM collections are 1-indexed
            let action = action_collection.get_Item(1)?;
            let exec_action: IExecAction = action.cast()?;
            let mut path_bstr: BSTR = BSTR::new();
            exec_action.Path(&mut path_bstr)?;

            let mut description_bstr: BSTR = BSTR::new();
            task_definition
                .RegistrationInfo()?
                .Description(&mut description_bstr)?;

            // task.Path() returns the full path like "\FolderName\TaskName".
            // We need just the folder portion, since all APIs (run/query/delete)
            // use path as a folder argument to GetFolder().
            let full_path = task.Path()?.to_string();
            let folder_path = std::path::Path::new(&full_path)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "\\".to_string());

            let config = TaskConfig {
                name: task.Name()?.to_string(),
                path: folder_path,
                description: description_bstr.to_string(),
                executable_path: PathBuf::from(path_bstr.to_string()),
                trigger_type,
                duration,
                start_boundary,
                enabled: task.Enabled()?.as_bool(),
            };

            // Get TaskStatus
            let state = task.State()?;
            let last_run_time = task.LastRunTime()?.to_string();
            let next_run_time = task.NextRunTime()?.to_string();

            let status = TaskStatus {
                state,
                last_run_time: Some(last_run_time),
                next_run_time: Some(next_run_time),
                enabled: task.Enabled()?.as_bool(),
            };

            Ok(TaskSchedule { config, status })
        }
    }

    // Modify list_tasks_in_folder to return Vec<TaskSchedule>
    fn list_tasks_in_folder(&self, folder: &ITaskFolder) -> Result<Vec<TaskSchedule>> {
        let mut tasks = Vec::new();
        unsafe {
            let tasks_collection = folder.GetTasks(0)?;
            let count = tasks_collection.Count()?;

            for i in 0..count {
                // COM collections are 1-indexed
                let task: IRegisteredTask = tasks_collection.get_Item(&VARIANT::from(i + 1))?;
                if let Ok(schedule) = self.get_task(&task) {
                    tasks.push(schedule);
                }
            }
        }
        Ok(tasks)
    }

    // List direct subfolders of current folder
    fn list_sub_folders(&self, folder: &ITaskFolder) -> Result<Vec<ITaskFolder>> {
        let mut sub_folders = Vec::new();
        unsafe {
            let folders_collection = folder.GetFolders(0)?;
            let folder_count = folders_collection.Count()?;

            for i in 0..folder_count {
                // COM collections are 1-indexed
                let sub_folder = folders_collection.get_Item(&VARIANT::from(i + 1))?;
                sub_folders.push(sub_folder);
            }
        }

        Ok(sub_folders)
    }

    fn list_recu_sub_folders(&self, folder: &ITaskFolder) -> Result<Vec<ITaskFolder>> {
        let mut all_sub_folders = Vec::new();
        let direct_sub_folders = self.list_sub_folders(folder)?;

        for sub_folder in direct_sub_folders {
            all_sub_folders.push(sub_folder.clone());

            let child_folders = self.list_recu_sub_folders(&sub_folder)?;
            all_sub_folders.extend(child_folders);
        }

        Ok(all_sub_folders)
    }

    // Modify list_tasks to return Vec<TaskSchedule>
    pub fn list_tasks(&self, start_folder_path: &str) -> Result<Vec<TaskSchedule>> {
        let start_folder = unsafe {
            self.task_service
                .GetFolder(&BSTR::from(start_folder_path))?
        };
        let mut all_schedules = self.list_tasks_in_folder(&start_folder)?;
        let sub_folders = self.list_recu_sub_folders(&start_folder)?;
        for folder in sub_folders {
            malefic_common::debug!("Listing tasks in folder {:#?}", folder);
            match self.list_tasks_in_folder(&folder) {
                Ok(mut folder_tasks) => all_schedules.append(&mut folder_tasks),
                Err(_e) => {
                    malefic_common::debug!(
                        "Failed to list tasks in folder {:?}{:?}: {:?}",
                        unsafe { folder.Path() },
                        unsafe { folder.Name() },
                        _e
                    )
                }
            }
        }

        Ok(all_schedules)
    }
}

// NOTE: Do NOT implement Drop with CoUninitialize() for TaskSchedulerManager.
// Each module handler (TaskSchdList, TaskSchdCreate, etc.) creates a new
// TaskSchedulerManager per request via `TaskSchedulerManager::initialize()`.
// If Drop calls CoUninitialize(), it will tear down COM for the entire thread,
// causing subsequent initialize() calls in the same thread to fail.
// Since CoInitializeEx is idempotent (returns S_FALSE on repeated calls),
// but CoUninitialize is NOT, the safe approach is to let COM stay initialized
// for the thread's lifetime.
//
// impl Drop for TaskSchedulerManager {
//     fn drop(&mut self) {
//         unsafe {
//             CoUninitialize();
//         }
//     }
// }
