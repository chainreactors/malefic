use crate::debug;
use std::path::PathBuf;
use std::time::Duration;
use windows::core::{Interface, Result, BSTR, VARIANT};
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_ALL, COINIT_MULTITHREADED};
use windows::Win32::System::TaskScheduler::{IActionCollection, IExecAction, 
                                            IRegisteredTask, IRunningTaskCollection, 
                                            ITaskDefinition, ITaskFolder, ITaskService, ITrigger, 
                                            TaskScheduler, TASK_ACTION_EXEC, TASK_CREATE_OR_UPDATE, TASK_LOGON_NONE, 
                                            TASK_STATE, TASK_TRIGGER_BOOT, TASK_TRIGGER_DAILY, TASK_TRIGGER_LOGON, 
                                            TASK_TRIGGER_MONTHLY, TASK_TRIGGER_TYPE2, TASK_TRIGGER_WEEKLY};
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum TaskTriggerType {
    Daily,
    Weekly,
    Monthly,
    AtLogon,
    AtStartup,
}

impl TaskTriggerType {
    pub fn to_win32(&self) -> TASK_TRIGGER_TYPE2 {
        match self {
            TaskTriggerType::Daily => TASK_TRIGGER_DAILY,
            TaskTriggerType::Weekly => TASK_TRIGGER_WEEKLY,
            TaskTriggerType::Monthly => TASK_TRIGGER_MONTHLY,
            TaskTriggerType::AtLogon => TASK_TRIGGER_LOGON,
            TaskTriggerType::AtStartup => TASK_TRIGGER_BOOT,
        }
    }

    pub fn to_int(&self) -> u32 {
        match self {
            TaskTriggerType::Daily => 2,
            TaskTriggerType::Weekly => 3,
            TaskTriggerType::Monthly => 4,
            TaskTriggerType::AtLogon => 9,
            TaskTriggerType::AtStartup => 8,
        }
    }

    pub fn from_int(value: u32) -> anyhow::Result<Self> {
        match value {
            2 => Ok(TaskTriggerType::Daily),
            3 => Ok(TaskTriggerType::Weekly),
            4 => Ok(TaskTriggerType::Monthly),
            9 => Ok(TaskTriggerType::AtLogon),
            8 => Ok(TaskTriggerType::AtStartup),
            _ => Err(anyhow::anyhow!("Invalid TaskTriggerType value: {}", value)),
        }
    }
}

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone)]
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

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone)]
pub struct TaskStatus {
    pub state: TASK_STATE,
    pub last_run_time: Option<String>,
    pub next_run_time: Option<String>,
    pub enabled: bool,
}

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone)]
pub struct TaskSchedule {
    pub config: TaskConfig,
    pub status: TaskStatus,
}

pub struct TaskSchedulerManager {
    task_service: ITaskService,
}

impl TaskSchedulerManager {
    pub fn initialize() -> Result<Self> {

        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
            // if hr != HRESULT(0) {
            //     debug!("Failed to initialize COM: {:#?}", hr);
            //     return Err(hr.into());
            // }

            let task_service: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_ALL)?;
            task_service.Connect(None, None, None, None)?;
            // CoUninitialize();
            Ok(TaskSchedulerManager { task_service })
        }
    }

    pub fn create_task(&self, config: TaskConfig) -> Result<TaskConfig> {
        unsafe {
            let task_folder: ITaskFolder =
                self.task_service.GetFolder(&BSTR::from(&config.path))?;
            let task_definition: ITaskDefinition = self.task_service.NewTask(0)?;

            // 设置触发器
            let trigger_collection = task_definition.Triggers()?;
            let trigger = trigger_collection
                .Create(config.trigger_type.to_win32())?
                .cast::<ITrigger>()?;
            trigger.SetStartBoundary(&BSTR::from(&config.start_boundary))?;

            // 设置执行动作
            let action_collection: IActionCollection = task_definition.Actions()?;
            let action = action_collection.Create(TASK_ACTION_EXEC)?;
            let exec_action: IExecAction = action.cast()?;
            exec_action.SetPath(&BSTR::from(config.executable_path.to_str().unwrap()))?;

            // 注册任务
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
            // 获取指定路径下的任务文件夹
            let task_folder: ITaskFolder = self.task_service.GetFolder(&BSTR::from(path))?;
            // 查找指定任务
            let task: IRegisteredTask = task_folder.GetTask(&BSTR::from(task_name))?;
            // 立即运行任务
            task.Run(None)?;
            Ok(())
        }
    }

    pub fn start_task(&self, path: &str, task_name: &str) -> Result<()> {
        unsafe {
            let task_folder: ITaskFolder = self.task_service.GetFolder(&BSTR::from(path))?;
            let task: IRegisteredTask = task_folder.GetTask(&BSTR::from(task_name))?;
            task.Run(None)?;
            Ok(())
        }
    }

    pub fn stop_task(&self, path: &str, task_name: &str) -> Result<()> {
        unsafe {
            let task_folder: ITaskFolder = self.task_service.GetFolder(&BSTR::from(path))?;
            let task: IRegisteredTask = task_folder.GetTask(&BSTR::from(task_name))?;
            let running_tasks: IRunningTaskCollection = task.GetInstances(0)?;
            let count = running_tasks.Count()?;
            for i in 0..count {
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

            let _ = task.Definition()?;
            self.get_task(&task)
        }
    }

    fn get_task(&self, task: &IRegisteredTask) -> Result<TaskSchedule> {
        unsafe {
            // 获取任务定义
            let task_definition: ITaskDefinition = task.Definition()?;
            let triggers = task_definition.Triggers()?;

            // 配置 TaskConfig
            let mut trigger_type = TaskTriggerType::Daily;
            let mut start_boundary = "N/A".to_string();
            let mut duration = Duration::new(0, 0);

            let mut trigger_count = 0;
            triggers.Count(&mut trigger_count)?;
            if trigger_count > 0 {
                let trigger = triggers.get_Item(1)?;
                let mut trigger_start: BSTR = BSTR::new();
                trigger.StartBoundary(&mut trigger_start)?;
                start_boundary = trigger_start.to_string();

                let mut interval_bstr: BSTR = BSTR::new();
                trigger.Repetition()?.Interval(&mut interval_bstr)?;
                duration = Duration::from_secs(
                    interval_bstr.to_string().parse::<u64>().unwrap_or(0) / 10_000_000,
                );

                let mut trigger_type_value = TASK_TRIGGER_TYPE2(0);
                trigger.Type(&mut trigger_type_value)?;
                trigger_type = TaskTriggerType::from_int(trigger_type_value.0 as u32)
                    .unwrap_or(TaskTriggerType::Daily);
            }

            let action_collection = task_definition.Actions()?;
            let action = action_collection.get_Item(1)?;
            let exec_action: IExecAction = action.cast()?;
            let mut path_bstr: BSTR = BSTR::new();
            exec_action.Path(&mut path_bstr)?;

            let mut description_bstr: BSTR = BSTR::new();
            task_definition
                .RegistrationInfo()?
                .Description(&mut description_bstr)?;

            let config = TaskConfig {
                name: task.Name()?.to_string(),
                path: task.Path()?.to_string(),
                description: description_bstr.to_string(),
                executable_path: PathBuf::from(path_bstr.to_string()),
                trigger_type,
                duration,
                start_boundary,
                enabled: task.Enabled()?.as_bool(),
            };

            // 获取 TaskStatus
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

    // 修改 list_tasks_in_folder 以返回 Vec<TaskSchedule>
    fn list_tasks_in_folder(&self, folder: &ITaskFolder) -> Result<Vec<TaskSchedule>> {
        let mut tasks = Vec::new();
        unsafe {
            let tasks_collection = folder.GetTasks(0)?;
            let count = tasks_collection.Count()?;

            for i in 0..count {
                let task: IRegisteredTask = tasks_collection.get_Item(&VARIANT::from(i + 1))?;
                if let Ok(schedule) = self.get_task(&task) {
                    tasks.push(schedule);
                }
            }
        }
        Ok(tasks)
    }

    // 列出当前文件夹的直接子文件夹
    fn list_sub_folders(&self, folder: &ITaskFolder) -> Result<Vec<ITaskFolder>> {
        let mut sub_folders = Vec::new();
        unsafe {
            let folders_collection = folder.GetFolders(0)?;
            let folder_count = folders_collection.Count()?;

            for i in 0..folder_count {
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

    // 修改 list_tasks 以返回 Vec<TaskSchedule>
    pub fn list_tasks(&self, start_folder_path: &str) -> Result<Vec<TaskSchedule>> {
        let start_folder = unsafe {
            self.task_service
                .GetFolder(&BSTR::from(start_folder_path))?
        };
        let mut all_schedules = self.list_tasks_in_folder(&start_folder)?;
        let sub_folders = self.list_recu_sub_folders(&start_folder)?;
        for folder in sub_folders {
            debug!("Listing tasks in folder {:#?}", folder);
            match self.list_tasks_in_folder(&folder) {
                Ok(mut folder_tasks) => {
                    // debug!("Listed tasks in folder {:#?}", folder_tasks);
                    all_schedules.append(&mut folder_tasks)
                }
                Err(e) => unsafe {
                    debug!(
                        "Failed to list tasks in folder {:?}{:?}: {:?}",
                        folder.Path(),
                        folder.Name(),
                        e
                    )
                },
            }
        }

        Ok(all_schedules)
    }
}

// impl Drop for TaskSchedulerManager {
//     fn drop(&mut self) {
//         unsafe {
//             CoUninitialize();
//         }
//     }
// }
