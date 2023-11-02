use crate::{
    configs::{
        ConnectionParameters, SchedulerConfig, SchedulerOverrideConfig, TargetConfig,
        DEFAULT_INTERVAL,
    },
    prober::Prober,
    store::{Store, Target, TargetState},
};
use futures::prelude::*;
use anyhow::Result as AnyResult;
use chrono::Utc;
use futures::stream::FuturesUnordered;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{sync::RwLock, time::sleep};

#[derive(Clone, Debug)]
pub struct ProbeScheduler {
    prober: Arc<Prober>,
    store: Arc<RwLock<Store>>,
    config: SchedulerConfig,
    target_store: HashMap<Target, TargetState>,
}

impl ProbeScheduler {
    pub fn new(prober: Arc<Prober>, store: Arc<RwLock<Store>>, config: SchedulerConfig) -> Self {
        Self {
            prober,
            store,
            config,
            target_store: Default::default(),
        }
    }

    pub fn add_target(
        &mut self,
        target: Target,
        conn_params: ConnectionParameters,
        schedule_config: SchedulerOverrideConfig,
    ) {
        self.target_store.insert(
            target,
            TargetState {
                conn_params,
                schedule_config,
                ..Default::default()
            },
        );
    }

    pub async fn load_from_target_config(&mut self, target_config: &TargetConfig) -> AnyResult<()> {
        let conn_params = ConnectionParameters::load_from_target_config(target_config).await?;
        let schedule_config = target_config.schedule_config.clone();

        self.add_target(target_config.target.parse()?, conn_params, schedule_config);

        Ok(())
    }

    pub fn iter_need_probe(&self) -> impl Iterator<Item = (&Target, &TargetState)> {
        self.target_store.iter().filter(|(_target, state)| {
            if let Some(last_probe) = state.last_probe {
                let config = &state.schedule_config + &self.config;
                let interval = config.interval;

                (Utc::now() - last_probe).to_std().unwrap_or(Duration::ZERO) > interval
            } else {
                true
            }
        })
    }

    /// Return the duration should wait to probe targets.
    pub fn wait_duration(&self) -> Duration {
        let now = Utc::now();

        self.target_store
            .values()
            .fold(DEFAULT_INTERVAL, |dura, v| {
                let nextdura = if let Some(last_probe) = v.last_probe {
                    let config = &v.schedule_config + &self.config;

                    let nextprobe = last_probe + config.interval;
                    (nextprobe - now).to_std().unwrap_or(Duration::ZERO)
                } else {
                    Duration::ZERO
                };

                dura.min(nextdura)
            })
    }

    pub async fn run(self: Arc<Self>) -> AnyResult<()> {
        loop {
            let wait = self.wait_duration();
            debug!("Sleep for: {}ms", wait.as_millis());
            sleep(wait).await;

            let targets: Vec<(Target, ConnectionParameters)> = self
                .iter_need_probe()
                .map(|(target, state)| (target.clone(), state.conn_params.clone()))
                .collect();

            let mut tasks =
                FuturesUnordered::from_iter(targets.into_iter().map(|(target, parameters)| {
                    let prober = self.prober.clone();
                    async move {
                        let task_result = prober.probe(&target, &parameters).await;
                        trace!("prober.probe() = {:?}", &task_result);
                        (target, task_result)
                    }
                }));

            while let Some((target, task_result)) = tasks.next().await {
                match task_result {
                    Ok(probe_results) => {
                        self.store
                            .write()
                            .await
                            .update_probe_result(&target, probe_results)?;
                    }
                    Err(e) => {
                        error!("Failed to probe the target: {}", e);
                    }
                };
            }
        }
    }
}
