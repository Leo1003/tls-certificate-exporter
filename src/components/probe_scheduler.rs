use crate::{
    configs::{
        ConnectionParameters, SchedulerConfig, SchedulerOverrideConfig, TargetConfig,
        DEFAULT_INTERVAL,
    },
    prober::Prober,
    store::{Store, Target, TargetState},
};
use anyhow::Result as AnyResult;
use chrono::Utc;
use futures::prelude::*;
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
            if let Some(next_probe) = state.next_probe {
                Utc::now() >= next_probe
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
                let nextdura = if let Some(next_probe) = v.next_probe {
                    (next_probe - now).to_std().unwrap_or(Duration::ZERO)
                } else {
                    Duration::ZERO
                };

                dura.min(nextdura)
            })
    }

    pub async fn run(&mut self) -> AnyResult<()> {
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
                let state = self.target_store.get_mut(&target);

                match task_result {
                    Ok(probe_results) => {
                        self.store
                            .write()
                            .await
                            .update_probe_result(&target, probe_results)?;

                        if let Some(state) = state {
                            let config = &state.schedule_config + &self.config;
                            state.last_probe = Some(Utc::now());
                            state.next_probe = Some(Utc::now() + config.interval);
                        }
                    }
                    Err(e) => {
                        error!("Failed to probe the target: {}", e);

                        if let Some(state) = state {
                            // TODO: Add backoff interval config
                            let _config = &state.schedule_config + &self.config;
                            state.last_probe = Some(Utc::now());
                            state.next_probe = Some(Utc::now() + Duration::from_secs(20));
                        }
                    }
                };
            }
        }
    }
}
