use super::{FileContent, ModuleConfig, Starttls, DEFAULT_TIMEOUT};
use anyhow::Result as AnyResult;
use petgraph::{
    algo::{has_path_connecting, DfsSpace},
    graph::Graph,
    visit::{Reversed, Topo},
};
use std::{collections::HashMap, path::PathBuf, time::Duration};

#[derive(Clone, Debug)]
pub struct ResolvedModuleConfig {
    pub timeout: Duration,

    pub trustedanchors: FileContent,

    pub certs: Option<FileContent>,

    pub key: Option<FileContent>,

    pub server_name: Option<String>,

    pub starttls: Option<Starttls>,

    pub insecure_skip_verify: bool,
}

impl ResolvedModuleConfig {
    pub fn override_with(&mut self, override_cfg: &ModuleConfig) {
        if let Some(timeout) = override_cfg.timeout {
            self.timeout = timeout;
        }
        if let Some(trustedanchors) = &override_cfg.trustedanchors {
            self.trustedanchors = trustedanchors.clone();
        }
        if let Some(certs) = &override_cfg.certs {
            self.certs = Some(certs.clone());
        }
        if let Some(key) = &override_cfg.key {
            self.key = Some(key.clone());
        }
        if let Some(server_name) = &override_cfg.server_name {
            self.server_name = Some(server_name.clone());
        }
        if let Some(starttls) = &override_cfg.starttls {
            self.starttls = Some(starttls.clone());
        }
        if let Some(insecure_skip_verify) = override_cfg.insecure_skip_verify {
            self.insecure_skip_verify = insecure_skip_verify;
        }
    }
}

impl Default for ResolvedModuleConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            trustedanchors: FileContent::Path {
                path: PathBuf::new(),
            },
            certs: None,
            key: None,
            server_name: None,
            starttls: None,
            insecure_skip_verify: false,
        }
    }
}

pub fn resolve_module_config(
    modules: &HashMap<String, ModuleConfig>,
) -> AnyResult<HashMap<String, ResolvedModuleConfig>> {
    let mut module_store = HashMap::new();

    let mut index_mapping = HashMap::new();
    let mut graph = Graph::new();

    for name in modules.keys() {
        let node_index = graph.add_node(name.clone());
        index_mapping.insert(name.clone(), node_index);
    }

    // Build the dependencies graph
    let mut workspace = DfsSpace::new(&graph);
    for (name, module) in modules.iter() {
        let node_index = index_mapping.get(name).unwrap();
        for extends in module.extends.iter() {
            let parent_index = index_mapping.get(extends).unwrap();
            graph.add_edge(*node_index, *parent_index, ());
            // Ensure the graph is acyclic
            if has_path_connecting(&graph, *parent_index, *node_index, Some(&mut workspace)) {
                return Err(anyhow::anyhow!("Cyclic dependency detected"));
            }
        }
    }

    // Reverse the direction of the graph to do bottom-up resolution
    let reversed_graph = Reversed(&graph);
    // Resolve the configurations with topological sort
    let mut topo = Topo::new(&reversed_graph);
    while let Some(node_index) = topo.next(&reversed_graph) {
        let name = graph[node_index].clone();
        let config = modules.get(&name).unwrap();

        // Merge the configurations
        let mut final_configs = ResolvedModuleConfig::default();
        for parent in config.extends.iter() {
            let parent_config = modules.get(parent).unwrap();
            final_configs.override_with(parent_config);
        }
        final_configs.override_with(config);
        module_store.insert(name, final_configs);
    }

    Ok(module_store)
}
