use super::{FileContent, ModuleConfig, Starttls, DEFAULT_TIMEOUT};
use anyhow::Result as AnyResult;
use petgraph::{
    algo::{has_path_connecting, DfsSpace},
    graph::{self, Graph}, visit::{Reversed, Topo},
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
    pub fn merge(self, override_cfg: ModuleConfig) -> Self {
        Self {
            timeout: override_cfg.timeout.unwrap_or(self.timeout),
            trustedanchors: override_cfg.trustedanchors.unwrap_or(self.trustedanchors),
            certs: override_cfg.certs.or(self.certs),
            key: override_cfg.key.or(self.key),
            server_name: override_cfg.server_name.or(self.server_name),
            starttls: override_cfg.starttls.or(self.starttls),
            insecure_skip_verify: override_cfg
                .insecure_skip_verify
                .unwrap_or(self.insecure_skip_verify),
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
    // Hardcoded default configurations
    module_store.insert(String::from("_default"), ResolvedModuleConfig::default());

    let mut index_mapping = HashMap::new();
    let mut graph = Graph::new();

    let default_index = graph.add_node(String::from("_default"));
    index_mapping.insert(String::from("_default"), default_index);

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

    // Resolve the configurations with topological sort
    // Reverse the direction of the graph to do bottom-up resolution
    let reversed_graph = Reversed(&graph);
    let mut topo = Topo::new(&reversed_graph);
    while let Some(node_index) = topo.next(&reversed_graph) {
        let name = graph[node_index].clone();
        let config = modules.get(&name).unwrap();

        // TODO: Merge the configurations
        todo!();
    }

    Ok(module_store)
}
