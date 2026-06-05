use petgraph::graph::DiGraph;
use petgraph::dot::{Dot, Config};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub address: String,
    pub label: String,
    pub x: f64,
    pub y: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub edge_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphData {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

pub fn layout_graph(graph: &DiGraph<String, String>) -> GraphData {
    // TODO: Implement force-directed layout or use graphviz
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    for node_idx in graph.node_indices() {
        let id = format!("node_{}", node_idx.index());
        nodes.push(GraphNode {
            id: id.clone(),
            address: graph[node_idx].clone(),
            label: graph[node_idx].clone(),
            x: (node_idx.index() as f64) * 100.0,
            y: (node_idx.index() as f64) * 50.0,
        });
    }

    for edge in graph.edge_indices() {
        let (from, to) = graph.edge_endpoints(edge).unwrap();
        edges.push(GraphEdge {
            from: format!("node_{}", from.index()),
            to: format!("node_{}", to.index()),
            edge_type: graph[edge].clone(),
        });
    }

    GraphData { nodes, edges }
}

pub fn to_dot(graph: &DiGraph<String, String>) -> String {
    format!("{:?}", Dot::with_config(graph, &[Config::EdgeNoLabel]))
}
