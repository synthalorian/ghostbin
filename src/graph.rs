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

/// Simple force-directed graph layout algorithm
/// Uses repulsion between all nodes and attraction along edges
pub fn layout_graph(graph: &DiGraph<String, String>) -> GraphData {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    if graph.node_count() == 0 {
        return GraphData { nodes, edges };
    }

    // Initialize node positions in a circle
    let node_count = graph.node_count();
    let mut positions: Vec<(f64, f64)> = Vec::with_capacity(node_count);
    let radius = 200.0;

    for i in 0..node_count {
        let angle = 2.0 * std::f64::consts::PI * (i as f64) / (node_count as f64);
        positions.push((
            radius * angle.cos(),
            radius * angle.sin(),
        ));
    }

    // Force-directed iteration
    let iterations = 100;
    let repulsion_constant = 5000.0;
    let attraction_constant = 0.01;
    let damping = 0.9;
    let mut velocities: Vec<(f64, f64)> = vec![(0.0, 0.0); node_count];

    for _ in 0..iterations {
        let mut forces: Vec<(f64, f64)> = vec![(0.0, 0.0); node_count];

        // Repulsion: all nodes repel each other
        for i in 0..node_count {
            for j in (i + 1)..node_count {
                let dx = positions[i].0 - positions[j].0;
                let dy = positions[i].1 - positions[j].1;
                let dist_sq = dx * dx + dy * dy;
                let dist = dist_sq.sqrt().max(1.0);

                let force = repulsion_constant / dist_sq;
                let fx = force * dx / dist;
                let fy = force * dy / dist;

                forces[i].0 += fx;
                forces[i].1 += fy;
                forces[j].0 -= fx;
                forces[j].1 -= fy;
            }
        }

        // Attraction: connected nodes attract each other
        for edge in graph.edge_indices() {
            let (from, to) = graph.edge_endpoints(edge).unwrap();
            let i = from.index();
            let j = to.index();

            let dx = positions[j].0 - positions[i].0;
            let dy = positions[j].1 - positions[i].1;
            let dist = (dx * dx + dy * dy).sqrt().max(1.0);

            let force = attraction_constant * dist;
            let fx = force * dx / dist;
            let fy = force * dy / dist;

            forces[i].0 += fx;
            forces[i].1 += fy;
            forces[j].0 -= fx;
            forces[j].1 -= fy;
        }

        // Update velocities and positions
        for i in 0..node_count {
            velocities[i].0 = (velocities[i].0 + forces[i].0) * damping;
            velocities[i].1 = (velocities[i].1 + forces[i].1) * damping;

            positions[i].0 += velocities[i].0;
            positions[i].1 += velocities[i].1;
        }
    }

    // Build output
    for node_idx in graph.node_indices() {
        let id = format!("node_{}", node_idx.index());
        let pos = positions[node_idx.index()];
        nodes.push(GraphNode {
            id: id.clone(),
            address: graph[node_idx].clone(),
            label: graph[node_idx].clone(),
            x: pos.0,
            y: pos.1,
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

#[allow(dead_code)]
pub fn to_dot(graph: &DiGraph<String, String>) -> String {
    format!("{:?}", Dot::with_config(graph, &[Config::EdgeNoLabel]))
}

/// Interactive graph view state for pan, zoom, and node selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractiveGraphState {
    pub viewport_x: f64,
    pub viewport_y: f64,
    pub zoom: f64,
    pub selected_nodes: Vec<String>,
    pub highlighted_edges: Vec<(String, String)>,
}

impl Default for InteractiveGraphState {
    fn default() -> Self {
        InteractiveGraphState {
            viewport_x: 0.0,
            viewport_y: 0.0,
            zoom: 1.0,
            selected_nodes: Vec::new(),
            highlighted_edges: Vec::new(),
        }
    }
}

impl InteractiveGraphState {
    pub fn pan(&mut self, dx: f64, dy: f64) {
        self.viewport_x += dx / self.zoom;
        self.viewport_y += dy / self.zoom;
    }

    pub fn zoom_in(&mut self, factor: f64) {
        self.zoom = (self.zoom * factor).min(10.0);
    }

    pub fn zoom_out(&mut self, factor: f64) {
        self.zoom = (self.zoom / factor).max(0.1);
    }

    pub fn select_node(&mut self, node_id: String) {
        if !self.selected_nodes.contains(&node_id) {
            self.selected_nodes.push(node_id);
        }
    }

    pub fn deselect_node(&mut self, node_id: &str) {
        self.selected_nodes.retain(|n| n != node_id);
    }

    pub fn clear_selection(&mut self) {
        self.selected_nodes.clear();
    }

    pub fn highlight_path(&mut self, from: String, to: String) {
        self.highlighted_edges.push((from, to));
    }

    pub fn clear_highlighted(&mut self) {
        self.highlighted_edges.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layout_empty_graph() {
        let graph: DiGraph<String, String> = DiGraph::new();
        let data = layout_graph(&graph);
        assert!(data.nodes.is_empty());
        assert!(data.edges.is_empty());
    }

    #[test]
    fn test_layout_single_node() {
        let mut graph: DiGraph<String, String> = DiGraph::new();
        graph.add_node("A".to_string());
        let data = layout_graph(&graph);
        assert_eq!(data.nodes.len(), 1);
        assert!(data.edges.is_empty());
    }

    #[test]
    fn test_layout_multiple_nodes() {
        let mut graph: DiGraph<String, String> = DiGraph::new();
        let a = graph.add_node("A".to_string());
        let b = graph.add_node("B".to_string());
        let c = graph.add_node("C".to_string());
        graph.add_edge(a, b, "edge1".to_string());
        graph.add_edge(b, c, "edge2".to_string());

        let data = layout_graph(&graph);
        assert_eq!(data.nodes.len(), 3);
        assert_eq!(data.edges.len(), 2);

        // Verify nodes have different positions
        assert!(data.nodes[0].x != data.nodes[1].x || data.nodes[0].y != data.nodes[1].y);
    }

    #[test]
    fn test_node_ids_are_unique() {
        let mut graph: DiGraph<String, String> = DiGraph::new();
        graph.add_node("A".to_string());
        graph.add_node("B".to_string());

        let data = layout_graph(&graph);
        assert_ne!(data.nodes[0].id, data.nodes[1].id);
    }
}
