import json

class GraphVizGenerator:
    def __init__(self):
        pass

    def generate_d3_json(self, data):
        nodes = []
        edges = []
        added_nodes = set()
        def add_node(id_val, label, group=1):
            if id_val not in added_nodes:
                nodes.append({"id": id_val, "label": label, "group": group})
                added_nodes.add(id_val)
        add_node("root", data.get("domain", "Unknown"), 1)
        for sub in data.get("subdomains", []):
            sub_name = sub if isinstance(sub, str) else sub.get("hostname", "")
            if sub_name:
                add_node(sub_name, sub_name, 2)
                edges.append({"source": "root", "target": sub_name})
        for sub in data.get("subdomains", []):
            sub_name = sub if isinstance(sub, str) else sub.get("hostname", "")
            if not sub_name:
                continue
            ip = ""
            if isinstance(sub, dict):
                ip = sub.get("ip", "")
            if ip:
                add_node(ip, ip, 3)
                edges.append({"source": sub_name, "target": ip})
            dns_data = {}
            if isinstance(sub, dict):
                dns_data = sub.get("dns", {})
            if dns_data:
                for rtype in ["A", "AAAA", "MX", "NS"]:
                    records = dns_data.get(rtype, [])
                    for rec in records:
                        rec_str = str(rec)
                        if rec_str and rtype != ip:
                            node_id = f"{rtype}: {rec_str}"
                            add_node(node_id, rec_str, 4)
                            edges.append({"source": sub_name, "target": node_id, "label": rtype})
        graph = {"nodes": nodes, "edges": edges}
        return graph

    def generate_html(self, graph_data, title="XREFS0 - Domain Graph"):
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  body {{ margin: 0; background: #0a0a1a; color: #fff; font-family: 'Segoe UI', sans-serif; overflow: hidden; }}
  #graph {{ width: 100vw; height: 100vh; }}
  .info {{ position: absolute; bottom: 20px; left: 20px; background: rgba(0,0,0,0.7); padding: 10px 20px; border-radius: 8px; font-size: 12px; color: #aaa; }}
</style>
</head>
<body>
<div id="graph"></div>
<div class="info">XREFS0 - Interactive Domain Graph | Drag to navigate, scroll to zoom</div>
<script src="https://d3js.org/d3.v7.min.js"></script>
<script>
const graphData = {json.dumps(graph_data)};
const width = window.innerWidth;
const height = window.innerHeight;
const svg = d3.select("#graph").append("svg").attr("width", width).attr("height", height);
const g = svg.append("g");
const zoom = d3.zoom().scaleExtent([0.1, 8]).on("zoom", (e) => g.attr("transform", e.transform));
svg.call(zoom);
const color = d3.scaleOrdinal(d3.schemeCategory10);
const simulation = d3.forceSimulation(graphData.nodes)
  .force("link", d3.forceLink(graphData.edges).id(d => d.id).distance(100))
  .force("charge", d3.forceManyBody().strength(-300))
  .force("center", d3.forceCenter(width / 2, height / 2));
const link = g.append("g").selectAll("line").data(graphData.edges).join("line")
  .attr("stroke", "#666").attr("stroke-width", 1.5).attr("stroke-opacity", 0.6);
const node = g.append("g").selectAll("circle").data(graphData.nodes).join("circle")
  .attr("r", d => d.group === 1 ? 12 : d.group === 2 ? 8 : 5)
  .attr("fill", d => color(d.group))
  .attr("stroke", "#fff").attr("stroke-width", 1.5)
  .call(drag(simulation));
node.append("title").text(d => d.label);
const label = g.append("g").selectAll("text").data(graphData.nodes).join("text")
  .text(d => d.label.length > 20 ? d.label.slice(0, 17) + "..." : d.label)
  .attr("font-size", d => d.group === 1 ? 14 : 10)
  .attr("dx", 12).attr("dy", 4).attr("fill", "#fff").style("pointer-events", "none");
simulation.on("tick", () => {{
  link.attr("x1", d => d.source.x).attr("y1", d => d.source.y)
      .attr("x2", d => d.target.x).attr("y2", d => d.target.y);
  node.attr("cx", d => d.x).attr("cy", d => d.y);
  label.attr("x", d => d.x).attr("y", d => d.y);
}});
function drag(sim) {{
  function dragstarted(e, d) {{ if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }}
  function dragged(e, d) {{ d.fx = e.x; d.fy = e.y; }}
  function dragended(e, d) {{ if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }}
  return d3.drag().on("start", dragstarted).on("drag", dragged).on("end", dragended);
}}
</script>
</body>
</html>"""
        return html
