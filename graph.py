import json
from pathlib import Path

def build_graph(nodes,edges):
    graph={}
    node_info={}
    for node in nodes:  #for each node we will add node name with an empty list of potential edges
        name=node["name"]
        graph[name]=[]
        node_info[name]=node
    for edge in edges: #extract from each edge the source and the targets (few edges from the same source)
        source=edge["from"]
        targets=edge["to"]
        if isinstance(targets,str): #deal with targets which given as a string and not list
            targets=[targets]
        #deal with edegs onto none existing nodes - as an assumption we will ignore them
        if source not in graph:
            continue
        for target in targets:
            if target in graph and target not in graph[source]:
                graph[source].append(target)
    return graph,node_info

def load_graph():
    file_path=Path(__file__).parent/"data.json"
    with open(file_path,"r",encoding="utf-8") as file:
        data = json.load(file)
    graph, node_info = build_graph(data["nodes"],data["edges"])
    return graph,node_info


#Routes that start in a public service ("publicExposed": true )
def is_public(node_name,node_info):
    return node_info[node_name].get("publicExposed",False)
def path_starts_public(path,node_info):
    if not path:
        return False
    return is_public(path[0],node_info)

#Routes that end in Sink (rds/sql)
def is_sink(node_name,node_info):
    if node_info[node_name].get("kind") in {'rds','sql'}:
        return True
    return False
def path_ends_sink(path,node_info):
    if not path:
        return False
    return is_sink(path[-1],node_info)

#Routes that have a vulnerability in one of the nodes
def is_vulnerability(node_name,node_info):
    vuln=node_info[node_name].get("vulnerabilities",[])
    if len(vuln)>0:
        return True
    return False
def path_with_vuln(path,node_info):
    for node in path:
        if is_vulnerability(node,node_info):
            return True
    return False

#define filters
Filters = {"public":path_starts_public,"sink":path_ends_sink,"vulnerable":path_with_vuln}

#Find paths from A to B using DFS
# def find_paths(graph,start,end):
#     if start not in graph or end not in graph:
#         return []
#
#     results=[]
#     path=[]
#     def dfs(curr):
#         path.append(curr)
#         if curr == end:
#             results.append(path.copy())
#         else:
#             for neighbor in graph[curr]:
#                 if neighbor not in path: #prevent circles
#                     dfs(neighbor)
#         path.pop()
#     dfs(start)
#     return results

#Find all paths - we will handle the case when "public" filter is on differently in order to improve the efficiency
def find_all_paths(graph, node_info=None, public_only=False):
    results=[]
    path=[]
    visited=set()
    def dfs(curr):
        path.append(curr)
        visited.add(curr)
        if len(path)>1: #we define path as a route with at least 2 nodes
            results.append(path.copy())

        for neighbor in graph[curr]: #prevent circles
            if neighbor not in visited: #we use set to make this check in O(1)
                dfs(neighbor)
        path.pop()
        visited.remove(curr)
    for node in graph:
        if public_only: #if public filter is on
            if not is_public(node,node_info): #will run DFS only from public node
                continue
        dfs(node)
    return results

#check if path passes all the filters
def pass_filters(path,node_info,filters_list):
    for filter_name in filters_list:
        filter_func=Filters[filter_name]
        if not filter_func(path,node_info):
            return False
    return True

#check all the relevant paths by the required filters
def final_routes(graph,node_info,filters_list):
    relevant_paths=[]
    public_only = False
    if "public" in filters_list:
        public_only=True
    results=find_all_paths(graph,node_info,public_only)
    for path in results:
        if pass_filters(path,node_info,filters_list):
            relevant_paths.append(path)
    return relevant_paths

#convert the relevant paths to a graph structure
def paths_to_graph(paths,node_info):
    unique_nodes=set()
    unique_edges=set()
    nodes=[]
    edges=[]

    for path in paths:
        for node in path:
            unique_nodes.add(node)
        for i in range(len(path)-1):
            start=path[i]
            end=path[i+1]
            unique_edges.add((start,end))
    for n in sorted(unique_nodes):
        nodes.append(node_info[n])
    for start,end in sorted(unique_edges):
        edge={"from":start, "to":end}
        edges.append(edge)
    return {
        "nodes":nodes,
        "edges":edges,
        "paths":paths
    }

