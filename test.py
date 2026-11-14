#import json
#from urllib.request import urlopen
#from urllib.error import HTTPError
from graph import load_graph,find_all_paths,paths_to_graph,path_with_vuln,path_starts_public,path_ends_sink,build_graph
from fastapi.testclient import TestClient
from main import app


#API response
client=TestClient(app)
response=client.get("/routes")
data=response.json()
#with urlopen("http://127.0.0.1:8765/routes") as response:
#    data=json.load(response)

paths=data["paths"]
edges=data["edges"]

#Load graph
graph,node_info=load_graph()

#Test 1: path contains only valid edges
for path in paths:
    assert len(path)>=2,f"Path is too short:{path}"
    for i in range(len(path)-1):
        start=path[i]
        end=path[i+1]
        assert start in graph, f"Unknown node:{start}"
        assert end in graph[start], f"Invalid edge:{start}->{end}"
print("Test 1 passed: All paths contain valid edges")

#Test 2: only simple paths (no repeated nodes)
for path in paths:
    visited=set()
    for node in path:
        assert node not in visited, f"Repeated node:{node} in path{path}"
        visited.add(node)
print("Test 2 passed: No repeated nodes")

#Test 3: no duplicate paths
unique_paths={tuple(path) for path in paths}
assert len(paths)==len(unique_paths),"we have some duplicate paths"
print("Test 3 passed: No duplicate paths")

#Test 4: check DFS results
small_graph = {
    "A": ["B", "C"],
    "B": ["C", "D"],
    "C": ["D"],
    "D": []
}
expected_paths = [
    ["A", "B"],
    ["A", "B", "C"],
    ["A", "B", "C", "D"],
    ["A", "B", "D"],
    ["A", "C"],
    ["A", "C", "D"],
    ["B", "C"],
    ["B", "C", "D"],
    ["B", "D"],
    ["C", "D"]
]
actual_paths=find_all_paths(small_graph)
assert {tuple(path) for path in actual_paths}=={
    tuple(path) for path in expected_paths},"DFS is not good"
assert len(actual_paths)==len(expected_paths),"DFS output has missing/duplicate paths"
print("Test 4 passed: DFS found all expected paths")

#Test 5: DFS handle graph with cycles
cycle_graph = {
    "A": ["B"],
    "B": ["C", "D"],
    "C": ["A"],
    "D": []
}
expected_cycle_paths = [
    ["A", "B"],
    ["A", "B", "C"],
    ["A", "B", "D"],
    ["B", "C"],
    ["B", "C", "A"],
    ["B", "D"],
    ["C", "A"],
    ["C", "A", "B"],
    ["C", "A", "B", "D"]
]
actual_cycle_paths=find_all_paths(cycle_graph)
assert {tuple(p) for p in actual_cycle_paths}=={tuple(p) for p in expected_cycle_paths}, "DFS failed on graph with cycles"
assert len(actual_cycle_paths)==len(expected_cycle_paths), "DFS returned duplicate or missing paths"
print("Test 5 passed: DFS handle with cycles")

#Test 6: validate filters
filter_names=["public","sink","vulnerable"]
for filter_name in filter_names:
    url = f"http://127.0.0.1:8765/routes?filters={filter_name}"
    #with urlopen(url) as response:
    #    data=json.load(response)
    response=client.get(url)
    data=response.json()
    filtered_paths=data["paths"]
    assert len(filtered_paths)>0, f"No paths found for {filter_name}"

    for path in filtered_paths:
        if filter_name=="public":
           first_node=path[0]
           assert node_info[first_node].get("publicExposed",False),f"Invalid public path:{path}"
        elif filter_name=="sink":
            last_node=path[-1]
            assert node_info[last_node].get("kind") in ["rds","sql"],f"Invalid sink path:{path}"
        elif filter_name=="vulnerable":
            has_vuln=False
            for node in path:
                if node_info[node].get("vulnerabilities"):
                    has_vuln=True
                    break
            assert has_vuln, f"Invalid vuln path: {path}"
    print(f"Test 6 passed: {filter_name} filter works")

#Test 7: filters return all matching paths
filter_names = ["public", "sink", "vulnerable"]
for filter_name in filter_names:
    expected_paths=[]
    for path in paths:
        if filter_name=="public":
            if node_info[path[0]].get("publicExposed", False):
                expected_paths.append(path)
        elif filter_name=="sink":
            if node_info[path[-1]].get("kind") in ["rds","sql"]:
                expected_paths.append(path)
        elif filter_name=="vulnerable":
            for node in path:
                if node_info[node].get("vulnerabilities"):
                    expected_paths.append(path)
                    break
    #get filters
    url = f"http://127.0.0.1:8765/routes?filters={filter_name}"
    #with urlopen(url) as response:
    #    data=json.load(response)
    response=client.get(url)
    data=response.json()
    actual_paths=data["paths"]
    expected_set={tuple(path) for path in expected_paths}
    actual_set={tuple(path) for path in actual_paths}
    assert  expected_set==actual_set, f"Missing or extra paths for {filter_name} filter"
    assert len(actual_paths)==len(expected_paths), f"Duplicate paths for {filter_name} filter"
    print(f"Test 7 passed: {filter_name} returns all the paths")

#Test 8: combined filters
combinations = [
    ["public", "sink"],
    ["public", "vulnerable"],
    ["sink", "vulnerable"],
    ["public", "sink", "vulnerable"]
]
for comb in combinations:
    url = "http://127.0.0.1:8765/routes"
    for filter_name in comb:
        if "?" not in url:
            url += f"?filters={filter_name}"
        else:
            url += f"&filters={filter_name}"
    #with urlopen(url) as response:
    #    data=json.load(response)
    response=client.get(url)
    data=response.json()
    actual_paths=data["paths"]
    expected_paths=[]
    for path in paths:
        valid=True
        if "public" in comb:
            if not node_info[path[0]].get("publicExposed",False):
                valid=False
        if "sink" in comb:
            if node_info[path[-1]].get("kind") not in ["rds","sql"]:
                valid=False
        if "vulnerable" in comb:
            has_vuln=False
            for node in path:
                if node_info[node].get("vulnerabilities"):
                    has_vuln=True
                    break
            if not has_vuln:
                valid=False
        if valid:
            expected_paths.append(path)
    expected_set={tuple(path) for path in expected_paths}
    actual_set={tuple(path) for path in actual_paths}
    assert expected_set == actual_set,f"Wrong paths for {comb}"
    assert len(actual_paths) == len(expected_paths),f"Duplicate paths for {comb}"
    print (f"Test 8 passed:{comb}")

#Test 9: Empty result
url = "http://127.0.0.1:8765/routes?filters=public&filters=sink"
#with urlopen(url) as response:
#    data=json.load(response)
#    status_code=response.status
response=client.get(url)
data=response.json()
status_code=response.status_code
assert status_code==200, "Wrong code"
assert data["nodes"]==[], "Nodes should be empty"
assert data["edges"]==[], "Edges should be empty"
assert data["paths"]==[], "Paths should be empty"
print("Test 9 passed: Empty result is handled")

#Test 10: Invalid filter name
invalid_filters = [
    ["banana"],
    ["SiNk"],
    ["PUBLIC"],
    [""],
    ["sink", "banana"]
]
for filters in invalid_filters:
    params=[]
    for filter_name in filters:
        params.append(("filters",filter_name))
    response=client.get("/routes",params=params)
    assert response.status_code==400, f"Expected 400 instead of {response.status_code}"
    data=response.json()
    assert "Unknown filter:" in data["detail"], f"Unexpected error message: {data["detail"]}"
    # try:
    #     with urlopen(url) as response:
    #         assert False, f"Expected HTTP 400 for {url}"
    # except HTTPError as error:
    #     assert error.code==400, f"Expected 400 instead of {error.code}"
    #     data=json.load(error)
    #     assert "Unknown filter:" in data["detail"], f"Unexpected error message: {data['detail']}"
print("Test 10 passed: All invalid filters were rejected")

#Test 11: validate response structure
#with urlopen("http://127.0.0.1:8765/routes") as response:
#    data = json.load(response)
url="http://127.0.0.1:8765/routes"
response=client.get(url)
data=response.json()

paths = data["paths"]
nodes = data["nodes"]
edges = data["edges"]
expected_nodes = set()
expected_edges = set()

for path in paths:
    for node in path:
        expected_nodes.add(node)
    for i in range(len(path) - 1):
        expected_edges.add((path[i], path[i + 1]))
actual_nodes = set()
actual_edges = set()
for node in nodes:
    actual_nodes.add(node["name"])
for edge in edges:
    actual_edges.add((edge["from"], edge["to"]))
assert expected_nodes == actual_nodes, "Nodes do not match the paths"
assert expected_edges == actual_edges, "Edges do not match the paths"
assert len(nodes) == len(actual_nodes), "Duplicate nodes found"
assert len(edges) == len(actual_edges), "Duplicate edges found"
print("Test 11 passed: Graph structure is correct")

#Test 12: Empty graph and empty paths
empty_graph = {}
assert find_all_paths(empty_graph) == [], \
    "Empty graph should return no paths"
assert path_starts_public([], {}) == False, \
    "Empty path should not pass public filter"
assert path_ends_sink([], {}) == False, \
    "Empty path should not pass sink filter"
assert path_with_vuln([], {}) == False, \
    "Empty path should not pass vulnerable filter"
assert paths_to_graph([], {}) == {
    "nodes": [],
    "edges": [],
    "paths": []
}, "Empty paths should return an empty graph"
print("Test 12 passed: Empty graph and paths handled correctly")

#Test 13: Invalid and duplicate edges
test_nodes = [
    {"name": "A"},
    {"name": "B"}
]
test_edges = [
    {"from": "A", "to": "B"},
    {"from": "A", "to": "B"},  # Duplicate edge
    {"from": "A", "to": "C"},  # Unknown target
    {"from": "X", "to": "B"}   # Unknown source
]
test_graph, test_info = build_graph(test_nodes, test_edges)
assert test_graph == {
    "A": ["B"],
    "B": []
}, "Invalid or duplicate edges were not handled correctly"
print("Test 13 passed: Invalid and duplicate edges handled correctly")

#Test 14: edges to few targets
test_nodes = [
    {"name": "A"},
    {"name": "B"},
    {"name": "C"}
]
test_edges = [
    {"from": "A", "to": ["B", "C"]},
    {"from": "B", "to": "C"}
]
test_graph, test_info = build_graph(test_nodes, test_edges)
assert test_graph == {
    "A": ["B", "C"],
    "B": ["C"],
    "C": []
}, "Multiple edge targets were not handled correctly"
print("Test 14 passed: Multiple edge targets handled correctly")