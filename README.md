# Train Ticket Graph Query API
## Overview
This project implements a REST API for finding and filtering paths in a graph of Train Ticket microservices.

The API identifies all possible simple paths between services and supports filtering based on public entry points, sink nodes (RDS/SQL), and vulnerabilities along a path.

The results are returned as JSON containing the matching paths, nodes, and edges, making them suitable for client-side graph visualization.

## Implementation Approach
### Graph Representation
The JSON data is loaded into an adjacency list which represent the directed graph, along with a separate dictionary containing each node's metadata.
This allows efficient access to neighboring nodes while finding paths and also to the node properties when applying filters.
### Path Discovery
All possible simple paths are found by using Depth-First Search (DFS) with backtracking.
The search starts from each node and explores all reachable paths containing at least two nodes.
To ensure that the paths are simple and don't have cycles, we use a set to track the nodes already visited in the current path. A set was chosen because it allows efficient membership checks in O(1) average time.

When the public filter is applied, the search starts only from publicly exposed nodes.
This reduces both runtime and memory usage by avoiding the search and storage of paths that would be filtered out later, which can be especially helpful in large graphs.
### Filtering
The API supports three filters: paths that start from a publicly exposed service, paths that end at a sink node (RDS/SQL), and paths containing at least one vulnerable node.
Each filter has its own function that checks whether a path meets the required condition. We use a dictionary to map each filter name to its corresponding function, allowing us to apply the requested filters using the same logic.

Users can apply filters individually, combine multiple filters, or retrieve all paths without any filter.
To make the solution easy to extend, adding a new filter only requires defining a new function and adding it to the dictionary, without changing the existing filtering logic.

## API Usage
### Endpoint
The API provides a single endpoint:
`GET /routes`

The endpoint accepts an optional `filters` query parameter. If no filters are provided, all paths are returned.
### Filters
Multiple filters can be provided by repeating the filters query parameter in the URL.
When multiple filters are provided, a path must satisfy all selected conditions.

#### Examples
Get all paths without filters:
`GET /routes`

Get paths starting from a publicly exposed service:
`GET /routes?filters=public`

Get paths ending at a sink node:
`GET /routes?filters=sink`

Get paths containing at least one vulnerable node:
`GET /routes?filters=vulnerable`

Combine filters:
`GET /routes?filters=public&filters=vulnerable`

### Response Format
The API returns a JSON object with three fields:
- `nodes`: Unique nodes included in the matching paths, along with their original properties.
- `edges`: Unique directed edges that appear in the matching paths.
- `paths`: The matching paths, each represented as an ordered list of node names.

Returning both the graph structure (`nodes` and `edges`) and the individual paths allows a client side application to visualize the graph and identify the matching routes.
#### Example Response (Simplified)
```json
{
  "nodes": [
    {
      "name": "A",
      "kind": "service",
      "publicExposed": true,
      "vulnerabilities": []
    },
    {
      "name": "B",
      "kind": "rds",
      "publicExposed": false,
      "vulnerabilities": []
    }
  ],
  "edges": [
    {"from": "A", "to": "B"}
  ],
  "paths": [
    ["A", "B"]
  ]
}
```
Each node retains all its original properties from the input JSON, even though only a few are shown in this example.

## Assumptions
- **Path definition:** A valid path contains at least two nodes and does not repeat any node (simple path). This prevents cycles and ensures that each path represents a connection between services.
Paths can end at any node, even if that node has outgoing edges, meaning that shorter paths that are part of longer ones are also included.
- **Start and end nodes:** Paths can start and end at any node in the graph, unless restricted by the selected filters.
- **Filter combination:** When multiple filters are selected, a path must satisfy all of them (AND).
- **Invalid and duplicate edges:** Edges referencing nodes that do not exist in the input data are ignored. Duplicate edges are also ignored when building the graph.

## Setup & Testing
### Insrallation
- Requires Python 3.10 or newer.
- Create and activate a virtual environment (Windows Command Prompt):
```bash
python -m venv .venv
.venv\Scripts\activate
```
- Install the project's dependencies using the provided requirements.txt file:
```bash
python -m pip install -r requirements.txt
```
### Running the API
- The API is built with FastAPI, a Python framework for creating web APIs, and uses Uvicorn to run the server.
- Start the server on port 8765 (chosen for local development, any other available port can be used):
```bash
python -m uvicorn main:app --port 8765
```
- Once the server is running, the API is available at http://127.0.0.1:8765/routes.
- FastAPI also provides interactive API documentation at http://127.0.0.1:8765/docs, where you can test the endpoint directly.

### Running Tests
- The project contain a test file. 
- The tests cover path discovery, cycles, filtering, API responses, and edge cases.
Run the tests with:
```bash
python test.py
```
- The tests use FastAPI's TestClient to send requests directly to the application, allowing them to run without starting a separate server.

## Performance & Limitations
Finding all simple paths can be computationally expensive, as the number of possible paths may grow exponentially with the size of the graph.

The "public" filter is applied before starting DFS to reduce the number of paths explored and stored. But, the "sink" and "vulnerable" filters are applied after path discovery, meaning they do not reduce the number of paths generated during the search.

Since the API currently generates and stores all discovered paths before filtering, large graphs may require significant runtime and memory.

