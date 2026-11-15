from fastapi import FastAPI, Query, HTTPException
from graph import load_graph,final_routes,paths_to_graph, Filters
app = FastAPI()

graph,node_info = load_graph()
@app.get("/routes")
def get_routes(filters: list[str]=Query(default=[])):
    for filter_name in filters:
        if filter_name not in Filters:
            raise HTTPException(status_code=400,detail=f"Unknown filter: {filter_name}")

    paths=final_routes(graph,node_info,filters)
    return paths_to_graph(paths,node_info)
