from mcp.server.fastmcp import FastMCP
from elasticsearch import Elasticsearch
 
mcp = FastMCP(name="Elastic", host="0.0.0.0", port=8050, stateless_http=True)
es = Elasticsearch(
    hosts=["https://192.168.35.46:9200"],
    api_key="NWZjSDY1Y0JHbGJPR0RSSGVpc3U6RF9aWUla",
    verify_certs=False,
)
 
 
@mcp.tool()
def search_logs(query: str) -> str:
    try:
        result = es.search(
            index="*",
            size=5,
            sort=[{"@timestamp": "desc"}],
            query={
                "multi_match": {
                    "query": query,
                    "fields": ["message", "host.hostname", "agent.name"],
                    "type": "best_fields",
                }
            },
        )
        hits = result.get("hits", {}).get("hits", [])
        if not hits:
            return f"No results found for '{query}'."
        return "\n\n".join(
            [
                f"{i + 1}. [{hit['_source'].get('@timestamp')}] {hit['_source'].get('message', '[No message]')}"
                for i, hit in enumerate(hits)
            ]
        )
    except Exception as e:
        return f"[ELASTIC ERROR] {str(e)}"
 
 
@mcp.tool()
def top_hostnames(n: int = 5) -> str:
    try:
        result = es.search(
            index="*",
            size=0,
            aggs={"top_hosts": {"terms": {"field": "host.hostname", "size": n}}},
        )
        hits = result["aggregations"]["top_hosts"]["buckets"]
        if not hits:
            return f"Nothing results found for '{result['aggs']}'."
        return "\n".join(
            [f"{i + 1}. {b['key']} ({b['doc_count']} logs)" for i, b in enumerate(hits)]
        )
    except Exception as e:
        return f"[ELASTIC ERROR] {str(e)}"
 
 
if __name__ == "__main__":
    transport = "streamable-http"
    mcp.run(transport=transport)
