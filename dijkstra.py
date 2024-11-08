import json
from netfuncs import get_network, ipv4_to_value, get_subnet_mask_value, value_to_ipv4, ips_same_subnet

def get_network_ip(ip, mask): # get network ip from ip and mask when mask is known
    ip = ipv4_to_value(ip)
    mask = get_subnet_mask_value(mask)
    return value_to_ipv4(get_network(ip, mask))
    
def find_network_ip(ip, graph):
    for vertex in graph: # for each vertex in the graph
        subnet_mask_value = get_subnet_mask_value(graph[vertex]['netmask']) # get mask
        network_value = get_network(ipv4_to_value(vertex), subnet_mask_value) # get network
        vertex_ip = value_to_ipv4(network_value) # get network back to ipv4
        if ips_same_subnet(ip, vertex_ip, graph[vertex]['netmask']): #if same network
            return vertex # return the network ip ( the one from json)
    raise KeyError(f"IP {ip} not found in any network in the graph")

def dijkstra(graph, source, destination):
    dist = {}
    prev = {}
    Q = set()
    
    # Find the network IPs for source and destination
    source_network_ip = find_network_ip(source, graph)
    destination_network_ip = find_network_ip(destination, graph)
    
    if source_network_ip == destination_network_ip: # if already on same network
        return []
    
    for vertex in graph:
        dist[vertex] = float('inf')
        prev[vertex] = None
        Q.add(vertex)


    dist[source_network_ip] = 0
    
    
    while Q:
        u = min(Q, key=lambda vertex: dist[vertex])
        
        if find_network_ip(u, graph) == destination_network_ip:
            path = []
            while prev[u]:
                path.insert(0, u)
                u = prev[u]
            path.insert(0, source)
            return path
        for v in graph[u]['connections']:  # for each neighbor v of u still in Q
             if v in Q:
                alt = dist[u] + graph[u]['connections'][v]['ad']
                if alt < dist[v]:
                    dist[v] = alt
                    prev[v] = u
        Q.remove(u)

    raise KeyError(f"No path found from {source} to {destination}")


def main():
    input_file = open('example1.json', 'r')
    json_data = input_file.read()
    input_file.close()
    json_data = json.loads(json_data)
    graph = json_data['routers']
    src_dest = json_data['src-dest']
    for src, dest in src_dest:
        path = dijkstra(graph, src, dest)
        print('Shortest path from {} to {}: {}'.format(src, dest, path))



if __name__ == '__main__':
    main()
