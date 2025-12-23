import numpy as np
import networkx as nx

# === 검증 함수 (main.py에서 그대로 복붙) ===
def is_physical(B, delta):
    flow_hat, _, _, _ = np.linalg.lstsq(B, delta, rcond=None)
    return np.allclose(B @ flow_hat, delta)

def is_physical_local(B_sub, delta_sub):
    flow_hat, _, _, _ = np.linalg.lstsq(B_sub, delta_sub, rcond=None)
    return np.allclose(B_sub @ flow_hat, delta_sub)

# === 스케일 테스트 ===
for n in [5, 10, 50, 100, 200, 400, 800, 1000, 5000, 10000, 40000, 80000, 100000]:
    G = nx.path_graph(n)
    B = nx.incidence_matrix(G, oriented=True).toarray()

    # 중앙 엣지 하나 선택
    mid_edge = n // 2 - 1

    # 정상 거래
    flow = np.zeros(B.shape[1])
    flow[mid_edge] = 1.0
    delta_valid = B @ flow

    # 로컬 서브그래프 (해당 엣지의 두 노드)
    nodes = [mid_edge, mid_edge + 1]
    B_sub = B[nodes, :][:, [mid_edge]]
    delta_sub = delta_valid[nodes]

    print(
        f"nodes={n}",
        f"global_dim={B.shape}",
        f"local_dim={B_sub.shape}",
        f"local_ok={is_physical_local(B_sub, delta_sub)}"
    )
