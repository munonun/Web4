import numpy as np
import networkx as nx

# 1. 그래프 만들기
G = nx.path_graph(5)

# incidence matrix B (node x edge)
B = nx.incidence_matrix(G, oriented=True).toarray()

# 2. "정상 거래" 정의
#    edge를 따라 흐름이 생김

flow = np.zeros(B.shape[1])
flow[1] = 1.0              # edge 1 -> 2 로 1 이동

delta_valid = B @ flow     # 노드 변화량

# 3. "위조 주입" 정의
#    노드 하나에 +1 주입
delta_forged = np.zeros(5)
delta_forged[1] = 1.0

# 4. 판별 함수
#    이 변화가 "엣지 흐름"으로 설명 가능한가?
def is_physical(delta):
    flow_hat, _, _, _ = np.linalg.lstsq(B, delta, rcond=None)
    reconstructed = B @ flow_hat
    return np.allclose(reconstructed, delta)

# 5. 결과 출력
print("Valid transfer:", is_physical(delta_valid))
print("Forged injection:", is_physical(delta_forged))
