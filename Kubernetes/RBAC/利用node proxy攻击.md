
测试kubernetes版本：v1.26.0

绑定能够get node/proxy的角色可以直接连接kubelet api端口控制node节点所有容器

参考：[Privilege Escalation from Node/Proxy Rights in Kubernetes RBAC](https://blog.aquasec.com/privilege-escalation-kubernetes-rbac)

## 验证步骤

当前主体具备以下角色

```shell
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: nodeproxy
rules:
- apiGroups: [""]
  resources: ["nodes/proxy"]
  verbs: ["get"]
EOF
```

创建ServiceAccount

```shell
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: nodeproxy
EOF
```

创建ClusterRoleBinding

```shell
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: nodeproxybinding
subjects:
- kind: ServiceAccount
  name: nodeproxy
  namespace: default
roleRef:
  kind: ClusterRole
  name: nodeproxy
  apiGroup: rbac.authorization.k8s.io
EOF
```

创建Secret

```shell
cat<<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
type: kubernetes.io/service-account-token
metadata:
  name: nodeproxy
  annotations:
    kubernetes.io/service-account.name: "nodeproxy"
EOF
```

当我们通过任何方式获取到`nodeproxy`的token时使用该token访问kubelet api端口即可获取对应node节点的所有pod权限