
## RBAC策略层面
1.   在命名空间级别分配权限，授予用户在特定命名空间中的权限时使用`RoleBinding`而不是`ClusterRoleBinding`
2.   避免通过通配符设置权限，尤其是对所有资源的权限，因此通过通配符来授予访问权限不仅会授予集群中当前的所有对象类型， 还包含所有未来被创建的所有对象类型
3.   不应使用 `cluster-admin` 角色，除非特别需要。为低特权帐户提供 [伪装权限](https://kubernetes.io/zh-cn/docs/reference/access-authn-authz/authentication/#user-impersonation) 可以避免意外修改集群资源
4.   非特殊情况不能将用户添加到 `system:masters` 组，`system:masters` 组任何属于此组成员的用户都会绕过所有 RBAC 权限检查，无法通过RABC策略变更这个组的权限
5.   非特殊情况不要为`system:anonymous` 、`system:unauthenticated` 组绑定角色
6.   谨慎为主体绑定对`Secrets`资源具有`get`、`list`、`watch`权限的角色
7.   谨慎为主体绑定对`Pods`资源具有`create`权限的角色
8.   谨慎为主体绑定对`PersistentVolume`资源具有`create`权限的角色
9.   谨慎为主体绑定对`node/proxy`子资源具有`get`权限的角色[Privilege Escalation from Node/Proxy Rights in Kubernetes RBAC](https://blog.aquasec.com/privilege-escalation-kubernetes-rbac) 
10.  谨慎为主体绑定对`clusterroles`及`roles`资源具有`bind`权限. 并且对`clusterrolebindings`及`rolebindings`资源具有`create`和`get`权限的角色
11.  谨慎为主体绑定对`clusterroles`及`roles`资源具有`escalate`、`get`和`patch`权限的角色
12.  谨慎为主体绑定对`users`、`groups`或`serviceaccounts`资源具有`impersonate`权限的角色
13.  谨慎为主体绑定对`certificatesigningrequests/approval`有`update`权限、对`certificatesigningrequests`有`get`、`create`权限并且对`signers`有`approve`权限的角色
14.  谨慎为主体绑定对`serviceaccounts/token`资源具有`create`权限的角色，Kubernetes 1.24版本删除了创建`serviceaccount`时自动创建`secret`的功能，通过TokenRequest API可以直接创建`serviceaccount`的`secret`，并在response中返回`secret`值
15.   创建角色时尽可能使用`resourceNames` 字段限制角色只能访问资源的特定命名实例，不设置`resourceNames`字段，即位允许访问对应`resources`所有实例

## 企业内RBAC权限操作层面
1.   内部应提供平台间接变更RBAC策略（`role`、`clusterrole`、`rolebinding`、`clusterrolebinding`的增删改查），以接入人工审批流程和变更日志审计
2.   对于需要挂载`serviceaccount`的pod需要针对pod单独创建`serviceaccount`而不是使用`namespace`下`default serviceaccount`，并在定义pod时指定`spec.serviceAccountName`，然后进行授权，使用`default serviceaccount`授权会使所有具有`default serviceaccount`的pod具有相应权限，扩大攻击面
3.   设置`automountServiceAccountToken为false`禁止seriveaccount token的默认挂载
5.   在集群使用者或运维人员离职或岗位变动时，如果使用的是客户端证书访问集群apiserver，应在集群中删除对应账户绑定的`rolebinding`，如果使用的是`serviceaccount`，可以直接删除对应的`serviceaccount`
