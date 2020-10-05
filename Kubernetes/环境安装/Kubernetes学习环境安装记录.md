# Kubernetes学习环境安装记录

<a name="9WB6I"></a>
#### 1. 检查机器是否开启VMX
```bash
sysctl -a | grep -E --color 'machdep.cpu.features|VMX'
```
<a name="j6lOL"></a>
#### 2. 安装kubectl
```bash
brew install kubectl
```
<a name="3LEQh"></a>
#### 3. 安装minikube
```bash
brew install minikube
```
<a name="6WEDW"></a>
#### 4. 安装 VMware Fusion，使用aliyun镜像启动Kubernetes集群
```bash
minikube start --vm-driver=vmwarefusion --image-repository=registry.cn-hangzhou.aliyuncs.com/google_containers
```
<a name="4dkl8"></a>
#### 5. 创建echoserver测试服务，国内无法连接k8s.gcr.io，使用docker hub的cilium/echoserver镜像代替
```bash
kubectl create deployment hello-minikube --image=k8s.gcr.io/echoserver:1.10
```
<a name="PoA1H"></a>
#### 6. 公开service
```bash
 kubectl expose deployment hello-minikube --type=NodePort --port=8080
```

<br />![image.png](https://cdn.nlark.com/yuque/0/2020/png/2646445/1601898201812-72ca15ec-2345-47f3-9917-65a1e3ff87c6.png#align=left&display=inline&height=1517&margin=%5Bobject%20Object%5D&name=image.png&originHeight=1517&originWidth=2559&size=918866&status=done&style=none&width=2559)
<a name="4DraN"></a>
#### 7. 查看Pod是否正常运行
```bash
kubectl get pod
```
<a name="6UIAg"></a>
#### 8. 获取hello-minikube服务访问url
```bash
minikube service hello-minikube --url
```

<br />![image.png](https://cdn.nlark.com/yuque/0/2020/png/2646445/1601898295939-7271646c-9f20-418b-ad43-535451ed0926.png#align=left&display=inline&height=597&margin=%5Bobject%20Object%5D&name=image.png&originHeight=597&originWidth=1337&size=81747&status=done&style=none&width=1337)<br />

<a name="4RdEQ"></a>
#### 9. 访问dashboard
```bash
minikube dashboard
```


<a name="QJr4S"></a>
#### ![image.png](https://cdn.nlark.com/yuque/0/2020/png/2646445/1601898381356-b2633027-7ea8-4467-8374-e77ecf535a5a.png#align=left&display=inline&height=1534&margin=%5Bobject%20Object%5D&name=image.png&originHeight=1534&originWidth=2502&size=242695&status=done&style=none&width=2502)10. 参考文档
[https://kubernetes.io/zh/docs/setup/learning-environment/minikube/](https://kubernetes.io/zh/docs/setup/learning-environment/minikube/)
