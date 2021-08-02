# kubeadm安装k8s

### 环境

centos 8.4.2105



### 关闭防火墙

```bash
systemctl stop firewalld
```

### 关闭swap

```bash
swapoff -a
```

### 安装docker

```bash
yum install -y yum-utils
yum-config-manager \
    --add-repo \
    https://download.docker.com/linux/centos/docker-ce.repo
yum install docker-ce docker-ce-cli containerd.io --allowerasing
systemctl start docker.service
systemctl enable docker.service
```

### 安装kubeadm、kubelet、kubectl

```bash
## https://kubernetes.io/zh/docs/setup/production-environment/tools/kubeadm/install-kubeadm/#%E5%AE%89%E8%A3%85-kubeadm-kubelet-%E5%92%8C-kubectl

cat <<EOF | sudo tee /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-\$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
exclude=kubelet kubeadm kubectl
EOF

# 将 SELinux 设置为 permissive 模式（相当于将其禁用）
sudo setenforce 0
sudo sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config

sudo yum install -y kubelet kubeadm kubectl --disableexcludes=kubernetes

sudo systemctl enable --now kubelet
```

### 设置iptables不处理bridge的数据

```bash
echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables
```

### 下载coredns镜像

```bash
docker pull coredns/coredns:1.8.0
```

### 下载其他镜像

```bash
kubeadm config images pull --image-repository=registry.aliyuncs.com/google_containers
```



### 修改镜像tag和kubeadm指定的镜像tag一致

按照自己的版本修改，查看kubeadm指定的镜像

```bash
kubeadm config images list
```

修改命令

```bash
docker tag registry.aliyuncs.com/google_containers/kube-proxy:v1.21.2 k8s.gcr.io/kube-proxy:v1.21.2
docker tag registry.aliyuncs.com/google_containers/kube-apiserver:v1.21.2 k8s.gcr.io/kube-apiserver:v1.21.2
docker tag registry.aliyuncs.com/google_containers/kube-controller-manager:v1.21.2 k8s.gcr.io/kube-controller-manager:v1.21.2
docker tag registry.aliyuncs.com/google_containers/kube-scheduler:v1.21.2 k8s.gcr.io/kube-scheduler:v1.21.2
docker tag registry.aliyuncs.com/google_containers/etcd:3.4.13-0 k8s.gcr.io/etcd:3.4.13-0
docker tag coredns/coredns:1.8.0 k8s.gcr.io/coredns/coredns:v1.8.0
docker tag registry.aliyuncs.com/google_containers/pause:3.4.1 k8s.gcr.io/pause:3.4.1
```

### 启动master节点

```bash
kubeadm init --pod-network-cidr=10.244.0.0/16
mkdir -p $HOME/.kube
cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
```

### 部署flannel网络插件

如果coredns一直是pending

```bash
kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml
```

等待master所有pod均为run状态

```bash
kubectl get nodes
```

### node加入集群

复制master节点init命令输出的join命令到node执行，让node加入集群

如果用的虚拟机，两个机器主机名相同，修改node机器主机名

```bash
hostnamectl set-hostname node1
```

加入集群

```bash
kubeadm join 192.168.209.141:6443 --token XXX --discovery-token-ca-cert-hash sha256:XXX  --node-name node1
```
