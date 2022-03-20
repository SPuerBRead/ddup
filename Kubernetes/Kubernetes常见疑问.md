# Kubernetes常见疑问

1、如何理解Pod和Container，以及他们的关系

* Pod只是一种概念和编排思想，也是Kubernetes最小的调度单位，是对容器的进一步抽象和封装，用于处理存在亲密关系的多个容器（公用网络、存储等），可以类比成传统部署方式中的虚拟机或Linux进程组（线程组），包含多个有亲密关系的Container
* Container是单独的一个进程，同一个Pod中的Container共用同一个Netword NameSpace

2、一个服务多个相同容器组成进行负载，这些容器之间是什么概念

可以理解成一个Deployment Controller，简单看Kubernetes通过Deployment Controller管理Pod（实际还有ReplicaSet Controller在中间），Deployment的replicas参数设置一个服务有多少个Pod，Controller类型很多，Deployment是Kubernetes Controller的最为常见一种

3、有状态应容器和无状态容器的理解

有状态应容器和无状态容器分别对应无状态应用和无状态应用，过去简单理解为有状态容器就是指容器更换网络地址也不会变，如果需要一个稳定的IP地址那就需要将应用设置为有状态，这个理解狭隘了很多

有状态应用指应用实例之间有着顺序或者依赖关系主从、主备或者应用的数据不能因为替换就被删除，举以下两个有状态应用的例子

A应用依赖B应用启动后才能启动
A应用为数据库服务，存储的数据必须在替换前后保持完全一致

4、容器启动流程

先解释下流程中出现的名次

* **container runtime**：容器运行时，管理容器的生命周期、镜像、存储
* **CRI**：Container Runtime Interface，Kubernetes定义的一组与容器运行时进行交互的接口，kubelet和容器运行时之间通信的主要协议，满足CRI标准的容器运行时就可以被Kubernetes调用，详细参考：[容器运行时接口（CRI） | Kubernetes](https://kubernetes.io/zh/docs/concepts/architecture/cri/)
* **OCI**：Open Container Initiative，容器运行时标准，定义了运行时规范（runtime-spec）和镜像规范（image-spec）详细参考：[Open Container Initiative](https://opencontainers.org/)
* **libcontainer**：老版本docker的container runtime后来改名为runc
* **runc**：以OCI标准实现的container runtime，真正负责设置容器namespace、cgroup、chroot的组件
* **dockershim**：Kubernetes小于1.24版本为了方便的接入docker集成在Kubernetes代码中的对接docker的接口
* **containerd**：老版本docker中通过docker daemon直接操作容器，后来拆分成dockerd、containerd、runc，containerd可以理解成CRI-shim，把kubelet的CRI请求转换为containerd的调用

可以简单理解为，Kubernetes负责容器的调度，就需要对接各种容器运行时，市面上非常多的容器运行时，比如docker、kata、gVisor为了方便对接，减少工作量就定义了CRI接口，满足CRI的容器运行时就可以直接接入Kubernetes，但是前期为了能够对docker开箱即用，所以单独实现了dockershim对接docker，容器运行时本身有很多产品，所以为了规范容器运行时需要包含哪些功能做哪些操作就有了OCI标准

* docker自身容器启动流程
    `dockerd(Docker Daemon) -> containerd -> containerd-shim -> runc`

* Kubernetes < 1.24
    `kubelet -> dockershim(kubelet 内置) -> dockerd -> containerd -> containerd-shim -> runc`

* containerd 1.0取代了dockershim和dockerd，此时的containerd还没有实现Kubernetes CRI，所以出现了CRI-Containerd去进行适配
    `kubelet -> CRI-Containerd -> containerd -> containerd-shim -> runc`

* containerd 1.1 containerd以CRI plugin插件形式支持了Kubernetes CRI，去除掉了CRI-Containerd
    `kubelet -> containerd(CRI plugin) -> containerd-shim -> runc`



