# docker设置btrfs存储驱动

测试环境 centos7.9

1. 安装并启动docker

2. 停止docker服务，备份/var/lib/docker

   ```shell
   service docker stop
   cp -au /var/lib/docker /var/lib/docker.bak
   rm -rf /var/lib/docker/*
   ```

3. 虚拟机增加磁盘空间

4. 对新增的磁盘空间分区，然后重启

   ```shell
   fdisk /dev/sda
   n
   p
   3 分区号在fdisk -l里找一个没用过的就可以了
   默认回车 起始扇区
   默认回车 结束扇区
   t 分区类型
   3 
   8e lvm
   w 写分区表
   ```

5. 格式化新建的分区，设置为btrfs文件系统`mkfs.btrfs -f /dev/sda3`

6. 把新设备挂载到/var/lib/docker目录下 `mount -t btrfs /dev/sda3 /var/lib/docker`

7. 设置或创建/etc/docker/daemon.json

   ```json
   {
    "storage-driver":"btrfs"
   }
   ```

8. 启动docker服务，docker info确认当前存储驱动是否为btrfs