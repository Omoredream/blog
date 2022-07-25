---
title: Frp与Proxifier配合使用
data: 2021-12-1
tags:
	- 内网
---

内网穿透的一次实现

<!-- more -->

## 环境准备

首先需要准备一台vps服务器，内网环境下的一台主机，自己的外网本机

客户端：部署在需要穿透的内网服务所在的机器上（需要代理出来流量的内网机器）

frp客户端为frpc

服务端： 部署在具有公网 IP 的机器上

frp服务端为frps

做这个实验，首先要明白什么是正向代理与反向代理

**入站反向，出站正向**（通常绕过防火墙）

### 正向代理

正向代理类似一个跳板机，代理访问外部资源（比如我们国内访问谷歌，直接访问访问不到，我们可以通过一个正向代理服务器，请求发到代理服，代理服务器能够访问谷歌，这样由代理去谷歌取到返回数据，再返回给我们，这样我们就能访问谷歌了）。

正向代理隐藏了真实的请求客户端。服务端不知道真实的客户端是谁，客户端请求的服务都被代理服务器代替来请求，某些科学上网工具扮演的就是典型的正向代理角色。用浏览器访问 http://www.google.com 时被墙了，于是你可以在国外搭建一台代理服务器，让代理帮我去请求 google，代理把请求返回的相应结构再返回给我。

 ![img](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112122101881.png)

### 反向代理

反向代理（Reverse Proxy）实际运行方式是指以代理服务器来接受internet上的连接请求，然后将请求转发给内部网络上的服务器，并将从服务器上得到的结果返回给internet上请求连接的客户端，此时代理服务器对外就表现为一个服务器。

反向代理隐藏了真实的服务端，当我们请求 www.baidu.com 的时候，背后可能有成千上万台服务器为我们服务，但具体是哪一台，你不知道，也不需要知道，你只需要知道 www.baidu.com 是我们的反向代理服务器，反向代理服务器会帮我们把请求转发到真实的服务器那里去。Nginx就是性能非常好的反向代理服务器，用来做负载均衡。

 ![img](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112122105086.png)

而FRP实现内网穿透，就在于使用反向代理，使得真实的服务端得以隐藏。当外部用户（client）请求访问服务端VPS的时候，服务端VPS是中的客户端的反向代理服务器，反向代理服务器会帮我们把请求转发到真实的服务器那里去。这样就实现了内网穿透。


## frp与proxifier

frp 是一个专注于内网穿透的高性能的反向代理应用，支持 TCP、UDP、HTTP、HTTPS 等多种协议。可以将内网服务以安全、便捷的方式通过具有公网 IP 节点的中转暴露到公网。

Proxifier是一款功能非常强大的socks5客户端，可以让不支持通过代理服务器工作的网络程序能通过HTTPS或SOCKS代理或代理链。支持 64位系统，支持Xp，Vista，Win7，MAC OS ,支持socks4，socks5，http代理协议，支持TCP，UDP协议，可以指定端口，指定IP，指定域名，指定程序等运行模式，兼容性非常好。。

**需要额外注意的事项：**

注意，除http(s)以外，客户端frpc.ini内任何端口修改时须在以下范围内：
默认端口白名单：2000-3000,3001,3003,4000-50000

转发远程桌面时，需先在本机开启允许远程协助 我的电脑-右键属性-远程设置

需要注意frpc所在机器和frps所在机器的时间相差不能超过15分钟，因为时间戳会被用于加密验证中，防止报文被劫持后被其他人利用。

**注意：所有转发的端口都需要在服务器端开放其防火墙！！！**

### 服务端部署（Linux VPS）

```linux
sudo apt-get update

wget https://github.com/fatedier/frp/releases/download/v0.17.0/frp_0.17.0_linux_amd64.tar.gz

tar -zxvf frp_0.17.0_linux_amd64.tar.gz  #解压缩：tar xvf 文件名

cd frp_0.17.0_linux_amd64                #进入解压目录

#修改frps.ini文件
sudo vim ./frps.ini
```

```shell
[common]

Bind_addr = 0.0.0.0   #服务端监听地址 默认0.0.0.0

bind_port = 7000    #服务端监听端口

dashboard_port = 7500  #状态以及代理统计信息展示,vpsip:7500可查看详情

dashboard_user = admin     #访问用户

dashboard_pwd = password    # dashboard_pwd访问密码

log_file = ./frps.log    #log_file日志文件

log_level = info    # log_level记录的日志级别

log_max_days = 3     # log_max_days日志留存3天

authentication_timeout = 0     #authentication_timeout超时时间

#max_pool_count最大链接池,每个代理预先与后端服务器建立起指定数量的最大链接数

max_pool_count = 50

allow_ports = 40000-50000  #允许代理绑定的服务端端口
```

![image-20211202102106630](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112122102517.png)

设置为开机自动启动

```
sudo vim /etc/systemd/system/frps.service
```

```shell
[Unit]
Description=frps daemon
After=syslog.target  network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/root/frp_0.17.0_linux_amd64/frps -c /root/frp_0.17.0_linux_amd64/frps.ini #你安装frps的路径
Restart= always
RestartSec=1min

[Install]
WantedBy=multi-user.target
```

```
#启动frps
systemctl daemon-reload
systemctl start frps

#设置为开机启动
systemctl enable frps

#或者在frp_0.17.0_linux_amd64目录下，临时启动命令
./frps -c ./frps.ini
```

### 客户端部署

```
sudo apt-get update

wget https://github.com/fatedier/frp/releases/download/v0.17.0/frp_0.17.0_linux_arm.tar.gz

tar -zxvf frp_0.17.0_linux_arm.tar.gz  #解压缩：tar xvf 文件名

cd frp_0.17.0_linux_arm                #进入解压目录

#修改frpc.ini文件
sudo vim ./frpc.ini
```

```shell
[common]
server_addr = vps的ip地址     #连接服务端的地址
server_port = 7000     #连接服务端的端口
tls_enable = ture      #启用 TLS 协议加密连接
pool_count = 5    #连接池大小

[plugin_socks]
type = tcp
remote_port = 46075
plugin = socks5
plugin_user = admin
plugin_passwd = admin123
use_encryption = true
use_compression = true
```

![image-20211202102117780](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112122102275.png)

设置为开机自动启动

```
sudo vim /etc/systemd/system/frpc.service
```

```shell
[Unit]
Description=frps daemon
After=syslog.target  network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/root/frp_0.17.0_linux_amd64/frpc -c /root/frp_0.17.0_linux_amd64/frpc.ini #你安装frpc的路径
Restart= always
RestartSec=1min

[Install]
WantedBy=multi-user.target
```

```
#启动frps
systemctl daemon-reload
systemctl start frpc

#设置为开机启动
systemctl enable frpc

#或者在frp_0.17.0_linux_amd64目录下，临时启动命令
./frpc -c ./frpc.ini
```

![image-20211202101803909](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112122105562.png)

访问VPS:7500查看是否连接成功（或看vps的执行完frps界面有没有报错，有报错的话按照报错提示去修改就好了。）

![image-20211202101749171](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112122102975.png)

### 配置proxifier

（1）配置ip、端口、连接方式、账号密码

l 点击Proxy Server按钮

l Add

l 输入本地shadowshocks的ip（默认127.0.0.1）和端口（默认1080）

l 选择SHOCKS Versin 5

l 然后点击check

l OK

 ![](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112122102543.png)

（2）配置通过该代理的IP

l 点击Proxification Rule

l 选中localhost,点击Edit

l Target hosts处添加允许通过的IP（一般内网我都会只让内网的IP通过，防止流量过大）

l Action选择刚才配置的连接方式

l OK

 ![img](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112122102136.png)

![image-20211212210509765](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112122105466.png)

（3）   代理成功后访问http://ip地址:7500![img](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112122102355.png)

**查看到已经能够访问到内网的网站**

![image-20211202102024501](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112122102879.png)