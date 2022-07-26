---
title: OWASP TOP 10 2021
data: 2021-10-3
tags: 	
	- 安全
---

OWASP（开放式Web应用程序安全项目）的工具、文档、论坛和全球各地分会都是开放的，对所有致力于改进应用程序安全的人士开放，其最具权威的就是“10项最严重的Web 应用程序安全风险列表” ，总结了Web应用程序最可能、最常见、最危险的十大漏洞，是开发、测试、服务、咨询人员应知应会的知识。

<!-- more -->

# 2021 年前 10 名的变化

有三个新类别，四个类别的命名和范围发生了变化，并在 2021 年的前 10 名中进行了一些合并。

**1.1、A01:2021-\**损坏的访问控制\****

从第五位上升；94% 的应用程序都经过了某种形式的破坏访问控制的测试。映射到 Broken Access Control 的 34 个 CWE 在应用程序中出现的次数比任何其他类别都多。



**1.2、A0*****\2:2021-加密失败\****

上移一位至 #2，以前称为*敏感数据暴露，*这是广泛的症状而不是根本原因。此处重新关注与密码学相关的故障，这些故障通常会导致敏感数据暴露或系统受损。



**1.3、A03:2021-注入**

下滑到第三位。94% 的应用程序都针对某种形式的注入进行了测试，映射到此类别的 33 个 CWE 在应用程序中出现次数第二多。跨站点脚本编写现在是此版本中此类别的一部分。



**1.4、A04:2021-不安全设计**

是2021 年的一个新类别，重点关注与设计缺陷相关的风险。如果我们真的想作为一个行业“向左移动”，就需要更多地使用威胁建模、安全设计模式和原则以及参考架构。



**1.5、A05:2021-安全配置错误**

从上一版的第 6 位上升；90% 的应用程序都经过了某种形式的错误配置测试。随着更多转向高度可配置的软件，看到这一类别上升也就不足为奇了。XML 外部实体 (XXE) 的前一个类别现在属于此类别。



**1.6、A06:2021-\**易受攻击和过时的组件\****

之前的标题是 *使用具有已知漏洞的组件，*在行业调查中排名第二，但也有足够的数据通过数据分析进入前 10 名。该类别从 2017 年的第 9 位上升，是我们难以测试和评估风险的已知问题。它是唯一没有任何 CVE 映射到包含的 CWE 的类别，因此默认的利用和影响权重 5.0 被计入他们的分数。



**1.7、A07:2021-\**身份验证失败\****

以前是 ***Broken Authentication\***并且从第二位下滑，现在包括与识别失败更多相关的 CWE。这个类别仍然是前 10 名的一个组成部分，但标准化框架的可用性增加似乎有所帮助。



**1.8、A08:2021-软件和数据完整性故障**

是 2021 年的一个新类别，专注于在不验证完整性的情况下做出与软件更新、关键数据和 CI/CD 管道相关的假设。CVE/CVSS 数据的最高加权影响之一映射到此类别中的 10 个 CWE。2017 年的不安全反序列化现在是这一更大类别的一部分。



**1.9、A09:2021-安全日志记录和监控失败**

以前是 **日志记录和监控***不足*，是从行业调查 (#3) 中添加的，从之前的 #10 上升。此类别已扩展为包括更多类型的故障，难以测试，并且在 CVE/CVSS 数据中没有得到很好的体现。但是，此类故障会直接影响可见性、事件警报和取证。



**1.10、A10:2021-\**服务器端请求伪造（SSRF）\****

是从行业调查 (#1) 中添加的。数据显示发生率相对较低，测试覆盖率高于平均水平，并且利用和影响潜力的评级高于平均水平。此类别代表行业专业人士告诉我们这很重要的场景，即使目前数据中没有说明。



# OWASP TOP 10 2021

## **2.1、损坏的访问控制**

### **描述：**

访问控制强制执行策略，使用户不能在其预期权限之外采取行动。故障通常会导致**未经授权的信息泄露、修改或破坏所有数据或执行超出用户限制的业务功能**。常见的访问控制漏洞包括：

- 通过修改 URL、内部应用程序状态或 HTML 页面，或仅使用自定义 API 攻击工具来绕过访问控制检查。
- 允许将主键更改为其他用户的记录，允许查看或编辑其他人的帐户。
- 特权提升。在未登录的情况下充当用户或以用户身份登录时充当管理员。
- 元数据操作，例如重放或篡改 JSON Web 令牌 (JWT) 访问控制令牌，或用于提升权限或滥用 JWT 失效的 cookie 或隐藏字段。
- CORS 错误配置允许未经授权的 API 访问。
- 强制以未经身份验证的用户身份浏览经过身份验证的页面或以标准用户身份浏览特权页面。访问 API 时缺少对 POST、PUT 和 DELETE 的访问控制。

### **如何预防：**

访问控制仅在受信任的服务器端代码或无服务器 API 中有效，攻击者无法修改访问控制检查或元数据。

- 除公共资源外，默认拒绝。
- 实施一次访问控制机制并在整个应用程序中重复使用它们，包括最大限度地减少 CORS 的使用。
- 模型访问控制应该强制记录所有权，而不是接受用户可以创建、读取、更新或删除任何记录。
- 独特的应用程序业务限制要求应由领域模型强制执行。
- 禁用 Web 服务器目录列表并确保文件元数据（例如 .git）和备份文件不在 Web 根目录中。
- 记录访问控制失败，在适当时提醒管理员（例如，重复失败）。
- 速率限制 API 和控制器访问，以最大限度地减少自动攻击工具的危害。
- 注销后，JWT 令牌应在服务器上失效。

### **攻击场景示例：**

**场景 #1：**应用程序在访问帐户信息的 SQL 调用中使用未经验证的数据：

> pstmt.setString(1, request.getParameter("acct")); 
>
> 结果集结果 = pstmt.executeQuery();



攻击者只需修改浏览器的“acct”参数即可发送他们想要的任何帐号。如果没有正确验证，攻击者可以访问任何用户的帐户。

https://example.com/app/accountInfo?acct=notmyacct



**场景#2：**攻击者只是强制浏览到目标 URL。访问管理页面需要管理员权限。

> https://example.com/app/getappInfo https://example.com/app/admin_getappInfo

> 

如果未经身份验证的用户可以访问任一页面，那就是一个缺陷。如果非管理员可以访问管理页面，这是一个缺陷。



## 2.2、加密失败



### **描述：**

首先是确定传输中和静止数据的保护需求。例如，密码、信用卡号、健康记录、个人信息和商业秘密需要额外保护，主要是如果该数据属于隐私法（例如欧盟的通用数据保护条例 (GDPR)）或法规（例如金融数据保护）例如 PCI 数据安全标准 (PCI DSS)。对于所有此类数据：

- 是否有任何数据以明文形式传输？这涉及 HTTP、SMTP 和 FTP 等协议。外部互联网流量是危险的。验证所有内部流量，例如，负载平衡器、Web 服务器或后端系统之间的流量。
- 默认情况下或在较旧的代码中是否使用任何旧的或弱的加密算法？
- 是否正在使用默认加密密钥、生成或重复使用弱加密密钥，或者是否缺少适当的密钥管理或轮换？
- 是否未强制执行加密，例如，是否缺少任何用户代理（浏览器）安全指令或标头？
- 用户代理（例如，应用程序、邮件客户端）是否不验证收到的服务器证书是否有效？

请参阅 ASVS 加密 (V7)、数据保护 (V9) 和 SSL/TLS (V10)

### **如何预防：**

至少执行以下操作，并查阅参考资料：

- 对应用程序处理、存储或传输的数据进行分类。根据隐私法、监管要求或业务需求确定哪些数据是敏感的。
- 根据分类应用控制。
- 不要不必要地存储敏感数据。尽快丢弃它或使用符合 PCI DSS 的标记化甚至截断。未保留的数据不能被窃取。
- 确保加密所有静态敏感数据。
- 确保拥有最新且强大的标准算法、协议和密钥；使用适当的密钥管理。
- 使用安全协议（例如具有完美前向保密 (PFS) 密码的 TLS、服务器的密码优先级和安全参数）加密所有传输中的数据。使用 HTTP 严格传输安全 (HSTS) 等指令强制加密。
- 对包含敏感数据的响应禁用缓存。
- 使用具有工作因子（延迟因子）的强自适应和加盐散列函数存储密码，例如 Argon2、scrypt、bcrypt 或 PBKDF2。
- 独立验证配置和设置的有效性。

### **攻击场景示例：**

**场景#1**：应用程序使用自动数据库加密对数据库中的信用卡号进行加密。但是，此数据在检索时会自动解密，从而允许 SQL 注入缺陷以明文形式检索信用卡号。

**场景#2**：站点不使用或对所有页面强制执行 TLS 或支持弱加密。攻击者监视网络流量（例如，在不安全的无线网络中），将连接从 HTTPS 降级为 HTTP，拦截请求并窃取用户的会话  cookie。然后攻击者重放这个 cookie  并劫持用户的（经过身份验证的）会话，访问或修改用户的私人数据。除了上述之外，他们还可以更改所有传输的数据，例如，汇款的接收者。

**场景#3**：密码数据库使用未加盐或简单的哈希来存储每个人的密码。文件上传缺陷允许攻击者检索密码数据库。所有未加盐的哈希值都可以通过预先计算的哈希值彩虹表公开。由简单或快速散列函数生成的散列可能会被 GPU 破解，即使它们被加盐。



## **2.3、注入**

### **描述：**

应用程序在以下情况下容易受到攻击：

- 应用程序不会验证、过滤或清理用户提供的数据。
- 没有上下文感知转义的动态查询或非参数化调用直接在解释器中使用。
- 在对象关系映射 (ORM) 搜索参数中使用恶意数据来提取额外的敏感记录。
- 直接使用或连接恶意数据。SQL 或命令包含动态查询、命令或存储过程中的结构和恶意数据。

一些更常见的注入是 SQL、NoSQL、OS 命令、对象关系映射 (ORM)、LDAP 和表达式语言 (EL) 或对象图导航库 (OGNL)  注入。这个概念在所有口译员中都是相同的。源代码审查是检测应用程序是否容易受到注入攻击的最佳方法。强烈建议对所有参数、标头、URL、cookie、JSON、SOAP 和 XML 数据输入进行自动化测试。组织可以将静态源 (SAST) 和动态应用程序测试 (DAST) 工具包含到 CI/CD  管道中，以在生产部署之前识别引入的注入缺陷。

### **如何预防：**

- 防止注入需要将数据与命令和查询分开。
- 首选选项是使用安全的 API，它完全避免使用解释器，提供参数化接口，或迁移到对象关系映射工具 (ORM)。
- 注意：即使在参数化时，如果 PL/SQL 或 T-SQL 连接查询和数据或使用 EXECUTE IMMEDIATE 或 exec() 执行恶意数据，则存储过程仍然会引入 SQL 注入。
- 使用正面或“白名单”服务器端输入验证。这不是一个完整的防御，因为许多应用程序需要特殊字符，例如文本区域或移动应用程序的 API。
- 对于任何残留的动态查询，使用该解释器的特定转义语法转义特殊字符。
- 注意：表名、列名等 SQL 结构不能转义，因此用户提供的结构名是危险的。这是报告编写软件中的常见问题。
- 在查询中使用 LIMIT 和其他 SQL 控件以防止在 SQL 注入的情况下大量披露记录。

### **攻击场景示例：**

**场景 #1：**应用程序在构建以下易受攻击的 SQL 调用时使用不受信任的数据：

String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";

**场景#2：**类似地，应用程序对框架的盲目信任可能会导致查询仍然存在漏洞（例如，Hibernate 查询语言 (HQL)）：

> Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");



在这两种情况下，攻击者都会修改浏览器中的 'id' 参数值以发送：' 或 '1'='1。例如：

http://example.com/app/accountView?id=' 或 '1'='1

这将更改两个查询的含义以返回帐户表中的所有记录。更危险的攻击可能会修改或删除数据，甚至调用存储过程。



## **2.4、不安全的设计**



### **描述：**

不安全设计是一个广泛的类别，代表许多不同的弱点，表现为“缺失或无效的控制设计”。缺少不安全的设计是缺少控制的地方。例如，想象一下应该加密敏感数据的代码，但没有方法。无效的不安全设计是可以实现威胁的地方，但域（业务）逻辑验证不足会阻止该操作。例如，假设域逻辑应该根据收入等级处理流行病税收减免，但不验证所有输入都已正确签名并提供比应授予的更重要的减免收益。

安全设计是一种文化和方法，它不断评估威胁并确保代码经过稳健设计和测试，以防止已知的攻击方法。安全设计需要安全的开发生命周期、某种形式的安全设计模式或铺砌道路组件库或工具，以及威胁建模。

### **如何预防：**

- 与 AppSec 专业人员建立并使用安全的开发生命周期，以帮助评估和设计与安全和隐私相关的控制
- 建立和使用安全设计模式库或准备使用组件的铺好的道路
- 将威胁建模用于关键身份验证、访问控制、业务逻辑和关键流
- 编写单元和集成测试以验证所有关键流都能抵抗威胁模型

### **攻击场景示例：**

**场景 #1：**凭证恢复工作流可能包括“问答”，这是 NIST 800-63b、OWASP ASVS 和 OWASP Top 10 所禁止的。不能将问答作为多个人身份的证据可以知道答案，这就是为什么它们被禁止。此类代码应删除并替换为更安全的设计。

**场景#2：**连锁影院允许团体预订折扣，并且在要求押金之前最多有 15 名参与者。攻击者可以对该流程进行威胁建模，并测试他们是否可以在几次请求中一次预订 600 个座位和所有电影院，从而造成巨大的收入损失。

**场景 #3：**零售连锁店的电子商务网站没有针对由黄牛运行的机器人提供保护，这些机器人购买高端显卡以转售拍卖网站。这对视频卡制造商和零售连锁店主造成了可怕的宣传，并与无法以任何价格获得这些卡的爱好者之间产生了仇恨。仔细的反机器人设计和域逻辑规则，例如在可用性的几秒钟内进行的购买，可能会识别出不真实的购买并拒绝此类交易。



## **2.5、安全配置错误**

### **描述：**

如果应用程序是：

- 在应用程序堆栈的任何部分缺少适当的安全强化或对云服务的权限配置不正确。
- 启用或安装了不必要的功能（例如，不必要的端口、服务、页面、帐户或权限）。
- 默认帐户及其密码仍处于启用状态且未更改。
- 错误处理向用户显示堆栈跟踪或其他信息过多的错误消息。
- 对于升级的系统，最新的安全功能被禁用或未安全配置。
- 应用程序服务器、应用程序框架（例如，Struts、Spring、ASP.NET）、库、数据库等中的安全设置未设置为安全值。
- 服务器不发送安全标头或指令，或者它们未设置为安全值。
- 软件已过时或易受攻击（请参阅 A06:2021-易受攻击和过时的组件）。

如果没有协调一致的、可重复的应用程序安全配置过程，系统将面临更高的风险。

### **如何预防：**

应实施安全安装过程，包括：

- 可重复的强化过程使部署另一个适当锁定的环境变得快速而轻松。开发、QA 和生产环境都应配置相同，在每个环境中使用不同的凭据。这个过程应该是自动化的，以最大限度地减少设置新安全环境所需的工作。
- 一个没有任何不必要的功能、组件、文档和示例的最小平台。删除或不安装未使用的功能和框架。
- 作为补丁管理流程的一部分，审查和更新适用于所有安全说明、更新和补丁的配置的任务（请参阅 A06:2021-易受攻击和过时的组件）。查看云存储权限（例如，S3 存储桶权限）。
- 分段应用程序架构通过分段、容器化或云安全组 (ACL) 在组件或租户之间提供有效且安全的分离。
- 向客户端发送安全指令，例如，安全标头。
- 验证配置和设置在所有环境中的有效性的自动化过程。

### **攻击场景示例：**

**场景#1：**应用程序服务器带有未从生产服务器中删除的示例应用程序。这些示例应用程序具有攻击者用来破坏服务器的已知安全漏洞。假设这些应用程序之一是管理控制台，并且默认帐户未更改。在这种情况下，攻击者使用默认密码登录并接管。

**场景#2：**服务器上没有禁用目录列表。攻击者发现他们可以简单地列出目录。攻击者找到并下载已编译的 Java 类，对其进行反编译和逆向工程以查看代码。然后攻击者发现应用程序中存在严重的访问控制缺陷。

**场景#3：**应用服务器的配置允许将详细的错误消息（例如堆栈跟踪）返回给用户。这可能会暴露敏感信息或潜在缺陷，例如已知易受攻击的组件版本。

**场景#4：**云服务提供商拥有其他 CSP 用户对 Internet 开放的默认共享权限。这允许访问存储在云存储中的敏感数据。



## **2.6、易受攻击和过时的组件**

### **描述：**

你可能很脆弱：

- 如果您不知道您使用的所有组件的版本（客户端和服务器端）。这包括您直接使用的组件以及嵌套的依赖项。
- 如果软件易受攻击、不受支持或已过期。这包括操作系统、Web/应用程序服务器、数据库管理系统 (DBMS)、应用程序、API 和所有组件、运行时环境和库。
- 如果您不定期扫描漏洞并订阅与您使用的组件相关的安全公告。
- 如果您没有以基于风险的方式及时修复或升级底层平台、框架和依赖项。这通常发生在修补是变更控制下的每月或每季度任务的环境中，使组织面临数天或数月不必要地暴露于固定漏洞的风险。
- 如果软件开发人员不测试更新、升级或修补的库的兼容性。
- 如果您不保护组件的配置（请参阅 A05:2021-安全配置错误）。

### **如何预防：**

应该有一个补丁管理流程来：

- 删除未使用的依赖项、不必要的功能、组件、文件和文档。
- 使用版本、OWASP Dependency Check、retire.js 等工具持续清点客户端和服务器端组件（例如框架、库）及其依赖项的版本。成分。使用软件组合分析工具来自动化该过程。订阅与您使用的组件相关的安全漏洞的电子邮件警报。
- 仅通过安全链接从官方来源获取组件。首选签名包以减少包含修改后的恶意组件的机会（请参阅 A08:2021-软件和数据完整性故障）。
- 监视未维护或未为旧版本创建安全补丁的库和组件。如果无法打补丁，请考虑部署虚拟补丁来监控、检测或防止发现的问题。

每个组织都必须确保在应用程序或产品组合的生命周期内制定持续的监控、分类和应用更新或配置更改的计划。

### **攻击场景示例：**

**场景#1：**组件通常以与应用程序本身相同的权限运行，因此任何组件中的缺陷都可能导致严重影响。此类缺陷可能是偶然的（例如，编码错误）或有意的（例如，组件中的后门）。发现的一些可利用组件漏洞的示例是：

- CVE-2017-5638 是一个 Struts 2 远程代码执行漏洞，可以在服务器上执行任意代码，已被归咎于重大漏洞。
- 虽然物联网 (IoT) 通常很难或不可能修补，但修补它们的重要性可能很大（例如，生物医学设备）。

有一些自动化工具可以帮助攻击者找到未打补丁或配置错误的系统。例如，Shodan IoT 搜索引擎可以帮助您找到仍然存在 2014 年 4 月修补的 Heartbleed 漏洞的设备。



## **2.7、身份验证失败**

### **描述：**

确认用户的身份、身份验证和会话管理对于防止与身份验证相关的攻击至关重要。如果应用程序存在以下情况，则可能存在身份验证漏洞：

- 允许自动攻击，例如撞库，其中攻击者拥有有效用户名和密码的列表。
- 允许蛮力或其他自动攻击。
- 允许使用默认密码、弱密码或众所周知的密码，例如“Password1”或“admin/admin”。
- 使用弱或无效的凭据恢复和忘记密码流程，例如无法确保安全的“基于知识的答案”。
- 使用纯文本、加密或弱散列密码（请参阅 A3:2017-敏感数据暴露）。
- 缺少或无效的多因素身份验证。
- 在 URL 中公开会话 ID（例如，URL 重写）。
- 成功登录后不要轮换会话 ID。
- 不会正确地使会话 ID 无效。用户会话或身份验证令牌（主要是单点登录 (SSO) 令牌）在注销或一段时间不活动期间未正确失效。

### **如何预防：**

- 在可能的情况下，实施多因素身份验证以防止自动凭证填充、暴力破解和被盗凭证重用攻击。
- 不要使用任何默认凭据进行交付或部署，尤其是对于管理员用户。
- 实施弱密码检查，例如针对前 10,000 个最差密码列表测试新密码或更改的密码。
- 将密码长度、复杂性和轮换策略与 NIST 800-63b 的第 5.1.1 节中关于记忆秘密的指南或其他现代的、基于证据的密码策略保持一致。
- 通过对所有结果使用相同的消息，确保注册、凭据恢复和 API 路径能够抵御帐户枚举攻击。
- 限制或增加延迟失败的登录尝试。当检测到凭证填充、暴力破解或其他攻击时，记录所有故障并提醒管理员。
- 使用服务器端、安全、内置的会话管理器，在登录后生成新的高熵随机会话 ID。会话 ID 不应在 URL 中，安全存储，并在注销、空闲和绝对超时后失效。

### **攻击场景示例：**

**场景#1：**凭证填充（使用已知密码列表）是一种常见的攻击。假设应用程序没有实施自动化威胁或凭证填充保护。在这种情况下，应用程序可以用作密码预言机来确定凭据是否有效。

**场景#2：**大多数身份验证攻击是由于继续使用密码作为唯一因素而发生的。一经考虑，最佳实践、密码轮换和复杂性要求会鼓励用户使用和重复使用弱密码。建议组织按照 NIST 800-63 停止这些做法并使用多因素身份验证。

**场景 #3：**应用程序会话超时设置不正确。用户使用公共计算机访问应用程序。用户没有选择“注销”，而是简单地关闭浏览器选项卡并走开。攻击者在一个小时后使用同一个浏览器，而用户仍然通过身份验证。



## **2.8、软件和数据完整性故障**

### **描述：**

软件和数据完整性故障与不能防止完整性违规的代码和基础设施有关。例如，在对象或数据被编码或序列化为攻击者可以看到和修改的结构的情况下，很容易受到不安全的反序列化的影响。另一种形式是应用程序依赖来自不受信任的来源、存储库和内容交付网络 (CDN) 的插件、库或模块。不安全的 CI/CD  管道可能会导致未经授权的访问、恶意代码或系统受损。最后，许多应用程序现在包括自动更新功能，其中更新在没有充分完整性验证的情况下被下载并应用于以前受信任的应用程序。攻击者可能会上传自己的更新以分发并在所有安装上运行。

### **如何预防：**

- 确保未签名或未加密的序列化数据不会在没有某种形式的完整性检查或数字签名的情况下发送到不受信任的客户端，以检测序列化数据的篡改或重放
- 通过签名或类似机制验证软件或数据来自预期来源
- 确保库和依赖项（例如 npm 或 Maven）使用受信任的存储库
- 确保使用软件供应链安全工具（例如 OWASP Dependency Check 或 OWASP CycloneDX）来验证组件不包含已知漏洞
- 确保您的 CI/CD 管道具有正确的配置和访问控制，以确保流经构建和部署过程的代码的完整性。

### **攻击场景示例：**

**场景 #1 不安全的反序列化：** React 应用程序调用一组 Spring Boot  微服务。作为函数式程序员，他们试图确保他们的代码是不可变的。他们提出的解决方案是序列化用户状态并在每个请求中来回传递它。攻击者注意到“R00”Java 对象签名并使用 Java Serial Killer 工具在应用服务器上获取远程代码执行权。

**场景 #2 无需签名即可更新：**许多家用路由器、机顶盒、设备固件和其他固件不通过签名固件验证更新。未签名固件是攻击者越来越多的目标，预计只会变得更糟。这是一个主要问题，因为很多时候除了在未来版本中修复并等待以前的版本过时之外，没有任何补救机制。

**场景#3 SolarWinds 恶意更新**：众所周知，国家会攻击更新机制，最近的一次著名攻击是 SolarWinds Orion 攻击。开发该软件的公司拥有安全的构建和更新完整性流程。尽管如此，这些还是能够被破坏，几个月来，该公司向  18,000 多个组织分发了一个高度针对性的恶意更新，其中大约 100 个组织受到了影响。这是历史上此类性质最深远、最重大的违规行为之一。



## 2.9、安全日志记录和监控失败



### **描述：**

回到 2021 年 OWASP 前 10 名，该类别旨在帮助检测、升级和响应主动违规行为。如果没有日志记录和监控，就无法检测到漏洞。任何时候都会发生日志记录、检测、监控和主动响应不足的情况：

- 不记录可审计的事件，例如登录、失败登录和高价值交易。
- 警告和错误不会生成、不充分或不清楚的日志消息。
- 不会监控应用程序和 API 的日志是否存在可疑活动。
- 日志仅存储在本地。
- 适当的警报阈值和响应升级流程没有到位或有效。
- DAST 工具（例如 OWASP ZAP）的渗透测试和扫描不会触发警报。
- 应用程序无法实时或接近实时地检测、升级或警告主动攻击。

通过使用户或攻击者可以看到日志记录和警报事件，您很容易受到信息泄漏的影响（请参阅 A01:2021 – 损坏的访问控制）。

### **如何预防：**

开发人员应实施以下部分或全部控制措施，具体取决于应用程序的风险：

- 确保所有登录、访问控制和服务器端输入验证失败都可以用足够的用户上下文来记录，以识别可疑或恶意帐户，并保留足够的时间以允许延迟取证分析。
- 确保以日志管理解决方案可以轻松使用的格式生成日志。
- 确保日志数据编码正确，以防止对日志或监控系统的注入或攻击。
- 确保高价值交易具有带有完整性控制的审计跟踪，以防止篡改或删除，例如仅追加数据库表或类似的。
- DevSecOps 团队应该建立有效的监控和警报，以便快速检测和响应可疑活动。
- 制定或采用事件响应和恢复计划，例如 NIST 800-61r2 或更高版本。

有商业和开源应用程序保护框架（例如 OWASP ModSecurity 核心规则集）和开源日志关联软件（例如 ELK 堆栈）具有自定义仪表板和警报功能。

### **攻击场景示例：**

**场景#1：**由于缺乏监控和日志记录，一家儿童健康计划提供商的网站运营商无法检测到违规行为。外部方通知健康计划提供者，攻击者访问并修改了超过 350 万儿童的数千份敏感健康记录。事后审查发现网站开发人员没有解决重大漏洞。由于没有对系统进行日志记录或监控，数据泄露可能自 2013  年以来一直在进行，时间超过七年。

**场景#2：**印度一家大型航空公司发生数据泄露事件，涉及数百万乘客十多年的个人数据，包括护照和信用卡数据。数据泄露发生在第三方云托管服务提供商处，该提供商在一段时间后将泄露事件通知了航空公司。

**场景 #3：**一家主要的欧洲航空公司遭遇了 GDPR 可报告的违规行为。据报道，该漏洞是由攻击者利用的支付应用程序安全漏洞引起的，他们收集了超过 400,000 条客户支付记录。该航空公司因此被隐私监管机构罚款 2000 万英镑。



## **2.10、服务器端请求伪造（SSRF）**



### **描述：**

每当 Web 应用程序在未验证用户提供的 URL 的情况下获取远程资源时，就会出现 SSRF 缺陷。它允许攻击者强制应用程序将精心设计的请求发送到意外目的地，即使受到防火墙、VPN 或其他类型的网络 ACL 的保护也是如此。

随着现代 Web 应用程序为最终用户提供方便的功能，获取 URL 成为一种常见情况。因此，SSRF 的发病率正在增加。此外，由于云服务和架构的复杂性，SSRF 的严重性越来越高。

### **如何预防：**

开发人员可以通过实施以下部分或全部深度防御控制来防止 SSRF：

### **从网络层：**

- 在单独的网络中分段远程资源访问功能以减少 SSRF 的影响
- 强制执行“默认拒绝”防火墙策略或网络访问控制规则，以阻止除基本 Intranet 流量之外的所有流量

### **从应用层：**

- 清理和验证所有客户端提供的输入数据
- 使用肯定的允许列表强制执行 URL 架构、端口和目标
- 不要向客户端发送原始响应
- 禁用 HTTP 重定向
- 注意 URL 一致性，以避免 DNS 重新绑定和“检查时间、使用时间”(TOCTOU) 竞争条件等攻击

不要通过使用拒绝列表或正则表达式来缓解 SSRF。攻击者拥有有效负载列表、工具和技能来绕过拒绝列表。

### **攻击场景示例：**

攻击者可以使用 SSRF 攻击受 Web 应用程序防火墙、防火墙或网络 ACL 保护的系统，使用的场景包括：

**场景#1：**端口扫描内部服务器。如果网络架构是未分段的，攻击者可以绘制内部网络，并根据连接结果或连接或拒绝 SSRF 负载连接所用的时间来确定内部服务器上的端口是打开还是关闭。

**场景#2：**敏感数据暴露。攻击者可以访问本地文件，例如 或内部服务以获取敏感信息。

场景#3：访问云服务的元数据存储。大多数云提供商都有元数据存储，例如http://169.254.169.254/。攻击者可以读取元数据来获取敏感信息。

**场景#4：**破坏内部服务——攻击者可以滥用内部服务进行进一步的攻击，例如远程代码执行 (RCE) 或拒绝服务 (DoS)。