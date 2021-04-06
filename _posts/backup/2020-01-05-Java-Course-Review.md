---
title: Java Course Review Note
tags:
  - Course
  - Java
date: 2020-01-05 16:09:29
---

## C0 Memo

**- 基本概述 -**

课程名称：Java 语言及网络编程

考试时间：2020-01-07(14:00-15:40) 博2-A101

注意事项：复习以课件为主

**- 题型分布 -**

- 选择题 
- 读程序写结果 
- 程序填空 
- 编程大题 (2) 
  - 面向对象★
  - 网络编程 / 多线程 / ★ GUI 用户界面 / 类库

**参考链接 >** [Java 复习 - ComyDream](https://comydream.github.io/2019/01/04/java-review/)

## C1/2 env
Path Class_PATH

## C3 语言基础

```
1.Java 中的八种数据类型
  所占字节数 精度
  相互转换 Bool不可转换
2.表达式多个操作数相互运算的规则结果类型
  int(float) 只保留整数部分
  + 算术加 字符串连接加 
      char 'a'+1 => 98  "a"+1="a1"
3.标识符的命名规则 数字/下划线/$/字母
4.表达式运算符及优先级关系 短路与 短路或
5.选择语句的两个if swith case break
6.循环 跳转 break continue 转义字符
7.一维二维数组的定义与初始化操作 new
8.参数传递
```

**-★ 标识符 -**

**标识符**：是程序员用来标记语言中元素名称的命名记号。

Java 中的标识符遵守先定义后使用的原则。即只有定义了的标识符，才可在语句部分使用。
Java 定义标识符的规则：

- 由**字母、 数字、下划线、 $** 组成。不能由数字开头。 
- 不能是 Java 中的保留字(关键字)。
- 大小写敏感，长度无限制。

**- 命名规范 -**

- 类名 / 接口名：每个字的首字母都需要大写。

- 方法名：第一个字的首字母小写，其余字的首字母大写。

- 常量名：所有字的所有字母都要大写，并且字与字之间用下划线连接

- 变量名：第一个字的首字母小写，其他字的首字母大写，不要使用下滑线，避免使用 `$`。

**- 注释 -**

Java有三种注释形式：

- `//` 单行注释。表示从此向后，直到行尾都是注释。
- `/*……*/` 块注释。在 `/*` 和 `*/` 之间都是注释。
- `/**……*/` 文档注释。所有在 `/**` 和 `*/` 之间的内容可以用来自动形成文档。

### 变量类型

**- 变量 -**

Java 的变量有两种：**局部变量**、**类成员变量**，变量必须先定义后使用。

**局部变量在使用前必须给定初值，否则，将编译出错，而类成员变量无此要求。**

**★ 基本数据类型表**：

![](/assets/images/move/2020-01-06-14-14-33.png)

注意: **Java 中不可将布尔类型看做整型值**。

**缺省值**就是默认的初值,只对成员变量有用。局部变量没有缺省值。



**- 常量 -**

常量是指在程序运行过程中其值不变的量，分为**数值常量**和**符号常量**。

- 数值常量 `123`、`052(8)`、`0x2A`、`12L`、`12.1f`、`true`、`'x'`、`"Test"`；

- 符号常量 `final  类型  常量名 = 值;`；

注意事项：

1. 常量只能赋值一次(初始化)；
2. **类静态成员常量**只能在定义时初始化；
3. **方法中的常量**(局部常量)可以在定义时初始化，也可以先定义，以后再初始化。


### 运算符及优先级

运算符按其功能分为七类：

1. 算术运算符  `+`、`-`、 `*`、 `/`、`%`、 `++`、 `--`；
2. 关系运算符  `>`、`<`、 `>=`、 `<=`、 `==`、 `!=`、`instanceof`(对象运算符)；
3. 逻辑运算符  `!`、`&&`、`||`、`&`、`|`；
4. 位运算符     `>>`、`<<`、`>>>`、`&`、`|`、`^`、`~`；
5. 条件运算符  `? :`；
6. 赋值运算符  `=`、`+=`、`-=` 、`*=` 、`/=`；
7. 其他：下标运算符`[]`.


运算符优先级：

![](/assets/images/move/2020-01-06-14-40-31.png)

**优先级**：() > 单目运算符 > 双目运算符 > 三目运算符 > 赋值运算符.

双目：算术 > 关系 > 逻辑。

**结合性**：大多数运算符结合性为从左至右，**赋值运算符的结合性为从右至左**。

```java
int a, b = 3, c = 5; a = b = c; // a = b = c = 5	
```

### 数据类型转换

**方式**：自动类型转换、手动强制类型转换，隐含强制转换。


**- 自动类型转换 -**

**Java 中整型、实型、字符型数据可以混合运算**。运算过程中，Java 自动把精度较低的类型转换为另一种**精度较高**的类型。

- byte、short、char -> int -> long -> float -> double.

**\* 如果 byte、short、char 在一起运算时，会先将这些值转换为 int 型。再进行运算，结果为 int 型。**


**- 手动强制类型转换 -**

在 Java 中直接将高精度的值赋给低精度的变量会导致**编译出错**。这时可用**强制类型转换**来解决。

强制类型转换可能造成信息的丢失，**布尔型与其它基本类型之间不能转换**。

```java
int i; byte b, c;
b = (byte)345; // c = 89  10 进制转为 2 进制取低 8 位
c = (byte)356; // c = 100 10 进制转为 2 进制取低 8 位
i = (int)(3.8 + 6); // i = 9, 取整 不进行四舍五入
```

运算类型提升功能：

- 在运算过程中，运算的结果至少是 int 型，即如果参与运算的两个数级别比 int 型低或是 int 型，则结果为 int 型。
- 参与运算的数据如果有一个级别比 int 型高，则运算结果的类型与类型级别高的数相同。
- 参与运算的两个数据如果类型不一样，会先把低级的数据转换成高级的类型的数据后再作运算，结果是高级的类型。


**- 隐含类型转换 -**

Java 中允许把 int 类型的**常量**赋给 byte、short 变量时不需要强制类型转换:

```java
byte b = 123; short s = 123; // 合法
b = b + 3; // 不合法
```

但是把 int 类型的**变量**赋给 byte、short 类型的变量时必须强制转换，否则会出错.

```java
int i = 123; byte b = i;  //byte b = (byte)i;
byte a = 1; byte c = (byte)(a + b);
```

### 简单语句和复合语句

**- I/O -**

1.标准输出 **System.out** 对象

`System.out` 对象中包含的最常用的方法是：

- `println`(参数) 向标准输出设备(显示器)打印一行文本并换行
- `print`(参数) 向标准输出设备(显示器)打印一行文本但不换行

参数类型：`boolean`, `char`, `char[]`, `double`, `float`, `int`, `long`, `Object`, `String`.

2.标准输入 **System.in** 对象

`System.in` 是字节流, 作用是从标准输入读一个字节, 常用的方法如下:

- int read()   从流中读取一个字节并将该字节作为整数返回, 若没有数据则返回 `-1`; 
- int read(byte b[])    从流中读取多个字节放到 b 中, 返回实际读取到的字节数; 
- int read(byte b[], int off, int len)    从流中读取最多 len 字节的数据, 放到数组 b 的下标 off 开始的单元中，返回读取到的字节数;

eg1 > ReadChar.java(读取一个字符):

```java
import java.io.*;
public class ReadChar{
    public static void main(String args[]){
    try {
        char ch = (char)System.in.read();
        System.out.println(ch);    
    } catch(IOException e){}
   } 
}
```


eg2 > ReadString.java(读取一串字符):

```java
import java.io.*;    
public class ReadString {
    public static void main(String args[]) {
        char c;
        try {
            do {
                c = (char)System.in.read();  
                System.out.print(c);
            } while(c != '\n');
         } catch(IOException e){}
     }
}
```

eg3 > ReadStringOrInt.java

```java
//从键盘读一数字串或一个整数
import java.io.*;
class ReadStringOrInt {
    public static void main(String args[]) {
        byte buf[] = new byte[20];
        String str;
        int anInt;
        try {
            System.in.read(buf);
            str = new String(buf);
            anInt = Integer.parseInt(str.trim());
        } catch(Exception e) {}
    }
}
```

要将数字串转换成实数，则： 

```java
float f = Float.parseFloat(str.trim()); //转成单精度数
double d = Double.parseDouble(str.trim()); //转成双精度数
```

**- 控制语句 -**

- **选择语句**

  **\> if-else** 语句
  ```java
  if(expr1) {

  } else if (expr2) {

  } else {

  }
  ```

  **\> switch** 语句
  表达式必须是符合 `byte`, `char`, `short` 和 `int` 类型的表达式, 不能是浮点类型或字符串，case 子句中常量的类型必须与表达式的类型相容,且每个常量必须不同。
  case 后面可以有多条语句，不用加 `{}`。
  ```java
  switch(expr) {
    case 常量1: 语句1; break;
    case 常量n: 语句n; break;
    default: 缺省处理语句; [break];
  }
  ```

- **循环语句**

  **\> while** 语句
  ```java
  while(expr) {}
  ```
  **\> do while** 语句
  ```java
  do {} while(expr)
  ```
  **\> for** 语句
  ```java
  for(expr1; expr2; expr3){}
  ```


- **跳转语句**

  **\> break** 语句
  使程序的流程从一个语句块的内部跳转出来。
  - 从 switch 语句的分支中跳出来
  - 从循环体内跳出来        
  **\> continue** 语句
  Continue 语句只结束本次循环,而不是终止整个循环的执行。
  **\> return** 语句
  - 结束方法的运行，并返回一个值。
  - 如果该方法没有返回值（void），则 return 后不能跟表达式。

### 数组操作

Java 中，数组是独立的类，有自身的方法，不只是变量的集合。在 Java 里创建一个数组，需要做如下的工作：

- 说明一个变量来存放该数组。
- 建立一个新的数组对象（即创建数组空间）并把它赋给这个数组变量。
- 在该数组中存储信息。

```java
String list[] = new String[3];
list[0]= "one";
list[1] = "two";
```

一维数组的说明格式：

```java
int list[]//类型  数组名[]；
int[] list//类型[]  数组名；
```

数组的两种初始化方式：

- 像初始化简单类型一样自动初始化数组，即在说明数组的同时进行初始化；

```java
int a[] = {1, 2, 3, 4}
```

- 先定义数组，然后为每个元素赋值。例如：

```java
int b[] = new int[3];
b[0] = 8; b[1] = 9;
```

错误的形式：

```java
int[] a; a = {1, 2, 3, 4};
```

其他形式：

```java
int[] a = new int[]{1, 2, 3, 4};
int[] a;
a = new int[]{1, 2, 3, 4};
```


**- 二维数组 -**

二维数组说明的格式为：

```java
int intArray[][]; //类型  数组名[][]；
int[][] intArray; //类型[][]  数组名；
```

二维数组创建：

(1) 直接为每一维分配空间，如：

```java
int a[][] = new int[2][3];
```

(2) 从最高维开始，分别为每一维分配空间，如：

```java
int b[][]=new int[2][ ]; 
b[0]=new int[3]; 
b[1]=new int[5];         
```

元素的初始化：

(1) 直接对每个元素进行赋值。
(2) 在说明数组的同时进行初始化。 
```java
int a[][] = \{\{2, 3},{1, 5},{3, 4\}\} 
```


与数组操作相关的**系统函数**：

- 使用 **Arrays.sort** 来对数组排序

  ```java
  java.util.Arrays.sort(x);  
  ```

- 使用 **Arrays.binarySearch** 函数对数组进行二分查找

  ```java
  java.util.Arrays.sort(x); //二分查找，在数组 x 中查找 1，输出 0 
  System.out.println(java.util.Arrays.binarySearch(x, 1)); //如果没找到，则会输出一个 < 0 的数
  ```

- 使用 **System.arraycopy** 函数拷贝数组

  ```java
  int [] x; x = new int[]{3,1,2,4};
  int [] y; y = new int[4];
  System.arraycopy(x, 0, y, 0, 4);
  ```

- 使用 **Arrays.fill** 函数填充数组

  ```java
  int[] x = new int[]{3,1,2,4};
  java.util.Arrays.fill(x, 7);
  ```

## C4 ★ 面向对象

```
* 了解匿名类 内部类 
会用 会写监听器 事件编程
方法里的内部类 不可访问方法里的局部变量可以访问方法所属类中的变量

1.类的声明与定义
2.main方法  程序执行的入口  
3.Java 源文件的组成 一个公共类
4.类的成员变量与方法修饰符 缺省 st fi
5.成员方法的重载
6.构造方法和this的使用
7.★类的继承 Object extends 
8.super的使用 访问父类隐藏属性 构造方法
9.复杂类对象 子类对象和父类对象之间的相互转换 复杂类创建时的构造方法调用顺序 
10.抽象类和接口的使用
11.了解一下包 package import
12.参数传递 基本类型变量及引用类型在内存上的形式 Java全部为值传递
13.多个类中的多态
```

**- 类的声明与定义 -**

Java 是一种**纯对象化**的语言，所有的应用程序代码都必须以**类**构成，即使是程序的开始执行点，也必须包含在某个类中。 

```java
public class Sample{
    public static void main(String args[]) {
       …… //程序代码
    }
}
```

类的定义格式：

```java
[修饰符] class 类名 [extends父类名] [implements接口名列表]
{
          [成员变量说明]
          [构造方法说明]
          [静态初始化说明]
          [成员方法说明]
}；
```


- 修饰符

  - **缺省** (默认方式)   这种类只能被同一个包中的类访问；
  - **public** (公共)   它修饰的类能被所有的类访问；
  - **abstract** (抽象)  它修饰的类不能被实例化，它可能包含有未实现的方法。
  - **final** (最终)  它修饰的类不能被继承，即不能有子类。
  - **extends** (继承) 该保留字用来表明新创建的类继承哪个类, 被继承的类称为此类的父类。extends后面只能跟一个父类名称, 因为Java中一个类最多能继承一个类(**单继承**)。
  - **implements** (实现)  该保留字用来表明这个类实现了哪些接口，接口名可以有多个。


**- 成员变量 -**

```java
[修饰符] 成员变量类型 成员变量名列表;
```

访问权限修饰符: public protected private

public >protected > 缺省 > private 

![](/assets/images/move/2020-01-06-20-08-03.png)

访问修饰符:
- 访问修饰符缺省
  访问修饰符缺省时，成员变量只能被同一包(package) 中的所有类访问，所以也称为包(package)变量。缺省访问修饰符实际是 friendly 修饰符，但因为 friendly 不是 Java 语言的关键字，所以 friendly 修饰符不能显式说明。
- public(公共)
  public 修饰的成员变量可以被程序中的任何类所访问。由于 public 成员变量不受限制, 这易使类的对象引起不希望的修改，建议成员变量尽量不要使用 public 修饰符。
- protected (受保护)
  protected 修饰的成员变量可以被本包及有继承关系的类自由访问。
- private (私有)
  private 修饰的成员变量只能在同一个类中使用。这种方式通常是最为安全的。

关于访问权限修饰符的总结:

- 具有继承关系的子类可以继承父类的一些成员变量，即可以不创建对象就可以直接访问，如果是同一个包的子类可以继承到 public、 缺省和 protected 修饰的变量，如果是不同的包的子类就只能继承到public 和 protected 的；
- 如果是其他类，不管是一个包还是不在一个包，都要创建该类的对象才能引用
- 如果是 `main` 方法，不管是本类还是非本类，要访问实例变量都要创建对象，可以引申到其他所有的类方法中
- 私有成员只能在本类中访问，如果在 `main` 方法中访问私有成员 必须创建对象

**> static**

static 修饰的成员变量称为**类变量**(静态变量)；不用 static 修饰的成员变量又叫**对象变量**(实例变量)。

区别：对象变量依附于具体的对象实例，它的值因具体对象实例的不同而不同，而**类变量为该类的所有对象所共享，它的值不因类的对象不同而不同**。

可以通过类来访问静态成员变量，也可以通过该类的对象访问静态成员变量。

形式：**类名.成员变量/对象名.成员变量**。


**> final**

- final 定义的成员变量叫最终变量 —— java 中的**常量**
- 常量在说明以后就不能改变其值
- 无论是实例变量，还是类变量，都可以被说明成常量。final 修饰符和 static 修饰符并不冲突 


**- 成员方法 -**

首部说明：

```java
[方法修饰符] 返回值类型 方法名（[形参列表]）[ throws 异常列表]
```

方法修饰符：

- 访问：缺省、public、protected、private

- 非访问修饰符：static、abstract、final、native、synchronized


**类方法（静态方法）注意事项：**

- 在类方法中不能直接引用对象变量。
- 在类方法中不能使用 **super**、**this**关键字(super、this介绍见后)。
- 类方法不能直接调用类中的对象方法。



**- 父类对象与子类对象的转换 -**

Java 中父类对象和子类对象的转化需要遵循如下原则：

- 子类对象转为父类对象时，可以是显示的或隐式的，子类对象直接向父类对象赋值；

- 父类对象不能被任意的转换成某一子类的对象，只有父类对象指向的实际是一个子类对象，那么这个父类对象可以转换成子类对象，但此时必须用**强制类型转换**(`(类名) 类对象`)。

- 如果一个方法的形式参数定义的是父类对象，那么调用这个方法时，可以使用子类对象作为实际参数。


**- 接口 -**

接口定义了一些没有实现的方法和静态常量集，在 Java 面向对象程序设计中起着重用的作用：

- 使程序设计和实现相互分离

- 弥补 Java 只支持单重继承的不足

- 约束实现接口的类

接口和类的区别：

- 类只能单继承，而接口可以**多继承**。
- 类中的方法可以是具体的，也可以抽象的。 接口中的方法都是**抽象**的。
- 接口中的方法要用**类来实现**，一个类可以实现**多个接口**。


Java 接口反映了对象较高层次的抽象，**为描述相互似乎没有关系的对象的共性提供了一种有效的手段**。

接口的说明：

```java
[修饰符] interface 接口名[extends] [接口列表]
{
   接口体
}
public interface Cookable extends Foodable,Printable
```

修饰符：缺省（同包访问）、 public（任意访问）

接口体：定义**常量**和**抽象**方法

接口中的方法不能使用下面的修饰符：static、native、synchronized、final。

接口自己不能提供方法的实现，接口中的方法必须由类实现。Java 语言用关键字 `implements` 声明类中将实现的接口。声明接口的形式：

```java
[类修饰符] class类名 [extends 子句] [ implements 子句]
```

```java
interface Runner{ public void run();}
interface Swimmer{ public void swim();}
abstract class Animal {abstract public void eat();}

class Person extends Animal implements Runner,Swimmer {
//Person是能跑和游泳的动物，所以继承了Animal，同时实现了Runner和Swimmer两个接口
	public void run() {System.out.println("run");}
	public void swim(){System.out.println("swim");}
	public void eat(){System.out.println("eat");}
}
```

**多个类中的多态**：在具有继承关系的多个类中，子类对父类方法的覆盖（不能是重载父类的方法），即子类和父类可以有相同首部的方法，运行的时间决定每个对象到底执行哪个特定的版本。 

Java 支持**动态绑定**：能在运行期间判断参数的实际类型，并分别调用适当的方法体，从而实现了多态性。在 Java 中所有非 final 和非 static 的方法都会自动地进行动态绑定。


- 提高程序的扩展性；
- 大大提高了程序的抽象程度和简洁性；
- 最大限度地降低了类和程序模块之间的耦合性，提高了类模块的封闭性，使得它们不需了解对方的具体细节，就可以很好地共同工作。


**- 包 -**

包的作用：

- 包能够让程序员将类组织成单元，通过文件夹或目录来组织文件和应用程序；
- 包减少了名称冲突带来的问题，可以防止同名的类发生冲突；
- 包能够更大面积的保护类、变量和方法，而不是分别对每个类进行保护；
- 包可以用于标示类。

**编译和运行包中的类** 当程序中用 package 语句指明一个包，在编译时产生的字节码文件（.class文件）需要放到相应的以包名为名称的文件夹目录下：
- 手工建立子目录，以包名命名该目录，再将 .class 文件复制到相应目录下。
- 在编译时，使用 `javac –d` 命令。


**- 变量及其传递 -**

- **按值传递** 当将一个参数传递给一个函数时，函数接收的是原始值的一个副本。因此，如果函数修改了该参数，仅改变副本，而原始值保持不变。

- **按引用传递** 当将一个参数传递给一个函数时，函数接收的原始值的内存地址，而不是值的副本，因此，如果修改了该参数，调用代码中的原始值也随之改变

Java 中的参数传递比 C++ 简单，按值传递所有参数，制作所有参数的副本，而不管它们的类型。


引用型变量比较总结：

- 比较两个变量是否同一个对象（即对象引用值是否相同），用 `==` 和 `!=`
- 比较两个变量的内容是否相同用 `equals` 方法
- 自己定义的类如果要支持 equals 方法必须重写从 Object 类继承来的 equals 方法

Object 中的 equals 方法：

```java
public boolean equals(Object obj){
   return (this==obj);
}
```

**- 内部类 -**

内部类的定义: 将类的定义置入一个用于封装它的类（外部类）里...

**匿名类**: 类或方法中定义的一种**没有类名**的特殊内部类。

**作用**：当需要创建一个类的对象而且用不上它的名字时，使用内部类可以使代码看上去简洁清楚。

```java
new interfacename(){……}; / new superclassname(){……};
```

\> demo:

```java
interface Contents{int value();}
public class Goods4 {
    public Contents cont() { //返回匿名类对象，该匿名类继承了Contents接口
        return new Contents() {
            private int i = 11;
            public int value() { return i;}
        };
    }
    public static void main(String[] args) {
   	  Goods4 g = new Goods4();
   	  Contents c = g.cont();
    }
}
```

## C5 异常处理

```java
1.运行时异常与非运行时异常的区别(程序员/编译器)
2.会用 try catch finally 捕获异常
3.会用 throws 自定义抛出
```

**- 异常分类 -**

程序错误分类：编译错误（编译器）、运行错误（程序员）。

异常分类：**运行时异常(Runtime Exception)** 和 **非运行时异常**。

运行时异常是程序员编写程序不正确所导致的异常，理论上，程序员经过检查和测试可以查出这类错误。如除数为零等，错误的强制类型转换、数组越界访问、空引用。运行时异常不建议捕获，改正错误就好了。

- **运行时异常** 这些异常是**不检查异常**，程序中可以选择捕获处理，也可以不处理。这些异常一般是由程序逻辑错误引起的，程序应该从逻辑角度尽可能避免这类异常的发生。

- **非运行时异常(编译异常)** 从程序语法角度讲是必须进行处理的异常，如果不处理，程序就不能**编译通过**。如 IOException、SQLException 等以及用户自定义的 Exception 异常，一般情况下不自定义检查异常。

**- 捕获异常 -**

```java
try {}
catch (Exception e) {}
finally {} // finally 总是执行，可以为异常处理事件提供一个清理机制。
```

访问文件未找到 `FileNotFoundException`，将可能抛出一个或者若干个异常的代码放入 `try` 语句块中。

**> 执行过程:**

1. try 块中的语句没有产生异常。try -> finally -> 其他。

2. try 块内的语句产生了异常，且该异常在方法内捕获。try(到异常处) -> catch 子句 -> finally。

3. 如果在 catch 语句中又重新抛出了异常。try -> catch -> finally -> 将异常抛给方法的调用者。

**- 抛出异常 -**

除了捕获异常，还可以不捕获 —— 抛出异常，交给上层调用它的方法程序处理。

throws 在方法体头部声明，这样也可以使它的调用者必须考虑处理这些异常。

```java
public void function() throws Exception{......}
public static void function() throws NumberFormatException{......}
```

## C6 基本类库

```
1.java.lang.Object(echos toString)
2.java.lang.System in/out
3.java.lang.String
4.java.lang.StringBuffer
5.java.lang.Math random/sqrt/pow
6.常用的数据类型封装类 Intger.toString..
7.集合类 泛型 java.util.Vector
8.io包 FileInuputStream FileOutputStream File对象
9.字节流与字符流的转换
10.如何调用Buffer.reader Input/Output 如何转换 如何读 ★printStream printWriter
```

- **java.lang.Object** 整个类层次结构的根节点。

- **java.lang.Math** 提供数学常数及各种函数。

- **java.lang.Thread** 提供对多线程的支持。

- **java.lang.Throwable** 是所有异常的基类。

- **java.lang.String** 不可改变的静态字符串。

- **java.lang.StringBuffer** 动态可变字符串。

**- String 类 -**

所有字符串常量都是 String 对象，存储在 String Pool（字符串池）中，字符串池是常量池的一部分。

String 类对象一旦创建，其内容不可更改。若要更改，则必须创建一个新的 String 对象。

在比较字符串内容时，不能用 `==`，而应该用 `equals()` 方法。（`==` 比较地址值，`equals()` 方法比较实体值）

常用方法：

```java
String str = "hello";
System.out.println(substring(2));    //子串，llo
System.out.println(substring(2, 4));    //子串，ll，左闭右开
System.out.println(str.length());    //长度，5
System.out.println(str.charAt(1));    //某个字符，e
//字符数组转换为String
char[] s = {'a','b','c'};
String str = new String(s);
System.out.println(str);    //abc
//String转换为字符数组  toCharArray
String str = "abc";
char[] s = str.toCharArray();
//大小写转换
String s1 = "Hello";
System.out.println(s1.toUpperCase());    //HELLO
System.out.println(s1.toLowerCase());    //hello
```

**- StringBuffer 类 -**

- 3 种动态构造方法
  ```java
  StringBuffer sb = new StringBuffer();
  StringBuffer sb = new StringBuffer(int length);
  StringBuffer sb = new StringBuffer(String str);
  ```
- 更新

  ```java
  sb.append("java");   //hellojava
  sb.insert(5, "sun"); //hellosunjava
  sb.setCharAt(0, 'H'); //Hellosunjava
  sb.delete(5, 8);     //Hellojava
  ```

- 相互转换

  ```java
  StringBuffer sb = new StringBuffer("hello"); //String to StringBuffer: 直接用构造函数
  String s = sb.toString(); //StringBuffer 2 String: 用 toString()方法
  ```

**- Integer 类 -**

```java
String string = "123";
int a = Integer.parseInt(string); //将字符串转成 int：parseInt()方法
String aString = Integer.toString(a); //将 int 转成字符串：toString()方法
```

**- Math 类 -**

```java
// PI
double x = Math.PI;
// 三角函数
double y = Math.sin(3.14);
// pow 、sqrt
double x = Math.pow(double a, double b)
double x = Math.sqrt(double a) 
// 得到一个[0,1)之间的随机数
double c = Math.random();
// 得到一个[20,80)之间的随机整数
int c = (int)(Math.random()*60+20);
// 得到一个[500,600)之间的随机整数
int c = (int)(Math.random()*100+500);
// 舍入函数 double
double x = Math.ceil(double a); //向上取整
double x = Math.floor(double a); //向下取整
double x = Math.rint(double a); //四舍五入
// round() 四舍五入
int x = Math.round(float a);  // float -> int 
long x = Math.round(double a); //double -> long
```

**-  java.util.Vector 类 -**

向量与数组的异同：

- 都是类，均可保存列表。

- 数组一旦定义，空间长度不可变，而向量空间是**动态**的。

- 数组中既能存放基本数据类型，又能存放对象。而向量中**只能存储对象**，若要存储基本数据类型，可通过封装类如 Integer。

**> 构造函数**

```java
Vector() //默认大小10
Vector(int size) //指定大小
Vector(int size, int inc) //指定大小，指定增量
```

**> 创建向量**

```java
Vector<Integer> v = new Vector<Integer>(10); // <> 中的类型不能是基本数据类型。
```

**> 常用方法**

```java
v.add(x); //添加元素
v.removeElementAt(idx);  //删除元素
v.elementAt(idx); //查下标为 idx 的元素
v.indexOf(obg); //返回向量中obj的下标，若无，返回-1
v.setElement(onj,idx); //修改元素
v.insertElementAt(obj,idx); //在下标为 idx 位置插入元素 obj
v.contains(obj); //判断有无元素obj
v.clear(); //清空向量
System.out.println(v.size()); //实际元素个数
System.out.println(v.capacity()); //存储容量
```

**- java.io 包 -**

- **FileInputStream**(文件输入流)

```java
FileInputStream(File file)
FileInputStream(String path)
```

- **FileOutputStream**(文件输出流) 

```java
FileOutputStream(File file) //向 File 对象的文件写入数据
FileOutputStream(File file,boolean append); //向 File 对象的文件追加写入数据
FileOutputStream(String path) // 向指定文件写入数据
FileOutputStream(String path, boolean append); //向指定文件追加写入数据
```

**- 重写 equals() 方法 -**

```java
class Person {
    String name;
    int age;
    Person(String name, int age) {
        this.name = name;
        this.age = age;
    }
    public boolean equals(Object obj) {
        if(obj == null) return false; // null 判断不为空
        if(this == obj) return true; // 是否为同一个对象
        if(this.getClass() != obj.getClass()) return false; //类名是否相同
        Person person = (Person)obj; //强制转化为同类
        return name.equals(person.name) && age == person.age;
    }
}
public class Test {
    public static void main(String[] args) {
        Person aPerson = new Person("Wang", 20);
        Person bPerson = new Person("Wang", 20);
        System.out.println(aPerson == bPerson); // return false
        System.out.println(aPerson.equals(bPerson)); // return true
    }
}
```

对 `equals()` 方法的设计要求：

1. **对称性** 如果 x.equals(y) 返回是 `true`，那么 y.equals(x) 也应该返回是 `true`。
2. **反射性** x.equals(x) 必须返回是 `true`。
3. **类推性** 如果 x.equals(y) 返回是 `true`，而且 y.equals(z) 返回是 `true`，那么 z.equals(x) 也应该返回是`true`。
4. **一致性** 如果 x.equals(y) 返回是 `true`，只要 x 和 y 内容一直不变，x.equals(y) 返回永远为 `true`。
5. **非空性** x.equals(null)，永远返回是 `false`；x.equals (和 x 不同类型的对象)永远返回是 `false`。



## C7 图形界面

```
1.会编写简单的窗体程序
2.面板和窗体的默认布局管理器
3.如何设置窗体和窗体上组建的大小位置背景色前景色
4.掌握两种布局管理器 flowlayout borderlayout sendlayout
5.常用组件: 按钮 文本框 标签 标签和文本框的区别
6.★事件处理 
事件源 事件监听器 事件处理函数 及绑定
按钮的动作事件 ActionListener
7.画图 覆盖 paint 方法 repaint smail->cry
```

两个包：

```java
import java.awt.*;
import javax.swing.*;
```

最后一定要：

```java
frame.setVisible(true);
```

为关闭窗体添加事件，使用匿名类，重载 `public void windowClosing(WindowEvent e)` 方法：

```java
this.addWindowListener(new WindowAdapter(){
    public void windowClosing(WindowEvent e){
        System.exit(0);
    } 
});
```

两种布局模式：

- `BorderLayout` **边界布局**是一个布置容器的边框布局，它可以对容器组件进行安排，并调整其大小，使其符合下列五个区域：北、南、东、西、中，每个区域最多只能包含一个组件。

- `FlowLayout` **顺序布局**将组件从左到右依次排列，一行排满就转到下一行继续排列，直到所有的组件都排列完毕。




### Frame / JFrame

Frame(JFrame) 类用于创建带有**菜单条的全功能窗口对象**,为窗口、面板等组件提供框架，它可以包含**窗口标题、最大化、最小化和关闭窗口**等按钮,通常是 GUI 应用程序窗口的顶层容器组件。
Frame 类的对象开始是不可见的，要调用 `show()` 方法 (或 `setVisible(true)` 方法) 才能显示出来，也可以调用 `hide()`方法将其隐藏。框架对象被创建后就可使用 `add()` 方法将其它组件加入到框架中。两种**构造方法**：

```java
Frame()        创建一个不带标题的框架
Frame(String)  创建一个带标题的框架
```

**Frame 和 Dialog 是 Window 的子类，它们都是窗口类，默认的布局管理器都是** `BorderLayout`。

**> 常用方法**:

```java
show() //显示框架
setVisible(boolean b) //使框架可见/不可见(true/false)
hide() //隐藏框架
setTitle() //设置框架的标题
setSize(int w, int h) //调整框架的尺寸(宽/高为w/h)
setBounds(int x, int y, int w,int h) //调整框架的位置及尺寸(左上角为(x,y), 宽、高为w、h)
add(Component ob) //将其它组件 ob 加入到框架的中心位置 
add(String p, Component ob) //将组件 ob 加入到框架的 p 位置 
// 框架默认的布局方式是 BorderLayout,  它将容器划分为东 East 西 West 南 South 北 North 中 Center
setLayout(new FlowLayout()); //设置布局管理器
```

**> FrameDemo3.java**

```java
import java.awt.*;
import javax.swing.*;
public class  JFrameDemo {
    public static void main(String args[]) {
        JFrame f = new  JFrame("简单框架"); //创建框架
        Container c = f.getContentPane(); //获取内容面板 
        c.setLayout(new FlowLayout());
        JButton btn = new JButton("Button1"); //创建一个按钮
        c.add(btn);  //将按钮加入面板中
        f.setSize(160,100) ; //修改框架尺寸
        f.show(); //显示框架
    }
}
```

### Dialog / JDialog

对话框类 Dialog (JDialog) 的对象是**有标题条而无菜单条和最小化按钮图标的容器组件**，它必须依附在某个窗口上(如Frame), 一旦它所依附的窗口关闭了, 对话框也**自动关闭**。

对话框默认的布局是 `BorderLayout`。同框架类一样, 要调用 show() 方法显示才可见, 调用 hide() 方法可将其隐藏。

对话框通常用于在应用程序中弹出一个窗口, 用于提示输入数据、保存文件等。

有两种模式的对话框:

- 响应模式: 对话框出现期间，所依附窗口不接收任何操作。
- 非响应模式: 对话框出现时, 与所依附窗口都可同时接收操作。


构造方法：

```java
Dialog(Frame) //创建依附于 Frame 的无模式对话框
Dialog(Frame, boolean) //创建对话框, 并由布尔值的真假决定此对话框有无模式
Dialog(Frame, String) //创建无模式对话框，并给定对话框的标题
Dialog(Frame, String, boolean) //创建对话框, 指出是否有模式, 并给定对话框的标题 
```

**> DialogDemo.java**

![](/assets/images/move/2020-01-07-09-57-34.png)

```java
import java.awt.*;
public class DialogDemo {
    public static void main(String args[]) {
        Frame frm1 = new Frame();
        Dialog Dialog1 = new Dialog(frm1, "myDialog");
        Button b1 = new Button("按钮1"), b2 = new Button("按钮2");
        Button b3 = new Button("按钮3"), b4 = new Button("按钮4");
        Button b5 = new Button("按钮5");
        Dialog1.add(b1);
        Dialog1.add("North",b2);  Dialog1.add("South",b3);
        Dialog1.add("East",b4);     Dialog1.add("West",b5);
        Dialog1.setVisible(true);    //功能等同于show(),让对话框显示
    }
}
```

### Panel / Jpanel

面板 `panel`(Jpanel) 是能在屏幕上实际显示的组件，提供了容纳其他组件的功能，但本身必须放在 **Window, Frame, Dialog** 等容器中才能使用。所有面板的默认的布局管理器是 `FlowLayout`, 即按照**从左至右、从上到下**的方式布局.

面板提供容纳其他组件的功能，利用面板可以把控件分组，使整个窗口的组件显得有层次，安排合理布局，`java.applet.Applet` 是 `java.awt.panel` 的子类。

**> UsePanel.java**

![](/assets/images/move/2020-01-07-10-06-30.png)

```java
import java.awt.*;
public class UsePanel extends Frame {
    public static void main(String args[]) {
        UsePanel frm = new UsePanel(); //创建UsePanel类的对象
        //注：UsePanel 是个框架类，所以创建该类的对象就是创建一个框架对象 
        frm.setLayout(new FlowLayout()); 
        Panel  panel1 = new Panel(); // 创建一个面板对象
        Panel  panel2 = new Panel();
        frm.add(panel1);  frm.add(panel2);
        panel1.add(new Button("left"));
        panel1.add(new Button("right")); 
        panel1.setBackground(Color.lightGray);   //为能看清面板, 
        panel2.setBackground(Color.yellow);      //这里修改面板
        panel2.add(new Button("Panel2"));        //的背景颜色
        frm.pack();
        frm.show();
    }
}
```

设置背景色及前景色：

```java
JPanel b = new JPanel();
b.setBackground(Color.RED);   //背景色
b.setForeground(Color.BLUE);  //前景色
```

### 常用组件

常用基本组件：

![](/assets/images/move/2020-01-07-09-36-15.png)

三个考试中重要的组件:

- **JButton**、 **JTextField**、 **JLabel**

**> JButton**

构造方法：

```java
JButton()
JButton(String)
```

常用方法：

```java
setLable(String t) //设置按钮标志
setText("hello")
addACtionListener(ActionListener 1) //将1指定为按钮的事件监听者
```

**> ButtonDemo.java**

![](/assets/images/move/2020-01-07-10-17-35.png)

```java
import java.awt.*;
public class ButtonDemo extends Frame {
    public static void main(String args[]) {
        ButtonDemo frm = new ButtonDemo();
        frm.setLayout(new FlowLayout()); 
        frm.setTitle("按钮的创建");
        Button b1 = new Button(), b2;   //定义二个按钮
        b2 = new Button("Button2");    //实例化按钮对象
        b1.setLabel("Button1");
        frm.add(b1);                       //将按钮加入窗口中
        frm.add(b2);
        b2.setEnabled(false);
        frm.show();
    }
}
```

**> JLabel**

标签(Label)是一种只能用来显示单行文本的组件。

标签在容器中的对齐方式有三种：左对齐、居中和右对齐, 用 `Label.LEFT`、`Label.CENTER`、`Label.RIGHT` 三个静态常量表示，在程序中可以设置其对齐方式。

构造方法：

- `JLabel()` 空标签
- `JLabel(String text)` 带有指定文本的标签
- `JLabel(String text, int alignment)` 带有指定文本和在容器中的对齐方式的标签

常用方法：

```java
getAlignment() //获取对齐方式
getText() //获取文本
setAlignment(int aligmnent) //设置对齐方式
setText(String text) //设置文本 
```


**> JTextField**

文本框(TextField)和多行文本区域(TextArea)是用来显示和输入文本的控件，它们都是 TextComponent 的子类。

构造方法：

```java
TextField() //创建一个空的文本框
TextField(Strint text) //创建一个带有初始文本的文本框
TextField(int Columns) //创建一个指定列数的文本框
TextField(String text, int Colulmns) //创建一个指定列数和带有初始文本的文本框 
```

常用方法：

```java
setText(String s) //设置文本框中的字符串
getText(String s) //获得文本框中的字符串
addActionListener(ActionListener 1) //指定1为文本框的事件监听者
setEchoChar(String s) //设置用户输入的回应字符,输入密码时可设置为*
```

### ★ 事件处理

![](/assets/images/move/2020-01-07-10-36-38.png)

- **事件源**是一个事件的产生者。

- **事件对象**是图形组件产生的事件。
    ```java
    ComponentEvent（组件事件：组件尺寸的变化，移动） 
    ContainerEvent（容器事件：组件增加，移动） 
    WindowEvent（窗口事件：关闭窗口，窗口闭合，图标化） 
    FocusEvent（焦点事件：焦点的获得和丢失） 
    KeyEvent（键盘事件：键按下、释放） 
    MouseEvent（鼠标事件：鼠标单击，移动）
    ActionEvent（动作事件：按钮按下，TextField中按Enter键） 
    AdjustmentEvent（调节事件：在滚动条上移动滑块以调节数值） 
    ItemEvent（项目事件：选择项目，不选择"项目改变"） 
    TextEvent（文本事件：文本对象改变）
    ```
- **事件监听器**就是一个接收事件、解释事件并处理用户交互的方法。

常用事件监听器的添加方法：

```java
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
public class Test extends JFrame {
    public void paint(Graphics g) {
        g.setColor(Color.RED);
        g.drawOval(x,y,w,h);
        g.drawRect(x,y,w,h)；//矩形
    }
    public static void main(String[] args) {
        Test frame = new Test();
        Test.setTitle("Test");
        Test.setSize(500, 500);
        JButton btn = new JButton("btn1");
        btn.addActionListener(new ActionListener(){ //匿名类
            public void actionPerformed(ActionEvent e) {
                repaint();
            }
        });
        Test.addWindowListener(new WindowAdapter(){
            public void windowClosing(WinodwEvent e) {
                System.exit(0);
            } 
        });
        Test.setVisible(true);
    }
}
```

## C9 多线程★

```
1.创建线程类的两种方法以及创建对象的方法
继承 Thread 类 / Runerable 接口 / 课件例子
2. synchronized wait notify
```

两种方式：

- 继承 Thread ，覆盖 `run()`
- 实现 Runnable ，实现 `run()`


```java
class myThread extends Thread {
    public void run() {
        //code
    }
}
class myThread2 implements Runnable {
    public void run() {
        //code
    }
}
```

开始线程用 `start()` 方法：

```java
MyThread thread = new MyThread();
thread.start();
```

实现互斥使用修饰符 `synchronized`：

```java
public synchronized void methodName(..){}
```

线程的生命周期：


1. 创建状态：`Thread myThread = new MyThreadClass();`
2. 可运行状态：分配资源
3. 不可运行状态：
   - 调用`sleep()`方法   --> 等待
   - 调用`suspend()`方法   -->调用`resume()`方法
   - 调用`wait()`方法   -->调用`notifyAll()`方法
   - 输入输出流发生阻塞   -->等待
   - 线程试图调用另一个对象的同步方法   -->等待释放同步锁
4. 死亡状态：
   - 自然撤销
   - 调用`stop()`方法停止当前线程 ，一般不用.

- wait / notify

`wait`导致当前线程等待，直到另一个线程调用该对象的 `notify()` 方法

`notify`唤醒正在等待对象监视器的单个线程。

`wait` 和 `notify` 必须配合 `synchronized` 使用，`wait` 在 `notify` 前用。


```java
import javax.swing.*;
import java.awt.*;
import java.util.*;
public mythread extends Thread {
   JLabel j1 = new JLabel("label1");
   JLabel j2 = new JLabel("label2");
   mythread(){}
   public void run(){
        try{
            sleep(1000);
            j1.setLocation(j1.getX() + 10, j1.getY());
            j2.setLocation(j1.getX(), j1.getY() + 10);
        } catch(InterruptedException e) {
          System.out.println(e.toString());
        }
   }
}
public class Test extends JFrame{
   public static void main(String[] args){
      Test f = new Test();
      f.setTitle("thread");
      f.setVisible(true);
      JButton b = new JButton("start");
      f.add(b);
      b.addActionListener(new actionListener(){
         public void actionPerformed(ActionEvent e){
            mythread t1 = new mythread();
            mythread t2 = new mythread();
            t1.start();
            t2.start();
         }
      });
   }
}
```

## C10 网络编程

```
1.基于 TCP 的 clinet server 怎么写
```

**- 基于 TCP 的 Socket 通讯实现 -**

![](/assets/images/move/2020-01-07-11-06-05.png)

- `Server` 一直运行，不断监听客户端的连接

    - 创建 `ServerSocket` 对象，指定服务器监听的端口号；
    - 调用以上建立服务器套接口对象的 `accept` 方法等待客户的连接；
    - 一旦有客户送来正确请求，就连接到端口，accept 方法返回一个新的套接口对象（Socket 类对象）；
    - 获取该返回对象绑定的输入**输出流对象**，实现和客户的**通信**

```java
import java.io.*;
import java.net.*;
public class Tcpserver { 
    public static void main(String args[]) throws IOException {
        ServerSocket svrsoc = null;
        Socket soc = null;
        BufferedReader in = null;
        PrintWriter out = null;
        InetAddress clientIP = null;
        String str = null;
        try { 
            svrsoc=new ServerSocket(8000); //构造ServerSocket对象，端口为8000
            System.out.println("Wait for.......");
            soc=svrsoc.accept(); //服务端等待一个连接，返回新套接口soc
            in=new DataInputStream(soc.getInputStream()) //在新套接口soc上构造BufferedReader对象
            out=new PrintStream(soc.getOutputStream()); //新套接口soc上构造PrintWriter对象
            clientIP=soc.getInetAddress(); 
            System.out.println("Client's IP address:"+clientIP);
            out.println("Welcome!...");
            str=in.readLine(); //在in上读一行
            while(!str.equals("quit")) { //如读出的不是"quit",继续读 
                System.out.println("Client said:"+str);
                str=in.readLine(); //out.println(str); 
            }
            System.out.println("Client want to leave.")
        } catch(Exception e) {
            System.out.println("Error:"+e);
        } finally {
            in.close();
            out.close();
            soc.close();
            svrsoc.close();
       }
    }
}
```

- `Client` 
    - 创建一个 Socket 类对象，指定所要连接服务器的 IP 地址和端口（服务器接受连接，该对象就建立）；
    - 获得该 Socket 对象绑定的输入输出流，实现和服务器的通信。

```java
import java.net.*;
import java.io.*;
public class TcpClient {
    static void clear(byte[] b) {
        for(int i = 0; i < b.length; i++)
            b[i] = 0;
    }
    public static void main(String args[])  throws IOException {
        Socket soc = null;
        BufferedReader in = null;
        PrintWriter out = null;
        String strin = null;
        String strout = null;
        try {
            soc = new Socket("localhost", 8000);
            System.out.println("Connecting to the Server...");
            in = new BufferedReader(new InputStreamReader(soc.getInputStream()));
            out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(
                    soc.getOutputStream())), true);
            strin = in.readLine();
            System.out.println("Server said:"+strin);
            byte bmsg[] = new byte[20];
            System.in.read(bmsg);
            String msg = new String(bmsg);
            msg = msg.trim();
            ouSt.println(msg);
            while(!msg.equals("quit")) {
                clear(bmsg);
                System.in.read(bmsg);
                msg=new String(bmsg);
                msg=msg.trim();
                out.println(msg);
            }
        } catch (Exception e) { 
            System.out.println("Error: " + e);
        } finally {
            in.close();
            out.close();
            soc.close();
            System.exit(0);
        }
    }
}
```

**----- 附录代码 -----**

**- 简单排序 -**

```java
import java.util.*;
public class Test{
   public static void main(String[] args){
      int[] a = new int[10];
      Scanner scan = new Scanner(System.in);
      for(int i = 0;i < 10;i++){
         a[i] = scan.nextInt();
      }
      Arrays.sort(a);
      for(int i = 0;i < 10;i++){
         System.out.print(a[i]+" ");
      }
   }
}
```



**- 复数类 -**

```java
import java.util.*;
public class Complex{
   public int realPart;
   public int maginPart;
   public Complex(){
      this.realPart = 0;
      this.maginPart = 0;
   }
   public Complex(int r,int i){
      this.realPart = r;
      this.maginPart = i;
   }
   public String toString(){
      return this.realPart+"+"+this.maginPart+"i";
   }
   public static Complex complexAdd(Complex a){
      return new Complex(this.realPart + a.realPart,this.maginPart + a.maginPart);
   }
   public static Complex complexSub(Complex a){
      return new Complex(this.realPart - a.realPart,this.maginPart - a.maginPart);
   }
   public static void main(String[] args){
      Scanner scan = new Scanner(System.in);
      Complex a1 = new Complex(scan.nextInt,scan.nextInt);
      Complex a2 = new Complex(scan.nextInt,scan.nextInt);
      System.out.println("a1:"+a1.toString());
      System.out.println("a2:"+a2.toString());
      System.out.println("a1+a2="+a1.Add(a2).toString());
      System.out.println("a1-a2="+a1.Sub(a2).toString());
   }
}
```



**- 加法器 -**

```java
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
public class jiafaqi extends JFrame{
   public static void main(String[] args){
      jiafaqi j = new jiafaqi();
      j.setTitle("加法器");
      JTextField shu1 = new JTextField(5);
      JTextField shu2 = new JTextField(5);
      JTextField result = new JTexField(5);
      JButton jia = new JButton("+");
      JButton jian = new JButton("-");
      j.add(shu1); //添加组件
      j.add(shu2);
      j.add(jia);
      j.add(jian);
      j.add(result);
      j.setLocation(300,300);
      j.setSize(500,100);                             //事件监听器 匿名类
      jia.addActionListener(new ActionListener(){
         public void actionPeformed(ActionEvent e){
            int x = Integer.parseInt(shu1.getText());
            int y = Integer.parseInt(shu2.getText());
            int z = x + y;
            result.setText(Integer.toString(z));
         }
      });
      jian.addActionListener(new ActionListener(){
         public void actionPeformed(ActionEvent e){
            int x = Integer.parseInt(shu1.getText());
            int y = Integer.parseInt(shu2.getText());
            int z = x - y;
            result.serText(Integer.toString(z));
         }
      });
      f.setVisible(true); //别忘了这个
   }
}
```



**- 变脸 -**

\> 利用事件处理程序mouseUp()实现程序运行后出现一张笑脸，鼠标点击一次则变成哭脸，再点击一次又变成笑脸，依次轮换

```java
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
public class Test extends JFrame{
   static int m = 0;
   public static void main(String[] args){
      Test f = new Test();
      f.setTitle("变脸");
      f.setSize(300,300);
      f.setVisible(true);
      f.addMouseListener(new MouseAdapter(){    //鼠标的点击事件
         public void mouseClicked(MouseEvent e){
            f.reprint();
         }
      });
   }
   public void paint(Graphics g){
      if(m++%2==1){
         super.paint(g); //消除之前画的
         g.getColor(Color.blue);
         g.drawString("哭！",80,60);
         g.drawOval(100,50,120,160);
         g.drawArc(170,90,30,30,0,-180);
         g.drawArc(120,90,30,30,0,-180);
         g.drawArc(120,150,80,80,20,140);
      }
      else{
         super.paint(g); //消除之前画的
         g.getColor(Color.blue);
         g.drawString("笑！",80,60);
         g.drawOval(100,50,120,160);
         g.drawArc(170,90,30,30,0,180);
         g.drawArc(120,90,30,30,0,180);
         g.drawArc(120,150,80,80,-20,-140);         
      }
   }
}
```



**- GUI多线程 -**

\> 编写一个图形用户界面程序，窗体的宽度300，高度150，布局管理器为null，窗体上有二个标签和二个按钮，标签的位置为（10,30）和（200,60），按钮的位置为（50,100）和（150,100），它们的宽度和高度都是80和20。编写一个线程，该线程可以让标签向右或向左移动10次，每次移动10个单位，间隔1秒，通过按钮的动作事件启动上述线程，“向右走”按钮启动“向右移标签”，“向左走”按钮启动“向左移标签

```java
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
public class Test extends Thread{
   JLabel l1,l2;
   static boolean bool;
   public Test(JLabel l1,Jlabel l2){
      this.l1 = l1;
      this.l2 = l2;
   }
   public void run(){
      if(bool==true){
         try{
            for(int i=0;i<10;i++){
               l1.setBounds(l1.getX()+10,30,80,80);
               Thread.sleep(1000);
            }
         }catch(Exception e){System.out.println(e.toString());}
      }
      else{
         try{
            for(int i=0;i<10;i++){
               l1.setBounds(l2.getX()-10,60,80,80);
               Thread.sleep(1000);
            }
         }catch(Exception e){System.out.println(e.toString());}         
      }
   }
   public static void main(String[] args){
      JFrame f = new JFrame();
      f.setSize(300,200);
      f.setVisible(true);
      f.setLayout(null);
      JLabel l1 = new JLabel("右移");
      JLabel l2 = new JLabel("左移");
      l1.setBounds(10,30,80,20);
      l2.setBounds(200,60,80,20);
      f.add(l1);
      f.add(l2);
      JButton b1 = new JButton("右");
      JButton b2 = new JButton("左");
      f.add(b1);
      f.add(b2);
      Test t1 = new Test(l1,l2);
      Test t2 = new Test(l1,l2);
      b1.addActionListener(new ActionListener(){
         public void actionPerformed(ActionEvent e){
            bool = true;
            t1.start();
         }
      });
      b2.addActionListener(new ActionListener(){
         public void actionPerformed(ActionEvent e){
            bool = false;
            t2.start();
         }
      });
   }
}
```




