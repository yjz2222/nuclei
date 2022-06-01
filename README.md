# MyPoc接口文档

测试环境地址前缀为`http://10.10.30.183:8822`

以下接口地址 ***除了登录相关接口*** 以外，其他接口均需接前缀`/api/v1`使用，如接口地址`/templates`,则实际请求地址为`http://10.10.30.183:8822/api/v1/templates`

> 所有接口均返回json形式

> 除了登录相关接口以外的其他接口，均需在请求头部添加`Authorization`字段，值的表现形式为`Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.Z3971_pDFwjtPKRv6g-9buQU03ZuEBTXZ-QSKD3n6wM`;
> 其中`Bearer`为固定值，***Bearer和token之间有一个空格***，参考[RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750)，`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.Z3971_pDFwjtPKRv6g-9buQU03ZuEBTXZ-QSKD3n6wM`为登录成功后返回的token

---

## 登录相关接口

**此部分接口直接使用URL前缀到端口部分，即`http://10.10.30.183:8822/login`和`http://10.10.30.183:8822/modPwd`**

---

### 1. 用户登录

- 请求方式：`POST`
- 接口地址：`/login`
- 请求类型：`application/json`

> 请求示例：

```
{
    "user_name": "admin",
    "password": "123456"
}
```

> 返回示例：成功后返回token，否则状态码不等于200

```
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.Z3971_pDFwjtPKRv6g-9buQU03ZuEBTXZ-QSKD3n6wM"
}
```


### 2. 修改密码

- 请求方式：`POST`
- 接口地址：`/modPwd`
- 请求类型：`application/json`

> 请求示例：

```
{
    "user_name": "admin",
    "password": "123456",   //原密码
    "new_pwd": "654321"      //新密码
}
```

> 返回示例：根据状态码是否等于200判断是否修改成功，成功后不返回数据，只响应200状态码


---

## 模板相关接口

---

### 1. 获取模板

- 请求方式：`GET`
- 接口地址：`/templates`

|  参数名   |   类型   | 说明             | 示例       |
|:------:|:------:|:---------------|:---------|
|  page  |  int   | 页码，默认0，表示第一页   | 12       |
|  size  |  int   | 每页显示数量，默认每页10条 | 20       |
| folder | string | 所属文件夹，可以理解为分类  | nuclei   |
| search | string | 搜索关键字          | http-xxx |

> 返回示例：

```
{
    "total": 3606,
    "data": [
        {
            "id": 3634,
            "name": "dotnetcms-sqli.yaml",
            "folder": "nuclei-templates",
            "path": "vulnerabilities/other/dotnetcms-sqli.yaml",
            "createdAt": "2022-05-31T14:45:46.330285+08:00",
            "updatedAt": "2022-05-31T00:00:00Z"
        },
        {
            "id": 3633,
            "name": "phppgadmin-version.yaml",
            "folder": "nuclei-templates",
            "path": "technologies/phppgadmin-version.yaml",
            "createdAt": "2022-05-31T14:45:46.308767+08:00",
            "updatedAt": "2022-05-31T00:00:00Z"
        },
        {
            "id": 3632,
            "name": "unifi-panel.yaml",
            "folder": "nuclei-templates",
            "path": "exposed-panels/unifi-panel.yaml",
            "createdAt": "2022-05-31T14:45:46.223613+08:00",
            "updatedAt": "2022-05-31T00:00:00Z"
        },
        {
            "id": 3631,
            "name": "seafile-panel.yaml",
            "folder": "nuclei-templates",
            "path": "exposed-panels/seafile-panel.yaml",
            "createdAt": "2022-05-31T14:45:46.220945+08:00",
            "updatedAt": "2022-05-31T00:00:00Z"
        },
        {
            "id": 3630,
            "name": "CVE-2022-24900.yaml",
            "folder": "nuclei-templates",
            "path": "cves/2022/CVE-2022-24900.yaml",
            "createdAt": "2022-05-31T14:45:46.201543+08:00",
            "updatedAt": "2022-05-31T00:00:00Z"
        },
        {
            "id": 3629,
            "name": "CVE-2022-22972.yaml",
            "folder": "nuclei-templates",
            "path": "cves/2022/CVE-2022-22972.yaml",
            "createdAt": "2022-05-31T14:45:46.199588+08:00",
            "updatedAt": "2022-05-31T00:00:00Z"
        },
        {
            "id": 3628,
            "name": "CVE-2022-0776.yaml",
            "folder": "nuclei-templates",
            "path": "cves/2022/CVE-2022-0776.yaml",
            "createdAt": "2022-05-31T14:45:46.196224+08:00",
            "updatedAt": "2022-05-31T00:00:00Z"
        },
        {
            "id": 3627,
            "name": "CVE-2019-12583.yaml",
            "folder": "nuclei-templates",
            "path": "cves/2019/CVE-2019-12583.yaml",
            "createdAt": "2022-05-31T14:45:46.142653+08:00",
            "updatedAt": "2022-05-31T00:00:00Z"
        },
        {
            "id": 3626,
            "name": "CVE-2019-12581.yaml",
            "folder": "nuclei-templates",
            "path": "cves/2019/CVE-2019-12581.yaml",
            "createdAt": "2022-05-31T14:45:46.140388+08:00",
            "updatedAt": "2022-05-31T00:00:00Z"
        },
        {
            "id": 3625,
            "name": "ait-csv-import-export-rce.yaml",
            "folder": "nuclei-templates",
            "path": "vulnerabilities/wordpress/ait-csv-import-export-rce.yaml",
            "createdAt": "2022-05-29T18:24:21.526848+08:00",
            "updatedAt": "2022-05-29T00:00:00Z"
        }
    ]
}
```

### 2. 新增模板

- 请求方式：`POST`
- 接口地址：`/templates`
- 请求类型：`application/json`

> 请求示例：其中path为模板的自定义路径，具有唯一性

```
{
  "contents": "这里是yaml文件内容的字符串",
  "folder": "my-templates",
  "path": "my/2022/my2022-1-1.yaml"
}
```

> 返回示例：返回新增后入库后的模板ID

```
{
  "id": 121
}
```

### 3. 更新模板

- 请求方式：`PUT`
- 接口地址：`/templates`
- 请求类型：`application/json`

> 请求示例：

```
{
  "contents": "这里是更新后的yaml文件内容的字符串",
  "path": "my/2022/my2022-1-1.yaml"
}
```

> 返回示例：此接口成功后无返回数据，只有出错后才有返回，判断是否返回错误即可

```
{
  "message": "could not parse template: no template name field provided",
  "error": "code=400, message=could not parse template: no template name field provided"
}
```

### 4. 删除模板

- 请求方式：`DELETE`
- 接口地址：`/templates`
- 请求类型：`application/json`

> 请求示例：

```
{
  "path": "my/2022/my2022-1-1.yaml"
}
```

> 返回示例：此接口成功后无返回数据，只有出错后才有返回，判断是否返回错误即可

```
{
  "message": "could not parse template: no template name field provided",
  "error": "code=400, message=could not parse template: no template name field provided"
}
```

### 5. 获取模板原始内容

- 请求方式：`GET`
- 接口地址：`/templates/raw`

| 参数名  |   类型   | 说明      | 示例                           |
|:----:|:------:|:--------|:-----------------------------|
| path | string | 模板自定义路径 | test/CVE-2022-0378test2.yaml |


> 返回示例：

```
id: CVE-2022-0378test2

info:
  name: Microweber Reflected Cross-Site Scripting
  author: pikpikcu
  severity: medium
  description: Microweber contains a reflected cross-site scripting in Packagist microweber/microweber prior to 1.2.11.
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2022-0378
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N
    cvss-score: 5.4
    cve-id: CVE-2022-0378
    cwe-id: CWE-79
  metadata:
    shodan-query: http.favicon.hash:780351152
  tags: cve,cve2022,microweber,xss

requests:
  - method: GET
    path:
      - '{{BaseURL}}/module/?module=admin%2Fmodules%2Fmanage&id=test%22+onmousemove%3dalert(document.domain)+xx=%22test&from_url=x'

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        part: body
        words:
          - 'mwui_init'
          - 'onmousemove="alert(document.domain)'
        condition: and

# Enhanced by mp on 2022/02/28
```

### 6. 执行单个模板

- 请求方式：`POST`
- 接口地址：`/templates/execute`
- 请求类型：`application/json`

> 请求示例：

```
{
  "path": "misconfiguration/http-missing-security-headers.yaml",
  "target": "https://www.baidu.com"
}
```

> 返回示例：返回的太大了。。。可以自己用请求示例里的两个参数去请求一下，然后查看返回的数据结构

## 目标相关接口

---

### 1. 获取目标

- 请求方式：`GET`
- 接口地址：`/targets`

|  参数名   |   类型   | 说明             | 示例  |
|:------:|:------:|:---------------|:----|
|  page  |  int   | 页码，默认0，表示第一页   | 12  |
|  size  |  int   | 每页显示数量，默认每页10条 | 20  |
| search | string | 搜索关键字          | myT |

> 返回示例：

```
[
    {
        "id": 1,
        "name": "myTargets1",
        "internalId": "b18922ae-1370-4dce-a4dc-77228eb5411d",
        "filename": "targets/my1",
        "total": 4,
        "createdAt": "2022-05-12T16:24:25.596047+08:00",
        "updatedAt": "2022-05-12T16:24:25.596047+08:00"
    }
]
```

### 2. 新增目标集

- 请求方式：`POST`
- 接口地址：`/targets`
- 请求类型：`form`

> 请求示例：其中path为目标文件的自定义路径，具有唯一性

|   参数名    |   类型   | 说明            | 示例              |
|:--------:|:------:|:--------------|:----------------|
|   path   | string | 页码，默认0，表示第一页  | myTargets/myTs1 |
|   name   | string | 目标集名称         | myTargets1      |
| contents |  file  | 按行分割的目标地址集合文件 | targets.txt     |

> 返回示例：返回新增后入库后的目标集ID

```
{
  "id": 121
}
```

### 3. 修改目标集

- 请求方式：`PUT`
- 接口地址：`/targets/:id`
- 请求类型：`form`

> 请求示例：需要修改的目标集的id直接替换接口地址里的`:id`，如需修改id为1的目标集合，
> 则请求地址为`http://10.10.30.183:8822/api/v1/targets/1`

|   参数名    |   类型   | 说明            | 示例          |
|:--------:|:------:|:--------------|:------------|
| contents |  file  | 按行分割的目标地址集合文件 | targets.txt |

> 返回示例：此接口成功后无返回数据，只有出错后才有返回，判断是否返回错误即可

> **此接口为追加模式，并非覆盖，即当前已入库目标集+本次请求的contents内目标**

### 4. 删除目标集

- 请求方式：`DELETE`
- 接口地址：`/targets/:id`

> 直接替换`:id`为需要删除的目标集合ID即可

> 返回示例：此接口成功后无返回数据，只有出错后才有返回，判断是否返回错误即可

### 5. 查看目标集内容

- 请求方式：`GET`
- 接口地址：`/targets/:id`

> 直接替换`:id`为需要查看的目标集合ID即可

> 返回示例：直接返回text文本信息`Content-Type=text/plain; charset=utf-8`

```
https://www.baidu.com
https://www.163.com
https://www.bilibili.com
```

## 配置相关接口

---

### 1. 获取settings

- 请求方式：`GET`
- 接口地址：`/settings`

> 返回示例：

```
[
    {
        "name": "default",
        "contents": "tags: []\ninclude-tags: []\nexclude-tags: []\ninclude-templates: []\nexclude-templates: []\nimpact: []\nauthors: []\nreport-config: \"\"\nheaders: {}\nvars: {}\nresolvers: \"\"\nsystem-resolvers: false\nenv-vars: false\nno-interactsh: false\ninteractsh-url: oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me\ninteractions-cache-size: 5000\ninteractions-eviction: 60\ninteractions-poll-duration: 5\ninteractions-cooldown-period: 5\nrate-limit: 150\nrate-limit-minute: 0\nbulk-size: 25\nconcurrency: 25\nheadless-bulk-size: 10\nheadless-concurrency: 10\ntimeout: 5\nretries: 1\nhost-max-error: 30\nstop-at-first-path: false\nheadless: false\npage-timeout: 0\nproxy-url: \"\"\nproxy-socks-url: \"\"\n",
        "type": "internal"
    }
]
```

### 2. 新增settings

- 请求方式：`POST`
- 接口地址：`/settings`
- 请求类型：`application/json`

> 请求示例：

```
{
    "name": "mySettings",
    "contents": "tags: []\ninclude-tags: []\nexclude-tags: []\ninclude-templates: []\nexclude-templates: []\nimpact: []\nauthors: []\nreport-config: \"\"\nheaders: {}\nvars: {}\nresolvers: \"\"\nsystem-resolvers: false\nenv-vars: false\nno-interactsh: false\ninteractsh-url: oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me\ninteractions-cache-size: 5000\ninteractions-eviction: 60\ninteractions-poll-duration: 5\ninteractions-cooldown-period: 5\nrate-limit: 200\nrate-limit-minute: 0\nbulk-size: 25\nconcurrency: 32\nheadless-bulk-size: 10\nheadless-concurrency: 10\ntimeout: 5\nretries: 1\nhost-max-error: 30\nstop-at-first-path: false\nheadless: false\npage-timeout: 0\nproxy-url: \"\"\nproxy-socks-url: \"\"\n",
    "type": "internal"
}
```

> 返回示例：此接口成功后无返回数据，只有出错后才有返回，判断是否返回错误即可

### 3. 根据name获取settings

- 请求方式：`GET`
- 接口地址：`/settings/:name`

> 请求示例：替换`:name`为需要获取的settings的name，
> 如请求地址为`http://10.10.30.183:8822/api/v1/settings/mySettings`

> 返回示例：

```
{
    "name": "mySettings",
    "contents": "tags: []\ninclude-tags: []\nexclude-tags: []\ninclude-templates: []\nexclude-templates: []\nimpact: []\nauthors: []\nreport-config: \"\"\nheaders: {}\nvars: {}\nresolvers: \"\"\nsystem-resolvers: false\nenv-vars: false\nno-interactsh: false\ninteractsh-url: oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me\ninteractions-cache-size: 5000\ninteractions-eviction: 60\ninteractions-poll-duration: 5\ninteractions-cooldown-period: 5\nrate-limit: 200\nrate-limit-minute: 0\nbulk-size: 25\nconcurrency: 32\nheadless-bulk-size: 10\nheadless-concurrency: 10\ntimeout: 5\nretries: 1\nhost-max-error: 30\nstop-at-first-path: false\nheadless: false\npage-timeout: 0\nproxy-url: \"\"\nproxy-socks-url: \"\"\n",
    "type": "internal"
}
```

### 4. 根据name修改settings

- 请求方式：`PUT`
- 接口地址：`/settings/:name`
- 请求类型：`application/json`

> 请求示例：请求地址`http://10.10.30.183:8822/api/v1/settings/mySettings`，
> body如下：

```
{
    "contents": "tags: []\ninclude-tags: []\nexclude-tags: []\ninclude-templates: []\nexclude-templates: []\nimpact: []\nauthors: []\nreport-config: \"\"\nheaders: {}\nvars: {}\nresolvers: \"\"\nsystem-resolvers: false\nenv-vars: false\nno-interactsh: false\ninteractsh-url: oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me\ninteractions-cache-size: 5000\ninteractions-eviction: 60\ninteractions-poll-duration: 5\ninteractions-cooldown-period: 5\nrate-limit: 200\nrate-limit-minute: 0\nbulk-size: 25\nconcurrency: 32\nheadless-bulk-size: 10\nheadless-concurrency: 10\ntimeout: 5\nretries: 1\nhost-max-error: 25\nstop-at-first-path: false\nheadless: false\npage-timeout: 0\nproxy-url: \"\"\nproxy-socks-url: \"\"\n",
    "type": "internal"
}
```

> 返回示例：此接口成功后无返回数据，只有出错后才有返回，判断是否返回错误即可

## 执行相关接口

---

### 1. 获取scans

- 请求方式：`GET`
- 接口地址：`/scans`

|  参数名   |   类型   | 说明             | 示例       |
|:------:|:------:|:---------------|:---------|
|  page  |  int   | 页码，默认0，表示第一页   | 12       |
|  size  |  int   | 每页显示数量，默认每页10条 | 20       |
| search | string | 搜索关键字          | http-xxx |

> 返回示例：

```
[
    {
        "id": 2,
        "status": "failed",
        "name": "test-scan",
        "templates": [
            ""
        ],
        "targets": [
            "https://www.baidu.com"
        ],
        "runNow": true,
        "hosts": 1
    },
    {
        "id": 3,
        "status": "done",
        "name": "test-scan",
        "templates": [
            ""
        ],
        "targets": [
            "https://www.baidu.com"
        ],
        "config": "default",
        "runNow": true,
        "hosts": 1
    }
]
```

### 2. 新增扫描任务

- 请求方式：`POST`
- 接口地址：`/scans`
- 请求类型：`application/json`

> 请求示例：

```
{
    "name":"test2",         //本次扫描名称
    "templates":[""],           //参与扫描的模板name，[""]表示使用所有
    "targets":["127.0.0.1"],   //目标地址集
    "runNow":true,          //保持true，提交立即执行
    "config":"default"        //要采用的settings的Name
}
```

> 返回示例：返回本次扫描任务的id，用于查看进度和结果等相关信息

```
{
    "id": 11
}
```

### 3. 根据ID获取scans

- 请求方式：`GET`
- 接口地址：`/scans/:id`

> 返回示例：请求`http://10.10.30.183:8822/api/v1/scans/11`

```
{
    "id": 11,
    "status": "done",      //done表示已结束，started表示正在执行中，failed表示失败
    "name": "test2",
    "templates": [
        ""
    ],
    "targets": [
        "127.0.0.1"
    ],
    "config": "default",
    "runNow": true,
    "hosts": 1
}
```

### 4. 根据ID获取scans的命中结果

- 请求方式：`GET`
- 接口地址：`/scans/:id/matches`

|  参数名   |   类型   | 说明             | 示例       |
|:------:|:------:|:---------------|:---------|
|  page  |  int   | 页码，默认0，表示第一页   | 12       |
|  size  |  int   | 每页显示数量，默认每页10条 | 20       |

> 返回示例：请求`http://10.10.30.183:8822/api/v1/scans/9/matches?page=0&size=2`

```
[
    {
        "templateName": "http-missing-security-headers.yaml",
        "severity": "info",
        "author": "socketz, geeknik, g4l1t0, convisoappsec, kurohost, dawid-czarnecki",
        "matchedAt": "http://127.0.0.1:8822"
    },
    {
        "templateName": "http-missing-security-headers.yaml",
        "severity": "info",
        "author": "socketz, geeknik, g4l1t0, convisoappsec, kurohost, dawid-czarnecki",
        "matchedAt": "http://127.0.0.1:8822"
    }
]
```

### 5. 根据ID获取scans的错误

- 请求方式：`GET`
- 接口地址：`/scans/:id/errors`

> 返回示例：请求`http://10.10.30.183:8822/api/v1/scans/9/errors?page=0&size=2`

```
[
    {
        "template": "/tmp/nuclei-templates-3070765142/misconfiguration/proxy/metadata-aws.yaml",
        "url": "http://127.0.0.1:8822",
        "type": "http",
        "error": "ReadStatusLine: read tcp 127.0.0.1:54786->127.0.0.1:8822: i/o timeout"
    },
    {
        "template": "/tmp/nuclei-templates-3070765142/misconfiguration/proxy/metadata-aws.yaml",
        "url": "http://127.0.0.1:8822",
        "type": "http",
        "error": "ReadStatusLine: read tcp 127.0.0.1:55020->127.0.0.1:8822: i/o timeout"
    }
]
```

### 6. 根据ID获取正在执行的模板

- 请求方式：`GET`
- 接口地址：`/scans/:id/progress`

> 返回示例：请求`http://10.10.30.183:8822/api/v1/scans/9/progress`

```
[
    {
      "templateId": "tp1",
      "status": 1
    },
    {
      "templateId": "tp2",
      "status": 2
    },
    {
      "templateId": "tp3",
      "status": 3
    }
]
```

### 7. 根据templateId获取时间轴信息

- 请求方式：`GET`
- 接口地址：`/scans/:tid/stamp`

> 返回示例：请求`http://10.10.30.183:8822/api/v1/scans/tpId1/stamp`

```
[
    {
      "content": "开始时间",
      "color": "#409EFF",
      "status": 0,
      "timestamp": "2006-01-02 15:04:05",
      "msg": ""
    },
    {
      "content": "成功",
      "color": "#409EFF",
      "status": 1,
      "timestamp": "2006-01-02 15:04:05",
      "msg": "{\"test\":\"a\"}"
    },
    {
      "content": "结束时间",
      "color": "#409EFF",
      "status": 0,
      "timestamp": "2006-01-02 15:04:05",
      "msg": ""
    }
]
```