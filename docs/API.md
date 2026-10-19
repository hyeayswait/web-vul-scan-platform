# 接口文档

Base URL: `http://127.0.0.1:5000/api`

除 `auth/register`、`auth/login` 外，所有接口都需要在请求头携带：

```
Authorization: Bearer <token>
```

## 1. 认证

### POST /auth/register
注册账号。

请求体：
```json
{ "username": "admin", "password": "123456" }
```

响应：
```json
{ "msg": "注册成功" }
```

### POST /auth/login
登录，返回 JWT。

请求体：
```json
{ "username": "admin", "password": "123456" }
```

响应：
```json
{ "token": "eyJhbGciOi...", "username": "admin" }
```

## 2. 资产管理

### GET /asset/list
返回当前用户的资产列表。

```json
[
  { "id": 1, "target": "http://127.0.0.1:8080", "name": "本地 DVWA" }
]
```

### POST /asset/add
新增资产。

```json
{ "name": "本地 DVWA", "target": "http://127.0.0.1:8080" }
```

### DELETE /asset/del/{id}
删除资产。

## 3. 扫描任务

### POST /task/start
对某个资产启动一次扫描（异步）。

```json
{ "asset_id": 1 }
```

响应：
```json
{ "task_id": 2, "msg": "扫描任务已启动" }
```

### GET /task/list
返回当前用户的所有任务（按时间倒序）。

```json
[
  {
    "id": 2,
    "asset_target": "http://127.0.0.1:8080",
    "asset_name": "本地 DVWA",
    "status": "running",
    "progress": 60,
    "create_time": "2026-10-19 14:30:00"
  }
]
```

`status`：`pending` / `running` / `finish` / `failed`

## 4. 漏洞与报告

### GET /vul/list/{task_id}
返回某次任务发现的漏洞列表。

```json
[
  {
    "id": 1,
    "vul_name": "反射型 XSS 检测",
    "level": "medium",
    "desc": "请求参数中的脚本被原样回显到页面..."
  }
]
```

`level`：`high` / `medium` / `low`

### GET /report/export/{task_id}
导出该任务的 PDF 漏洞巡检报告，直接返回文件流。
