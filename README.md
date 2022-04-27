# Kong Config

功能: 【截止v0.1.0】
- kong route & service 配置 及 准实时更新（2分钟左右）
- kong 插件, 目前支持以下插件
  - cors
  - request-termination
  - rate-limiting
  - key-auth
  - jwt
  - ip-restriction


## 使用方式

<details>
<summary>KongConfig CRD 配置文件参考</summary>

```yaml
apiVersion: kong.pyfdtic.com/v1
kind: KongConfig
metadata:
  name: kongconfig-sample
spec:
  kongUrl: "http://kong-web-service.kong:8081"
  tags:
    - "name"
    - "tom"
  service:
    host: test.dwarf-zhangsan
    port: 8080
    path: '/'
    retries: 5
    protocol: http
    connectTimeout: 60000
    writeTimeout: 60000
    readTimeout: 60000
    plugins:
    - name: 
        config: config
    - name:
        config: app
      
  route:
    hosts:
      - test.example.com
    paths:
      - /test
    methods:
      - GET
      - POST
    pathHandling: v1
    httpsRedirectStatusCode: 426
    regexPriority: 0
    stripPath: true
    preserveHost: false
    protocols:
      - http
      - https
```
</details>

## 版本历史

- v0.1.0
  - kong route/service 配置以及准实时更新
  - kubernetes event 支持
  - 插件支持：
    - cors
    - request-termination
    - rate-limiting
    - key-auth
    - jwt
    - ip-restriction

## Tips:
- [Kong Admin Rest API](https://docs.konghq.com/gateway-oss/2.1.x/admin-api)
