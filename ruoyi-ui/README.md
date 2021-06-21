## 开发

```bash
后端配置
# 1、auth模块 bootstrap.yml配置cas
#我的cas时搭建在本地的,端口8081,修改了以支持http访问（具体请自行百度），同时将cas用户改为admin::admin123
cas:
  server:
    host:
      login_url: ${cas.server.host.url}/login
      logout_url: ${cas.server.host.url}/logout?service=${app.server.host.url}
      url: http://localhost:8081/cas


# 2、auth模块cas目录
1）、配置pom：spring-security-cas降了版本
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-cas</artifactId>
            <version>5.0.4.RELEASE</version>
        </dependency>
2）、新增cas代码
    CASAuthenticationEntryPointImpl.java
    CasSecurityConfig.java
    CasProperties.java
3)、启动模块增加重定向前端
       @RequestMapping("/")
       public void index(HttpServletResponse response) throws IOException {
           System.out.println("-----------"+response.getStatus());
           response.sendRedirect("http://localhost");//前端地址
       }
4)、TokenController新增casLogin
    @GetMapping("casLogin")
    public AjaxResult casLogin()
    {
        UserDetails loginUser=(UserDetails) SecurityUtils.getLoginUser();
        AjaxResult ajax = AjaxResult.success();
        LoginUser userInfo = sysLoginService.login(loginUser.getUsername(), null);
        Map<String, Object> tokenMap = tokenService.createToken(userInfo);
        ajax.put("user", userInfo.getSysUser());
        ajax.put("roles", userInfo.getRoles());
        ajax.put("permissions", userInfo.getPermissions());
        ajax.put("token",tokenMap.get("access_token"));
        return ajax;
    }

   修改logout方法，将url路径:logout改为TokenLogout,默认登出方法不能登出，此处在清理了token等缓存信息后，前端页面会
重新调用cas登出方法。

# 3、gateway增加白名单---nacos  ruoyi-gateway-dev.yml
  ignore:
    whites:
      - /auth/logout
      - /auth/login
      - /*/v2/api-docs
      - /csrf
      - /auth/casLogin
      - /auth/tokenLogout



前端配置
   1、permission.js
   2、user.js增加casLogin、casLogout
   3、login.js增加casLogin
   4、request.js修改响应拦截器：401时跳转cas
   5、request.js修改判断逻辑
