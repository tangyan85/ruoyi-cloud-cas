package com.ruoyi.auth.controller;

import javax.servlet.http.HttpServletRequest;

import com.ruoyi.common.core.utils.SecurityUtils;
import com.ruoyi.common.core.web.domain.AjaxResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import com.ruoyi.auth.form.LoginBody;
import com.ruoyi.auth.service.SysLoginService;
import com.ruoyi.common.core.domain.R;
import com.ruoyi.common.core.utils.StringUtils;
import com.ruoyi.common.security.service.TokenService;
import com.ruoyi.system.api.model.LoginUser;

import java.security.Security;
import java.util.Map;

/**
 * token 控制
 * 
 * @author ruoyi
 */
@RestController
public class TokenController
{
    @Autowired
    private TokenService tokenService;

    @Autowired
    private SysLoginService sysLoginService;

    @GetMapping("casLogin")
    public AjaxResult casLogin()
    {
        UserDetails loginUser=(UserDetails) SecurityUtils.getLoginUser();
        AjaxResult ajax = AjaxResult.success();
        LoginUser userInfo = sysLoginService.login(loginUser.getUsername());
        Map<String, Object> tokenMap = tokenService.createToken(userInfo);
        ajax.put("user", userInfo.getSysUser());
        ajax.put("roles", userInfo.getRoles());
        ajax.put("permissions", userInfo.getPermissions());
        ajax.put("token",tokenMap.get("access_token"));
        return ajax;
    }

    @PostMapping("login")
    public R<?> login(@RequestBody LoginBody form)
    {
        // 用户登录
        LoginUser userInfo = sysLoginService.login(form.getUsername(), form.getPassword());
        // 获取登录token
        return R.ok(tokenService.createToken(userInfo));
    }

    @DeleteMapping("TokenLogout")
    public R<?> logout(HttpServletRequest request)
    {
        LoginUser loginUser = tokenService.getLoginUser(request);
        if (StringUtils.isNotNull(loginUser))
        {
            String username = loginUser.getUsername();
            // 删除用户缓存记录
            tokenService.delLoginUser(loginUser.getToken());
            // 记录用户退出日志
            sysLoginService.logout(username);
        }
        return R.ok();
    }

    @PostMapping("refresh")
    public R<?> refresh(HttpServletRequest request)
    {
        LoginUser loginUser = tokenService.getLoginUser(request);
        if (StringUtils.isNotNull(loginUser))
        {
            // 刷新令牌有效期
            tokenService.refreshToken(loginUser);
            return R.ok();
        }
        return R.ok();
    }
}
