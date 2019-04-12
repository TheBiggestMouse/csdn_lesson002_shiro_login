package com.lgf.maven_ssm.system.controller;


import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.DisabledAccountException;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import com.lgf.maven_ssm.system.entity.CsdnUser;
import com.lgf.maven_ssm.system.service.ILoginService;

/**
 *  描述: 登录控制器
 *  作者: 郎国峰 
 *  时间: 2019年4月11日 上午10:37:49
 */
@Controller
@RequestMapping("login")
public class LoginAction {
	@Autowired
	private ILoginService service;
	/**
	 * @方法名: loginAction 
	 * @描述: TODO 登录控制器,根据传入用户名和密码进行登录验证
	 * @作者: 郎国峰
	 * @时间: 2019年4月11日 上午11:17:07
	 * @参数: @return   
	 * @返回类型： String     
	 * @throws
	 */
	@RequestMapping("loginPage")
	public String loginAction(CsdnUser user) {
		
    	// 验证
        UsernamePasswordToken token = new UsernamePasswordToken(user.getUserName(), user.getUserPassword());
        Subject currentUser = SecurityUtils.getSubject();// 获取当前的 Subject
        try {
            // 在调用了 login 方法后, SecurityManager 会收到 AuthenticationToken, 并将其发送给已配置的 Realm 执行必须的认证检查
            // 每个 Realm 都能在必要时对提交的 AuthenticationTokens 作出反应
            // 所以这一步在调用 login(token) 方法时, 它会走到 MyRealm.doGetAuthenticationInfo() 方法中, 具体验证方式详见此方法
            currentUser.login(token);
        }catch(UnknownAccountException uae){
        	System.err.println("进行登录验证.. 验证未通过, 未知账户");
        }catch(IncorrectCredentialsException ice){
        	System.err.println("进行登录验证.. 验证未通过, 错误的凭证");
        }catch(LockedAccountException lae){
        	System.err.println("对用户  进行登录验证.. 验证未通过, 账户已锁定");
        }catch(ExcessiveAttemptsException eae){
        	System.err.println("对用户进行登录验证.. 验证未通过, 错误次数大于 5 次, 账户已锁定");
        }catch (DisabledAccountException sae){
        	System.err.println("对用户进行登录验证.. 验证未通过, 帐号已经禁止登录");
        }catch(AuthenticationException ae){
        	System.err.println("对用户  进行登录验证.. 验证未通过, 堆栈轨迹如下");
            ae.printStackTrace();
        }
        // 验证是否登录成功
        if(currentUser.isAuthenticated()){
            return "jsp/sys/login";
        }else {
            token.clear();
            return "jsp/error";
        }
	}
}
