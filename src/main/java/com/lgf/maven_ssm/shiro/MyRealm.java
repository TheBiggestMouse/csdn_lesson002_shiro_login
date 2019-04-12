package com.lgf.maven_ssm.shiro;

import javax.annotation.Resource;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import com.lgf.maven_ssm.system.entity.CsdnUser;
import com.lgf.maven_ssm.system.service.ILoginService;



public class MyRealm extends AuthorizingRealm {

	@Resource
    private ILoginService loginService;
	
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
	 	UsernamePasswordToken userToken = (UsernamePasswordToken) token;
        CsdnUser user=loginService.getUserByName(userToken.getUsername());
        if (user != null){
            // 若存在，将此用户存放到登录认证 info 中，无需自己做密码对比，Shiro 会为我们进行密码对比校验
            return new SimpleAuthenticationInfo(user, user.getUserPassword(), getName());
        }
        return null;
	}
}
