/*
 * Copyright (c) 2017, vindell (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.ldap.authentication;

import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;

import org.springframework.security.ldap.ppolicy.PasswordPolicyAwareContextSource;

/**
 * 登录环境变量的设置
 */
public class LoginContextSource extends PasswordPolicyAwareContextSource {
    private static final String LDAP_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";

    public LoginContextSource(String providerUrl) {
        super(providerUrl);

        this.afterPropertiesSet();
    }

    @Override
    protected DirContext getDirContextInstance(Hashtable<String, Object> environment) throws NamingException {
        environment.put(Context.INITIAL_CONTEXT_FACTORY, LDAP_FACTORY);
        // LDAP server
        //environment.put(Context.PROVIDER_URL, ladpUrl);
        environment.put(Context.SECURITY_AUTHENTICATION, "simple");
        // 这里只是做一个演示，后面其实并不需要公用的帐号登录
        environment.put(Context.SECURITY_PRINCIPAL, "username");
        environment.put(Context.SECURITY_CREDENTIALS, "password");
        environment.put("java.naming.referral", "follow");

        return super.getDirContextInstance(environment);
    }
}