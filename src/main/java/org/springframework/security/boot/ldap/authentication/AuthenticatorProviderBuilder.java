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

import java.util.Properties;

import javax.annotation.Resource;

import org.springframework.context.annotation.Scope;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.stereotype.Service;

@Service("authenticatorProviderBuilder")
@Scope("prototype")
public class AuthenticatorProviderBuilder {
    @Resource(name="ldapAuthoritiesPopulator")
    PortalLdapAuthoritiesPopulator ldapAuthoritiesPopulator; 

    @Resource(name="profileSetting")
    Properties setting;

    public AuthenticationProvider getAuthenticationProvider() {
    	
        String ladpDomain = setting.getProperty("ladp.domain");
        String ladpuserSearch = setting.getProperty("ladp.userSearch");
        String ladpUrl = setting.getProperty("ladp.url");

        BaseLdapPathContextSource contenxSource = new LoginContextSource(ladpUrl);

        FilterBasedLdapUserSearch userSearch = new FilterBasedLdapUserSearch(ladpDomain, ladpuserSearch, contenxSource);

        LoginAuthenticator bindAuth = new LoginAuthenticator(contenxSource, ladpDomain, ladpuserSearch);
        bindAuth.setUserSearch(userSearch);

        LdapAuthenticationProvider ldapAuth = new LdapAuthenticationProvider(bindAuth, ldapAuthoritiesPopulator);

        return ldapAuth;
    }
}