/*
 * Copyright (c) 2010-2020, vindell (https://github.com/vindell).
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


import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.LdapContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.security.ldap.authentication.AbstractLdapAuthenticator;

/**
 * 自定义的LDAP登录认证器
 */
public class LoginAuthenticator extends AbstractLdapAuthenticator {
    private static final Log logger = LogFactory.getLog(LoginAuthenticator.class);

    /**
     * The filter expression used in the user search. This is an LDAP search filter (as
     * defined in 'RFC 2254') with optional arguments. See the documentation for the
     * <tt>search</tt> methods in {@link javax.naming.directory.DirContext DirContext} for
     * more information.
     *
     * <p>
     * In this case, the username is the only parameter.
     * </p>
     * Possible examples are:
     * <ul>
     * <li>(uid={0}) - this would search for a username match on the uid attribute.</li>
     * </ul>
     */
    private final String searchFilter;

    /** Context name to search in, relative to the base of the configured ContextSource. */
    private String searchBase = "";

    /** Default search controls */
    private SearchControls searchControls = new SearchControls();

    public LoginAuthenticator(ContextSource contextSource, String searchBase, String searchFilter) {
        super(contextSource);

        this.searchFilter = searchFilter;
        this.searchBase = searchBase;

        if (searchBase.length() == 0) {
            logger.info("SearchBase not set. Searches will be performed from the root: ---");
        }
    }

    @Override
    public DirContextOperations authenticate(Authentication authentication) {
        DirContextOperations user = null;

        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        ContextSource contextSource = getContextSource();
        LdapContext context = (LdapContext) contextSource.getReadOnlyContext();

        try {
            // 尝试使用用户的域账号登陆LDAP，如果连接成功那么就算是通过
            context.addToEnvironment(Context.SECURITY_PRINCIPAL, username + "@buyabs.corp");
            context.addToEnvironment(Context.SECURITY_CREDENTIALS, password);
            context.reconnect(null);
        } catch (NamingException e) {
            if (logger.isDebugEnabled()) {
                logger.debug("Username or password does not match: " + e.getLocalizedMessage());
            }
            // 如果重新连接不上，则断定为登陆失败
            throw new UsernameNotFoundException("Username or password does not match: " + e.getLocalizedMessage());
        }

        // 使用用户自己的域账号登陆LDAP，并获取信息。避免使用公用账号获取信息（因为我们压根没有公用账号0_0）
        if (user == null && getUserSearch() != null) {
            try {
                searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                user = SpringSecurityLdapTemplate.searchForSingleEntryInternal(context, searchControls, searchBase, searchFilter, new String[] { username });
            } catch (NamingException e) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Username or password does not match: " + e.getLocalizedMessage());
                }
            }
        }

        if (user == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }

        return user;
    }

}