/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
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

import org.springframework.ldap.core.support.AbstractTlsDirContextAuthenticationStrategy;
import org.springframework.ldap.core.support.DirContextAuthenticationStrategy;

/**
 * Authorities Mapper Policy
 * @author ： <a href="https://github.com/hiwepy">wandl</a>
 */
public enum AuthoritiesMapperPolicy {

	/**
	 * Default implementation of TLS authentication. Applies <code>SIMPLE</code>
	 * authentication on top of the negotiated TLS session. Refer to
	 * {@link AbstractTlsDirContextAuthenticationStrategy} for configuration
	 * options.
	 */
	ROLE_HIERARCHY,
	/**
	 * {@link DirContextAuthenticationStrategy} for using TLS and external (SASL)
	 * authentication. This implementation requires a client certificate to be
	 * pointed out using system variables, as described
	 * <a href="http://java.sun.com/products/jndi/tutorial/ldap/ext/starttls.html"
	 * >here</a>. Refer to {@link AbstractTlsDirContextAuthenticationStrategy} for
	 * other configuration options.
	 */
	SIMPLE,
	/**
	 * The default {@link DirContextAuthenticationStrategy} implementation, setting
	 * the <code>DirContext</code> environment up for 'SIMPLE' authentication, and
	 * specifying the user DN and password as SECURITY_PRINCIPAL and
	 * SECURITY_CREDENTIALS respectively in the authenticated environment before the
	 * context is created.
	 */
	NONE;
	
	public boolean equals(AuthoritiesMapperPolicy policy) {
		return this.compareTo(policy) == 0;
	}

}
