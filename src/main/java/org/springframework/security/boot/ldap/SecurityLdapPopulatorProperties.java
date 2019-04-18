/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
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
package org.springframework.security.boot.ldap;

import org.springframework.ldap.core.LdapTemplate;
import org.springframework.util.Assert;

public class SecurityLdapPopulatorProperties {
	
	private String defaultRole;
	
	/**
	 * The ID of the attribute which contains the role name for a group
	 */
	private String groupRoleAttribute = "cn";

	/**
	 * The base DN from which the search for group membership should be performed
	 */
	private String groupSearchBase;

	private boolean searchSubtree;

	/**
	 * The pattern to be used for the user search. {0} is the user's DN
	 */
	private String groupSearchFilter = "(member={0})";
	/**
	 * The role prefix that will be prepended to each role name
	 */
	private String rolePrefix = "ROLE_";
	/**
	 * Should we convert the role name to uppercase
	 */
	private boolean convertToUpperCase = true;

	private boolean ignorePartialResultException = false;

	/**
	 * The default role which will be assigned to all users.
	 *
	 * @param defaultRole the role name, including any desired prefix.
	 */
	public void setDefaultRole(String defaultRole) {
		Assert.notNull(defaultRole, "The defaultRole property cannot be set to null");
		this.defaultRole = defaultRole;
	}
	
	/**
	 * Convert the role to uppercase
	 */
	public void setConvertToUpperCase(boolean convertToUpperCase) {
		this.convertToUpperCase = convertToUpperCase;
	}

	public void setGroupRoleAttribute(String groupRoleAttribute) {
		Assert.notNull(groupRoleAttribute, "groupRoleAttribute must not be null");
		this.groupRoleAttribute = groupRoleAttribute;
	}

	public void setGroupSearchBase(String groupSearchBase) {
		this.groupSearchBase = groupSearchBase;
	}

	/**
	 * If set to true, a subtree scope search will be performed. If false a
	 * single-level search is used.
	 *
	 * @param searchSubtree set to true to enable searching of the entire tree below
	 *                      the
	 */
	public void setSearchSubtree(boolean searchSubtree) {
		this.searchSubtree = searchSubtree;
	}

	public void setGroupSearchFilter(String groupSearchFilter) {
		Assert.notNull(groupSearchFilter, "groupSearchFilter must not be null");
		this.groupSearchFilter = groupSearchFilter;
	}

	/**
	 * Sets the prefix which will be prepended to the values loaded from the
	 * directory. Defaults to "ROLE_" for compatibility with <tt>RoleVoter</tt>.
	 */
	public void setRolePrefix(String rolePrefix) {
		Assert.notNull(rolePrefix, "rolePrefix must not be null");
		this.rolePrefix = rolePrefix;
	}

	/**
	 * Specify whether <code>PartialResultException</code> should be ignored in
	 * searches. AD servers typically have a problem with referrals. Normally a
	 * referral should be followed automatically, but this does not seem to work
	 * with AD servers. The problem manifests itself with a a
	 * <code>PartialResultException</code> being thrown when a referral is
	 * encountered by the server. Setting this property to <code>true</code>
	 * presents a workaround to this problem by causing
	 * <code>PartialResultException</code> to be ignored, so that the search method
	 * returns normally. Default value of this parameter is <code>false</code>.
	 * 
	 * @param ignore <code>true</code> if <code>PartialResultException</code> should
	 *               be ignored in searches, <code>false</code> otherwise. Default
	 *               is <code>false</code>.
	 * @see LdapTemplate#setIgnoreNameNotFoundException(boolean)
	 */
	public void setIgnorePartialResultException(boolean ignore) {
		this.ignorePartialResultException = ignore;
	}

	/**
	 * Returns the default role Method available so that classes extending this can
	 * override
	 * @return the default role used
	 * @see #setDefaultRole(String)
	 */
	public String getDefaultRole() {
		return this.defaultRole;
	}
	
	/**
	 * Returns the attribute name of the LDAP attribute that will be mapped to the
	 * role name Method available so that classes extending this can override
	 * 
	 * @return the attribute name used for role mapping
	 * @see #setGroupRoleAttribute(String)
	 */
	public String getGroupRoleAttribute() {
		return this.groupRoleAttribute;
	}

	/**
	 * Returns the search filter configured for this populator Method available so
	 * that classes extending this can override
	 * 
	 * @return the search filter
	 * @see #setGroupSearchFilter(String)
	 */
	public String getGroupSearchFilter() {
		return this.groupSearchFilter;
	}

	/**
	 * Returns the role prefix used by this populator Method available so that
	 * classes extending this can override
	 * 
	 * @return the role prefix
	 * @see #setRolePrefix(String)
	 */
	public String getRolePrefix() {
		return this.rolePrefix;
	}

	/**
	 * Returns true if role names are converted to uppercase Method available so
	 * that classes extending this can override
	 * 
	 * @return true if role names are converted to uppercase.
	 * @see #setConvertToUpperCase(boolean)
	 */
	public boolean isConvertToUpperCase() {
		return this.convertToUpperCase;
	}

	public String getGroupSearchBase() {
		return groupSearchBase;
	}

	public boolean isSearchSubtree() {
		return searchSubtree;
	}

	public boolean isIgnorePartialResultException() {
		return ignorePartialResultException;
	}

}
