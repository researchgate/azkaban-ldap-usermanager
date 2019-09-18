package net.researchgate.azkaban;

import azkaban.user.*;
import azkaban.utils.Props;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.filter.FilterEncoder;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;


import org.apache.log4j.Logger;

import java.io.IOException;
import java.util.List;

public class LdapUserManager implements UserManager {
    final static Logger logger = Logger.getLogger(UserManager.class);

    public static final String LDAP_HOST = "user.manager.ldap.host";
    public static final String LDAP_PORT = "user.manager.ldap.port";
    public static final String LDAP_USE_SSL = "user.manager.ldap.useSsl";
    public static final String LDAP_USER_BASE = "user.manager.ldap.userBase";
    public static final String LDAP_USERID_PROPERTY = "user.manager.ldap.userIdProperty";
    public static final String LDAP_EMAIL_PROPERTY = "user.manager.ldap.emailProperty";
    public static final String LDAP_BIND_ACCOUNT = "user.manager.ldap.bindAccount";
    public static final String LDAP_BIND_PASSWORD = "user.manager.ldap.bindPassword";
    public static final String LDAP_ALLOWED_GROUPS = "user.manager.ldap.allowedGroups";
    public static final String LDAP_ADMIN_GROUPS = "user.manager.ldap.adminGroups";
    public static final String LDAP_GROUP_SEARCH_BASE = "user.manager.ldap.groupSearchBase";
    public static final String LDAP_EMBEDDED_GROUPS = "user.manager.ldap.embeddedGroups";

    private String ldapHost;
    private int ldapPort;
    private boolean useSsl;
    private String ldapUserBase;
    private String ldapUserIdProperty;
    private String ldapUEmailProperty;
    private String ldapBindAccount;
    private String ldapBindPassword;
    private List<String> ldapAllowedGroups;
    private List<String> ldapAdminGroups;
    private String ldapGroupSearchBase;
    private boolean ldapEmbeddedGroups;

    public LdapUserManager(Props props) {
        ldapHost = props.getString(LDAP_HOST);
        ldapPort = props.getInt(LDAP_PORT);
        useSsl = props.getBoolean(LDAP_USE_SSL);
        ldapUserBase = props.getString(LDAP_USER_BASE);
        ldapUserIdProperty = props.getString(LDAP_USERID_PROPERTY);
        ldapUEmailProperty = props.getString(LDAP_EMAIL_PROPERTY);
        ldapBindAccount = props.getString(LDAP_BIND_ACCOUNT);
        ldapBindPassword = props.getString(LDAP_BIND_PASSWORD);
        ldapAllowedGroups = props.getStringList(LDAP_ALLOWED_GROUPS);
        ldapAdminGroups = props.getStringList(LDAP_ADMIN_GROUPS);
        ldapGroupSearchBase = props.getString(LDAP_GROUP_SEARCH_BASE);
        ldapEmbeddedGroups = props.getBoolean(LDAP_EMBEDDED_GROUPS, false);
    }

    @Override
    public User getUser(String username, String password) throws UserManagerException {
        if (username == null || username.trim().isEmpty()) {
            throw new UserManagerException("Username is empty.");
        } else if (password == null || password.trim().isEmpty()) {
            throw new UserManagerException("Password is empty.");
        }

        LdapConnection connection = null;
        EntryCursor result = null;

        try {
            connection = getLdapConnection();

            result = connection.search(
                    ldapUserBase,
                    "(" + escapeLDAPSearchFilter(ldapUserIdProperty + "=" + username) + ")",
                    SearchScope.SUBTREE
            );

            if (!result.next()) {
                throw new UserManagerException("No user " + username + " found");
            }

            final Entry entry = result.get();

            if (result.next()) {
                throw new UserManagerException("More than one user found");
            }

            if (!isMemberOfGroups(connection, entry, ldapAllowedGroups)) {
                throw new UserManagerException("User is not member of allowed groups");
            }

            connection.bind(entry.getDn(), password);

            Attribute idAttribute = entry.get(ldapUserIdProperty);
            Attribute emailAttribute = null;
            if (ldapUEmailProperty.length() > 0) {
                emailAttribute = entry.get(ldapUEmailProperty);
            }

            if (idAttribute == null) {
                throw new UserManagerException("Invalid id property name " + ldapUserIdProperty);
            }
            User user = new User(idAttribute.getString());
            if (emailAttribute != null) {
                user.setEmail(emailAttribute.getString());
            }

            if (isMemberOfGroups(connection, entry, ldapAdminGroups)) {
                logger.info("Granting admin access to user: " + username);
                user.addRole("admin");
            }

            return user;

        } catch (LdapException e) {
            throw new UserManagerException("LDAP error: " + e.getMessage(), e);
        } catch (CursorException e) {
            throw new UserManagerException("Cursor error", e);
        }
        finally {
            if (result != null)
                result.close();

            if (connection != null) {
                try {
                    connection.close();
                } catch(IOException e) {
                    throw new UserManagerException("IO error", e);
                }
            }
        }
    }

    /**
     * @return true, when user is member of provided list of expectedGroups or if expectedGroups is empty; false, otherwise
     */
    private boolean isMemberOfGroups(LdapConnection connection, Entry user, List<String> expectedGroups) throws CursorException, LdapException {
        if (expectedGroups.size() == 0) {
            return true;
        }
        if (ldapEmbeddedGroups) {
            Attribute groups = user.get("memberof");
            for (String expectedGroupName : expectedGroups) {
                String expectedGroup = "CN=" + expectedGroupName + "," + ldapGroupSearchBase;
                final boolean isMember = attributeContainsNormalized(expectedGroup, groups);
                logger.info("For group '" + expectedGroupName + "' " +
                        "searched for '" + expectedGroup + "' " +
                        "within user groups '" + groups.toString() + "'. " +
                        "User is member: " + isMember);
                if (isMember) {
                    return true;
                }
            }
            return false;
        } else {
            Attribute usernameAttribute = user.get(ldapUserIdProperty);
            if (usernameAttribute == null) {
                logger.info("Could not extract attribute '" + ldapUserIdProperty + "' for entry '" + user + "'. Not checking further groups.");
                return false;
            }
            Value usernameValue = usernameAttribute.get();
            if (usernameValue == null) {
                logger.info("Could not extract value of attribute '" + ldapUserIdProperty + "' for entry '" + user + "'. Not checking further groups.");
                return false;
            }

            String username = usernameValue.getString();
            for (String expectedGroupName : expectedGroups) {
                String expectedGroup = "CN=" + expectedGroupName + "," + ldapGroupSearchBase;
                logger.info("For group '" + expectedGroupName + "' " +
                        "looking up '" + expectedGroup + "'...");
                Entry result = connection.lookup(expectedGroup);

                if (result == null) {
                    logger.info("Could not lookup group '" + expectedGroup + "'. Not checking further groups.");
                    return false;
                }

                Attribute objectClasses = result.get("objectClass");
                if(objectClasses != null && objectClasses.contains("groupOfNames")) {
                    Attribute members = result.get("member");

                    if (members == null) {
                        logger.info("Could not get members of group '" + expectedGroup + "'. Not checking further groups.");
                        return false;
                    }

                    String userDn = "cn=" + username + "," + ldapUserBase;
                    boolean isMember = members.contains(userDn);
                    logger.info("Searched for userDn '" + userDn + "' " +
                            "within group members of group '" + expectedGroupName + "'. " +
                            "User is member: " + isMember);
                    if (isMember) {
                        return true;
                    }
                } else {
                    Attribute members = result.get("memberuid");
                    if (members == null) {
                        logger.info("Could not get members of group '" + expectedGroup + "'. Not checking further groups.");
                        return false;
                    }

                    boolean isMember = members.contains(username);
                    logger.info("Searched for username '" + username + "' " +
                            "within group members of group '" + expectedGroupName + "'. " +
                            "User is member: " + isMember);
                    if (isMember) {
                        return true;
                    }
                }
            }
            return false;
        }
    }

    /**
     * Tests if the attribute contains a given value (case insensitive)
     *
     * @param expected the expected value
     * @param attribute the attribute encapsulating a list of values
     * @return a value indicating if the attribute contains a value which matches expected
     */
    private boolean attributeContainsNormalized(String expected, Attribute attribute) {
        if (expected == null) {
            return false;
        }
        for (Value value : attribute) {
            if (value.toString().toLowerCase().equals(expected.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean validateUser(String username) {
        if (username == null || username.trim().isEmpty()) {
            return false;
        }

        LdapConnection connection = null;
        EntryCursor result = null;

        try {
            connection = getLdapConnection();

            result = connection.search(
                    ldapUserBase,
                    "(" + escapeLDAPSearchFilter(ldapUserIdProperty + "=" + username) + ")",
                    SearchScope.SUBTREE
            );

            if (!result.next()) {
                return false;
            }


            final Entry entry = result.get();

            if (!isMemberOfGroups(connection, entry, ldapAllowedGroups)) {
                return false;
            }

            // Check if more than one user found
            return !result.next();

        } catch (LdapException e) {
            return false;
        } catch (CursorException e) {
            return false;
        } finally {
            if (result != null)
                result.close();

            if (connection != null) {
                try {
                    connection.close();
                } catch(IOException e) {
                    return false;
                }
            }
        }
    }

    @Override
    public boolean validateGroup(String group) {
        return ldapAllowedGroups.contains(group);
    }

    @Override
    public Role getRole(String roleName) {
        Permission permission = new Permission();
        permission.addPermissionsByName(roleName.toUpperCase());
        return new Role(roleName, permission);
    }

    @Override
    public boolean validateProxyUser(String proxyUser, User realUser) {
        return false;
    }

    private LdapConnection getLdapConnection() throws LdapException {
        LdapConnection connection = new LdapNetworkConnection(ldapHost, ldapPort, useSsl);
        connection.bind(ldapBindAccount, ldapBindPassword);
        return connection;
    }

    /**
     * See also https://www.owasp.org/index.php/Preventing_LDAP_Injection_in_Java
     */
    static String escapeLDAPSearchFilter(String filter) {
        return FilterEncoder.encodeFilterValue(filter);
    }
}
