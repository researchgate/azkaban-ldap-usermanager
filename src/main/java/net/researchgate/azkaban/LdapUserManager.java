package net.researchgate.azkaban;

import azkaban.user.*;
import azkaban.utils.Props;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
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

            if (!isMemberOfAllowedGroups(connection, entry)) {
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

            if (isMemberOfAdminGroups(connection, entry)) {
            logger.info("User is admin; granting admin access");
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

    private boolean isMemberOfAllowedGroups(LdapConnection connection, Entry user) throws CursorException, LdapException {
        if (ldapAllowedGroups.size() == 0) {
            return true;
        }
    if (ldapEmbeddedGroups) {
        for (String groupName : ldapAllowedGroups) {
                logger.info("This is group : " + groupName);
        String goodGroup = "CN=" + groupName + "," + ldapGroupSearchBase;
                logger.info("Going to search for " + goodGroup);
        Attribute groups = user.get("memberof");
        String memberships = user.get("memberof").toString();
        logger.info("User is: " + memberships);
        if (groups.contains(goodGroup)){
                return true;
        }

        }
        return false;
    } else {
        Attribute username = user.get(ldapUserIdProperty);
        for (String group : ldapAllowedGroups) {
        logger.info("This is group : " + group);
        logger.info("Going to search CN=" + group + "," + ldapGroupSearchBase);
        Entry result = connection.lookup("CN=" + group + "," + ldapGroupSearchBase);

        if (result == null) {
            return false;
        }

        Attribute members = result.get("memberuid");
                logger.info("Got a result  ");
        logger.info("Comparing " + username.toString() );

        if (members == null) {
            return false;
        }
        logger.info("going to return stuff");
        return members.contains(username.toString());
        }
    }

        return false;
    }

    private boolean isMemberOfAdminGroups(LdapConnection connection, Entry user) throws CursorException, LdapException {
        if (ldapAdminGroups.size() == 0) {
            return true;
        }
        if (ldapEmbeddedGroups) {
            for (String groupName : ldapAdminGroups) {
                logger.info("This is group : " + groupName);
                String goodGroup = "CN=" + groupName + "," + ldapGroupSearchBase;
                logger.info("Going to search for " + goodGroup);
                Attribute groups = user.get("memberof");
                String memberships = user.get("memberof").toString();
                logger.info("User is: " + memberships);
                if (groups.contains(goodGroup)){
                            return true;
                }

            }
            return false;
        } else {
            Attribute username = user.get(ldapUserIdProperty);
            for (String group : ldapAdminGroups) {
                logger.info("This is group : " + group);
                logger.info("Going to search CN=" + group + "," + ldapGroupSearchBase);
                Entry result = connection.lookup("CN=" + group + "," + ldapGroupSearchBase);

                if (result == null) {
                    return false;
                }

                Attribute members = result.get("memberuid");
                logger.info("Got a result  ");
                logger.info("Comparing " + username.toString() );

                if (members == null) {
                    return false;
                }
                logger.info("going to return stuff");
                return members.contains(username.toString());
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

            if (!isMemberOfAllowedGroups(connection, entry)) {
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
     * Taken from https://www.owasp.org/index.php/Preventing_LDAP_Injection_in_Java
     */
    public String escapeLDAPSearchFilter(String filter) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < filter.length(); i++) {
            char curChar = filter.charAt(i);
            switch (curChar) {
                case '\\':
                    sb.append("\\5c");
                    break;
                case '*':
                    sb.append("\\2a");
                    break;
                case '(':
                    sb.append("\\28");
                    break;
                case ')':
                    sb.append("\\29");
                    break;
                case '\u0000':
                    sb.append("\\00");
                    break;
                default:
                    sb.append(curChar);
            }
        }
        return sb.toString();
    }
}
