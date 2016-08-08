package net.researchgate.azkaban;

import azkaban.user.Role;
import azkaban.user.User;
import azkaban.user.UserManager;
import azkaban.user.UserManagerException;
import azkaban.utils.Props;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class LdapUserManager implements UserManager {

    public static final String LDAP_HOST = "user.manager.ldap.host";
    public static final String LDAP_PORT = "user.manager.ldap.port";
    public static final String LDAP_USE_SSL = "user.manager.ldap.useSsl";
    public static final String LDAP_USER_BASE = "user.manager.ldap.userBase";
    public static final String LDAP_USERID_PROPERTY = "user.manager.ldap.userIdProperty";
    public static final String LDAP_EMAIL_PROPERTY = "user.manager.ldap.emailProperty";
    public static final String LDAP_BIND_ACCOUNT = "user.manager.ldap.bindAccount";
    public static final String LDAP_BIND_PASSWORD = "user.manager.ldap.bindPassword";
    public static final String LDAP_ALLOWED_GROUPS = "user.manager.ldap.allowedGroups";
    public static final String LDAP_GROUP_SEARCH_BASE = "user.manager.ldap.groupSearchBase";
    public static final String LDAP_EMBEDDED_GROUPS = "user.manager.ldap.embeddedGroups";
    public static final String LDAP_ROLE_SUPPORT = "user.manager.ldap.roleSupport";
    public static final String LDAP_GROUPS_FILE = "user.manager.ldap.groupsFile";

    private String ldapHost;
    private int ldapPort;
    private boolean useSsl;
    private String ldapUserBase;
    private String ldapUserIdProperty;
    private String ldapUEmailProperty;
    private String ldapBindAccount;
    private String ldapBindPassword;
    private List<String> ldapAllowedGroups;
    private String ldapGroupSearchBase;
    private boolean ldapEmbeddedGroups;
    private boolean ldapRoleSupport;
    private String ldapGroupsFile;

    private Map<String, Group> groups;
    private Map<String, Role> roles;

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
        ldapGroupSearchBase = props.getString(LDAP_GROUP_SEARCH_BASE);
        ldapEmbeddedGroups = props.getBoolean(LDAP_EMBEDDED_GROUPS, false);
        ldapRoleSupport = props.getBoolean(LDAP_ROLE_SUPPORT, false);
        ldapGroupsFile = props.getString(LDAP_GROUPS_FILE);

        loadGroups();
        resolveRoles();
    }

    private void loadGroups() {
        GroupsLoader loader = new GroupsLoader();

        if (ldapRoleSupport) {
            groups = loader.loadFromFile(ldapGroupsFile);
            return;
        }

        groups = loader.loadFromList(ldapAllowedGroups);
    }

    private void resolveRoles() {
        roles = new HashMap<>();

        for (Map.Entry<String, Group> entry : groups.entrySet()) {
            Group group = entry.getValue();

            for (Role role : group.getRoles()) {
                roles.put(role.getName(), role);
            }
        }
    }

    @Override
    public User getUser(String username, String password) throws UserManagerException {
        if (username == null || username.trim().isEmpty()) {
            throw new UserManagerException("Username is empty.");
        } else if (password == null || password.trim().isEmpty()) {
            throw new UserManagerException("Password is empty.");
        }

        try {
            LdapConnection connection = getLdapConnection();
            EntryCursor result = connection.search(
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

            connection.bind(entry.getDn(), password);

            User user = createUserFromEntry(entry);
            addGroupsToUser(user, entry, connection);

            if (!isMemberOfAllowedGroups(user)) {
                throw new UserManagerException("User is not member of allowed groups");
            }

            assignRolesToUser(user);

            connection.unBind();
            connection.close();

            return user;
        } catch (LdapException e) {
            throw new UserManagerException("LDAP error: " + e.getMessage(), e);
        } catch (IOException e) {
            throw new UserManagerException("IO error", e);
        } catch (CursorException e) {
            throw new UserManagerException("Cursor error", e);
        }
    }

    private User createUserFromEntry(Entry entry) throws UserManagerException, LdapException {
        Attribute idAttribute = entry.get(ldapUserIdProperty);
        Attribute emailAttribute = null;

        if (idAttribute == null) {
            throw new UserManagerException("Invalid id property name " + ldapUserIdProperty);
        }

        if (ldapUEmailProperty.length() > 0) {
            emailAttribute = entry.get(ldapUEmailProperty);
        }

        User user = new User(idAttribute.getString());

        if (emailAttribute != null) {
            user.setEmail(emailAttribute.getString());
        }

        return user;
    }

    private void addGroupsToUser(User user, Entry userEntry, LdapConnection connection) throws LdapException {
        if (ldapEmbeddedGroups) {
            for (String groupName: groups.keySet()) {

                String groupDN = "CN=" + groupName + "," + ldapGroupSearchBase;
                Attribute groups = userEntry.get("memberof");

                if (groups.contains(groupDN)) {
                    user.addGroup(groupName);
                }
            }

            return;
        }

        Attribute userDn = userEntry.get(ldapUserIdProperty);

        for (String groupName: groups.keySet()) {
            Entry result = connection.lookup("CN=" + groupName + "," + ldapGroupSearchBase);

            if (result == null) {
                continue;
            }

            Attribute members = result.get("memberuid");

            if (members == null) {
                continue;
            }

            if (members.contains(userDn.toString())) {
                user.addGroup(groupName);
            }
        }
    }

    private void assignRolesToUser(User user) {
        for (String groupName : user.getGroups()) {
            Group group = groups.get(groupName);
            group.assignRolesToUser(user);
        }
    }

    private boolean isMemberOfAllowedGroups(User user) throws CursorException, LdapException {
        if (!ldapRoleSupport && ldapAllowedGroups.size() == 0) {
            return true;
        }

        for (String groupName : user.getGroups()) {
            if (groups.containsKey(groupName)) {
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

        try {
            LdapConnection connection = getLdapConnection();

            EntryCursor result = connection.search(
                    ldapUserBase,
                    "(" + escapeLDAPSearchFilter(ldapUserIdProperty + "=" + username) + ")",
                    SearchScope.SUBTREE
            );

            if (!result.next()) {
                return false;
            }


            final Entry entry = result.get();

            User user = createUserFromEntry(entry);
            addGroupsToUser(user, entry, connection);

            if (!isMemberOfAllowedGroups(user)) {
                return false;
            }

            // Check if more than one user found
            return !result.next();

        } catch (UserManagerException e) {
            return false;
        } catch (LdapException e) {
            return false;
        } catch (CursorException e) {
            return false;
        }
    }

    @Override
    public boolean validateGroup(String group) {
        return groups.containsKey(group);
    }

    @Override
    public Role getRole(String roleName) {
        return roles.get(roleName);
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
