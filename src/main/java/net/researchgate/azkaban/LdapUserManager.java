package net.researchgate.azkaban;

import azkaban.user.*;
import azkaban.utils.Props;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.filter.FilterEncoder;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;

import org.apache.log4j.Logger;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class LdapUserManager implements UserManager {
    final static Logger logger = Logger.getLogger(UserManager.class);

    public static final String LDAP_HOST = "user.manager.ldap.host";
    public static final String LDAP_PORT = "user.manager.ldap.port";
    public static final String LDAP_USE_SSL = "user.manager.ldap.useSsl";
    public static final String LDAP_USER_BASE = "user.manager.ldap.userBase";
    public static final String LDAP_USER_ID_PROPERTY = "user.manager.ldap.userIdProperty";
    public static final String LDAP_EMAIL_PROPERTY = "user.manager.ldap.emailProperty";
    public static final String LDAP_BIND_ACCOUNT = "user.manager.ldap.bindAccount";
    public static final String LDAP_BIND_PASSWORD = "user.manager.ldap.bindPassword";
    public static final String LDAP_ALLOWED_GROUPS = "user.manager.ldap.allowedGroups";
    public static final String LDAP_ADMIN_GROUPS = "user.manager.ldap.adminGroups";
    public static final String LDAP_GROUP_SEARCH_BASE = "user.manager.ldap.groupSearchBase";
    public static final String LDAP_EMBEDDED_GROUPS = "user.manager.ldap.embeddedGroups";

    // Support local salt account for admin privileges
    public static final String LOCAL_SALT_ACCOUNT = "user.manager.salt.account";
    public static final String LOCAL_SALT_PASSWORD = "user.manager.salt.password";

    private final String ldapHost;
    private final int ldapPort;
    private final boolean useSsl;
    private final String ldapUserBase;
    private final Dn ldapUserBaseDn;
    private final String ldapUserIdProperty;
    private final String ldapUEmailProperty;
    private final String ldapBindAccount;
    private final String ldapBindPassword;
    private final List<String> ldapAllowedGroups;
    private final List<String> ldapAdminGroups;
    private final String ldapGroupSearchBase;
    private final boolean ldapEmbeddedGroups;

    // Support local salt account for admin privileges
    private final String localSaltAccount;
    private final String localSaltPassword;

    public LdapUserManager(Props props) {
        ldapHost = props.getString(LDAP_HOST);
        ldapPort = props.getInt(LDAP_PORT);
        useSsl = props.getBoolean(LDAP_USE_SSL);
        ldapUserBase = props.getString(LDAP_USER_BASE);

        Dn userBaseDn = null;
        try {
            userBaseDn = parseDn(ldapUserBase);
        } catch (LdapInvalidDnException e) {
            logger.error("Failed parsing user base DN: " + ldapUserBase);
            e.printStackTrace();
        }

        ldapUserBaseDn = userBaseDn;

        ldapUserIdProperty = props.getString(LDAP_USER_ID_PROPERTY);
        ldapUEmailProperty = props.getString(LDAP_EMAIL_PROPERTY);
        ldapBindAccount = props.getString(LDAP_BIND_ACCOUNT);
        ldapBindPassword = props.getString(LDAP_BIND_PASSWORD);
        ldapAllowedGroups = props.getStringList(LDAP_ALLOWED_GROUPS);
        ldapAdminGroups = props.getStringList(LDAP_ADMIN_GROUPS);
        ldapGroupSearchBase = props.getString(LDAP_GROUP_SEARCH_BASE);
        ldapEmbeddedGroups = props.getBoolean(LDAP_EMBEDDED_GROUPS, false);
        // Support local salt account for admin privileges
        localSaltAccount = props.getString(LOCAL_SALT_ACCOUNT).trim();
        localSaltPassword = props.getString(LOCAL_SALT_PASSWORD);
    }

    @Override
    public User getUser(String username, String password) throws UserManagerException {
        logger.info("Logging in user " + username);
        if (username == null || username.trim().isEmpty()) {
            throw new UserManagerException("Username is empty.");
        } else if (password == null || password.trim().isEmpty()) {
            throw new UserManagerException("Password is empty.");
        }

        // Support local salt account for admin privileges
        if (username.trim().equals(localSaltAccount) && password.equals(localSaltPassword)) {
            User user = new User(username.trim());
            logger.info("Granting admin access to salt user: " + username);
            user.addRole("admin");
            return user;
        }

        LdapConnection connection = null;
        SearchCursor cursor = null;

        try {
            connection = getLdapConnection();

            SearchRequest searchRequest = new SearchRequestImpl();

            String ldapSearchFilter = "(" + escapeLDAPSearchFilter(ldapUserIdProperty + "=" + username) + ")";
            searchRequest.setFilter(ldapSearchFilter);
            searchRequest.setScope(SearchScope.SUBTREE);
            searchRequest.setBase(ldapUserBaseDn);

            // This is important so that we can determine how many users was found only by iterating with cursor.next()
            searchRequest.ignoreReferrals();

            cursor = connection.search(searchRequest);

            if (!cursor.next()) {
                throw new UserManagerException("No user " + username + " found");
            }

            final Entry entry = cursor.getEntry();

            String userId = getUserId(entry);

            // Check that only one user was found
            while (cursor.next()) {

                // May be referral, intermediate, done ...
                if (cursor.isEntry()) {
                    Entry nextEntry = cursor.getEntry();

                    if (!getUserId(nextEntry).equals(userId)) {
                        throw new UserManagerException("More than one user found");
                    }
                }
            }

            if (!isMemberOfGroups(connection, entry, ldapAllowedGroups)) {
                throw new UserManagerException("User is not member of allowed groups");
            }

            // Validate credentials
            connection.bind(entry.getDn(), password);

            User user = new User(userId);

            if (ldapUEmailProperty.length() > 0) {
                Attribute emailAttribute = entry.get(ldapUEmailProperty);

                if (emailAttribute != null)
                    user.setEmail(emailAttribute.getString());
            }

            for (String group : getMemberOfGroups(user, entry)) {
                logger.info("User " + username + " is in group: " + group);
                user.addGroup(group);
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
        } finally {
            try {
                if (cursor != null)
                    cursor.close();

                if (connection != null) {
                    connection.close();
                }
            } catch (IOException e) {
                throw new UserManagerException("IO error", e);
            }
        }
    }

    /**
     * Returns userId from configured userIdProperty
     *
     * @param entry
     * @return
     * @throws UserManagerException
     * @throws LdapInvalidAttributeValueException
     */
    private String getUserId(Entry entry) throws UserManagerException, LdapInvalidAttributeValueException {

        Attribute idAttribute = entry.get(ldapUserIdProperty);

        if (idAttribute == null) {
            throw new UserManagerException("Invalid id property name " + ldapUserIdProperty);
        }

        return idAttribute.getString();
    }

    /**
     * Processes LDAP's "memberof" fields & parses the CN value, which is then added to returned list
     *
     * @param user
     * @param entry
     * @return memberOfGroups
     */
    private List<String> getMemberOfGroups(User user, Entry entry) {

        List<String> memberOfGroups = new ArrayList<>();

        Attribute groups = entry.get("memberof");

        for (Value groupValue : groups) {
            String groupLdap = (String) groupValue.getValue();

            // Get only the CN value (from memberOf='cn=JON User Group,ou=groups,dc=example,dc=com')
            String groupCn = groupLdap.split(",")[0];

            // strip the "cn="
            String group = groupCn.substring(3).toLowerCase();

            memberOfGroups.add(group);
        }

        return memberOfGroups;
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
            return false;
        }
    }

    /**
     * Tests if the attribute contains a given value (case insensitive)
     *
     * @param expected  the expected value
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

        // Support local salt account for admin privileges
        if (username.trim().equals(localSaltAccount)) {
            return true;
        }

        LdapConnection connection = null;
        SearchCursor cursor = null;

        try {
            connection = getLdapConnection();

            SearchRequest searchRequest = new SearchRequestImpl();

            String ldapSearchFilter = "(" + escapeLDAPSearchFilter(ldapUserIdProperty + "=" + username) + ")";
            searchRequest.setFilter(ldapSearchFilter);
            searchRequest.setScope(SearchScope.SUBTREE);
            searchRequest.setBase(ldapUserBaseDn);

            // This is important so that we can determine how many users was found only by iterating with cursor.next()
            searchRequest.ignoreReferrals();

            cursor = connection.search(searchRequest);

            if (!cursor.next()) {
                logger.info("User doesn't exist");
                return false;
            }


            final Entry entry = cursor.getEntry();

            if (!isMemberOfGroups(connection, entry, ldapAllowedGroups)) {
                logger.info("User is not in allowed groups" + ldapAllowedGroups);
                return false;
            }

            String userId = getUserId(entry);

            // Check that only one user was found
            while (cursor.next()) {

                // May be referral, intermediate, done ...
                if (cursor.isEntry()) {
                        return false;
                }
            }

            return true;

        } catch (LdapException e) {
            return false;
        } catch (CursorException e) {
            return false;
        } catch (UserManagerException e) {
            return false;
        } finally {
            try {
                if (cursor != null)
                    cursor.close();

                if (connection != null) {
                    connection.close();
                }
            } catch (IOException e) {
                return false;
            }
        }
    }

    /**
     * Creates Dn object from string
     *
     * @param dnStr
     * @return
     * @throws LdapInvalidDnException
     */
    private Dn parseDn(String dnStr) throws LdapInvalidDnException {

        Dn dn = new Dn();
        String[] dnStrSplitted = dnStr.split(",");
        for (int i = dnStrSplitted.length; i > 0; ) {
            String rdnVal = dnStrSplitted[--i];
            Rdn rdn = new Rdn(rdnVal);
            dn = dn.add(rdn);
        }

        return dn;
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
