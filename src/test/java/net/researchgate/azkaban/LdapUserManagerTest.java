package net.researchgate.azkaban;

import azkaban.user.Role;
import azkaban.user.User;
import azkaban.user.UserManagerException;
import azkaban.utils.Props;
import java.util.List;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.zapodot.junit.ldap.EmbeddedLdapRule;
import org.zapodot.junit.ldap.EmbeddedLdapRuleBuilder;

import static org.junit.Assert.*;

public class LdapUserManagerTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Rule
    public EmbeddedLdapRule embeddedLdapRule = EmbeddedLdapRuleBuilder
            .newInstance()
            .usingDomainDsn("dc=example,dc=com")
            .withSchema("custom-schema.ldif")
            .importingLdifs("default.ldif")
            .bindingToPort(11389)
            .usingBindDSN("cn=read-only-admin,dc=example,dc=com")
            .usingBindCredentials("password")
            .build();

    private LdapUserManager userManager;

    @Before
    public void setUp() throws Exception {
        Props props = getProps();
        userManager = new LdapUserManager(props);
    }

    private Props getProps() {
        Props props = new Props();

        props.put(LdapUserManager.XML_FILE_PARAM, "azkaban-users.xml");

        props.put(LdapUserManager.LDAP_HOST, "localhost");
        props.put(LdapUserManager.LDAP_PORT, "11389");
        props.put(LdapUserManager.LDAP_USE_SSL, "false");
        props.put(LdapUserManager.LDAP_USER_BASE, "dc=example,dc=com");
        props.put(LdapUserManager.LDAP_USERID_PROPERTY, "uid");
        props.put(LdapUserManager.LDAP_EMAIL_PROPERTY, "mail");
        props.put(LdapUserManager.LDAP_BIND_ACCOUNT, "cn=read-only-admin,dc=example,dc=com");
        props.put(LdapUserManager.LDAP_BIND_PASSWORD, "password");
        props.put(LdapUserManager.LDAP_ALLOWED_GROUPS, "");
        props.put(LdapUserManager.LDAP_ADMIN_GROUPS, "admin");
        props.put(LdapUserManager.LDAP_GROUP_SEARCH_BASE, "dc=example,dc=com");
        return props;
    }

    @Test
    public void testGetXmlAdminUser() throws Exception {
        User user = userManager.getUser("admin", "admin");
        List <String> roles = user.getRoles();
        Role role = userManager.getRole(roles.get(0));

        assertEquals("admin", user.getUserId());
        assertEquals(1, roles.size());
        assertTrue(role.getPermission().isPermissionNameSet("ADMIN"));
    }

    @Test
    public void testGetXmlReadUser() throws Exception {
        User user = userManager.getUser("read", "read");
        List <String> roles = user.getRoles();
        Role role = userManager.getRole(roles.get(0));

        assertEquals("read", user.getUserId());
        assertEquals(1, roles.size());
        assertTrue(role.getPermission().isPermissionNameSet("READ"));
    }

    @Test
    public void testGetLdapUser() throws Exception {
        User user = userManager.getUser("gauss", "password");
        List <String> roles = user.getRoles();
        Role role = userManager.getRole(roles.get(0));

        assertEquals("gauss", user.getUserId());
        assertEquals("gauss@ldap.example.com", user.getEmail());
        assertEquals(1, roles.size());
        assertTrue(role.getPermission().isPermissionNameSet("READ"));
    }

    @Test
    public void testGetLdapUserWithAllowedGroup() throws Exception {
        Props props = getProps();
        props.put(LdapUserManager.LDAP_ALLOWED_GROUPS, "svc-test");
        final LdapUserManager manager = new LdapUserManager(props);

        User user = manager.getUser("gauss", "password");

        assertEquals("gauss", user.getUserId());
        assertEquals("gauss@ldap.example.com", user.getEmail());
    }

    @Test
    public void testGetLdapUserWithAllowedGroupThatGroupOfNames() throws Exception {
        Props props = getProps();
        props.put(LdapUserManager.LDAP_ALLOWED_GROUPS, "svc-test2");
        final LdapUserManager manager = new LdapUserManager(props);

        User user = manager.getUser("gauss", "password");

        assertEquals("gauss", user.getUserId());
        assertEquals("gauss@ldap.example.com", user.getEmail());
    }


    @Test
    public void testGetLdapUserWithEmbeddedGroup() throws Exception {
        Props props = getProps();
        props.put(LdapUserManager.LDAP_ALLOWED_GROUPS, "svc-test");
        props.put(LdapUserManager.LDAP_EMBEDDED_GROUPS, "true");
        final LdapUserManager manager = new LdapUserManager(props);

        User user = manager.getUser("gauss", "password");

        assertEquals("gauss", user.getUserId());
        assertEquals("gauss@ldap.example.com", user.getEmail());
    }

    @Test
    public void testGetLdapUserWithInvalidPasswordThrowsUserManagerException() throws Exception {
        thrown.expect(UserManagerException.class);
        userManager.getUser("gauss", "invalid");
    }

    @Test
    public void testGetLdapUserWithInvalidUsernameThrowsUserManagerException() throws Exception {
        thrown.expect(UserManagerException.class);
        userManager.getUser("invalid", "password");
    }

    @Test
    public void testGetLdapUserWithEmptyPasswordThrowsUserManagerException() throws Exception {
        thrown.expect(UserManagerException.class);
        userManager.getUser("gauss", "");
    }

    @Test
    public void testGetLdapUserWithEmptyUsernameThrowsUserManagerException() throws Exception {
        thrown.expect(UserManagerException.class);
        userManager.getUser("", "invalid");
    }

    @Test
    public void testValidateUser() throws Exception {
        assertTrue(userManager.validateUser("gauss"));
        assertFalse(userManager.validateUser("invalid"));
    }

    @Test
    public void testGetRole() throws Exception {
        Role role = userManager.getRole("admin");

        assertTrue(role.getPermission().isPermissionNameSet("ADMIN"));
    }

    @Test
    public void testInvalidEmailPropertyDoesNotThrowNullPointerException() throws Exception {
        Props props = getProps();
        props.put(LdapUserManager.LDAP_EMAIL_PROPERTY, "invalidField");
        userManager = new LdapUserManager(props);
        User user = userManager.getUser("gauss", "password");

        assertEquals("gauss", user.getUserId());
        assertEquals("", user.getEmail());
    }

    @Test
    public void testInvalidIdPropertyThrowsUserManagerException() throws Exception {
        thrown.expect(UserManagerException.class);

        Props props = getProps();
        props.put(LdapUserManager.LDAP_USERID_PROPERTY, "invalidField");
        userManager = new LdapUserManager(props);
        userManager.getUser("gauss", "password");
    }

    @Test
    public void testEscapeLDAPSearchFilter() throws Exception {
        assertEquals("No special characters to escape", "Hi This is a test #çà", LdapUserManager.escapeLDAPSearchFilter("Hi This is a test #çà"));
        assertEquals("LDAP Christams Tree", "Hi \\28This\\29 = is \\2A a \\5C test # ç à ô", LdapUserManager.escapeLDAPSearchFilter("Hi (This) = is * a \\ test # ç à ô"));
    }
}
