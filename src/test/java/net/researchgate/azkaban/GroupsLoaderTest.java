package net.researchgate.azkaban;

import azkaban.user.Permission;
import azkaban.user.Role;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class GroupsLoaderTest {

    @Test(expected = IllegalArgumentException.class)
    public void testFileDoesNotExists() {
        GroupsLoader loader = new GroupsLoader();
        loader.loadFromFile("does-not-exists.xml");

        fail("GroupsLoader should throw an exception when the file doesn't exist");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFileIsMalformed() {
        String filePath = getClass().getResource("/azkaban-groups-malformed.xml").getFile();
        GroupsLoader loader = new GroupsLoader();
        loader.loadFromFile(filePath);

        fail("GroupsLoader should throw an exception when the file is malformed");
    }

    @Test
    public void testValidFile() {
        String filePath = getClass().getResource("/azkaban-groups.xml").getFile();
        GroupsLoader loader = new GroupsLoader();
        loader.loadFromFile(filePath);

    }

    @Test
    public void testLoadGroupsFromFile() {
        String filePath = getClass().getResource("/azkaban-groups.xml").getFile();
        GroupsLoader loader = new GroupsLoader();
        Map<String, Group> groups = loader.loadFromFile(filePath);

        assertEquals(3, groups.size());

        Group mathematiciansGroup = groups.get("mathematicians");
        List<Role> mathematiciansRoles = mathematiciansGroup.getRoles();

        assertEquals(1, mathematiciansRoles.size());
        assertEquals("administrator", mathematiciansRoles.get(0).getName());
        assertTrue(mathematiciansRoles.get(0).getPermission().isPermissionSet(Permission.Type.ADMIN));

        Group scientistsGroup = groups.get("scientists");
        List<Role> scientistsRoles = scientistsGroup.getRoles();
        Permission vieuwerPermission = scientistsRoles.get(0).getPermission();
        Permission executorPermission = scientistsRoles.get(1).getPermission();

        assertEquals(2, scientistsRoles.size());
        assertTrue(vieuwerPermission.isPermissionSet(Permission.Type.READ));
        assertTrue(executorPermission.isPermissionSet(Permission.Type.WRITE));
        assertTrue(executorPermission.isPermissionSet(Permission.Type.EXECUTE));

        Group viewersGroup = groups.get("viewers");
        List<Role> viewersRoles = viewersGroup.getRoles();
        Permission viewerPermission = viewersRoles.get(0).getPermission();

        assertEquals(2, scientistsRoles.size());
        assertTrue(viewerPermission.isPermissionSet(Permission.Type.READ));
    }

    @Test
    public void testLoadGroupsFromList() {
        List<String> groupNames = new ArrayList<>();
        groupNames.add("mathematicians");
        groupNames.add("scientists");

        GroupsLoader loader = new GroupsLoader();
        Map<String, Group> groups = loader.loadFromList(groupNames);

        assertEquals(2, groups.size());

        Group group = groups.get("mathematicians");
        Role role = group.getRoles().get(0);

        assertEquals("admin", role.getName());
        assertTrue("admin", role.getPermission().isPermissionSet(Permission.Type.ADMIN));
    }
}
