package net.researchgate.azkaban;

import azkaban.user.Role;
import azkaban.user.User;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A group to which Azkaban users belong to.
 * It is used to map groups from the XML file.
 */
class Group {

    private String name;
    private List<Role> roles;

    Group(String name) {
        this.name = name;
        this.roles = new ArrayList<>();
    }

    String getName() {
        return name;
    }

    void addRole(Role role) {
        roles.add(role);
    }

    List<Role> getRoles() {
        return Collections.unmodifiableList(roles);
    }

    void assignRolesToUser(User user) {
        for (Role role : roles) {
            if (!user.hasRole(role.getName())) {
                user.addRole(role.getName());
            }
        }
    }
}
