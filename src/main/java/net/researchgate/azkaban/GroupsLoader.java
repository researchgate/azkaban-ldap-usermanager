package net.researchgate.azkaban;

import azkaban.user.Permission;
import azkaban.user.Role;
import org.w3c.dom.*;
import org.xml.sax.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Loads groups from an XML file.
 */
class GroupsLoader {

    private static final String DEFAULT_ROLE_NAME = "admin";
    private static final String XML_DTD_FILE_PATH = "/azkaban-groups.dtd";

    Map<String, Group> loadFromFile(String filePath) {
        File file = loadFile(filePath);
        Document document = loadDocument(file);

        if (document == null) {
            return null;
        }

        NodeList nodes = document.getChildNodes();
        Element rootElement = (Element)nodes.item(1);

        Map<String, Role> roles = parseRoles(rootElement);

        return parseGroups(rootElement, roles);
    }

    Map<String, Group> loadFromList(List<String> list) {
        Map<String, Group> groups = new HashMap<>();

        for (String groupName : list) {
            Permission permission = new Permission();
            permission.addPermission(Permission.Type.ADMIN);

            Role role = new Role(DEFAULT_ROLE_NAME, permission);

            Group group = new Group(groupName);
            group.addRole(role);

            groups.put(group.getName(), group);
        }

        return groups;
    }

    private Map<String, Role> parseRoles(Element rootElement) {
        NodeList roleNodes = rootElement.getElementsByTagName("role");
        Map<String, Role> roles = new HashMap<>();

        for (int i = 0; i < roleNodes.getLength(); i++) {
            NamedNodeMap attributes = roleNodes.item(i).getAttributes();
            Node nameAttribute = attributes.getNamedItem("name");
            Node permissionsAttribute = attributes.getNamedItem("permissions");

            Permission permission = new Permission();

            permission.addPermissionsByName(
                    permissionsAttribute.getNodeValue().split("\\s+")
            );

            String roleName = nameAttribute.getNodeValue();

            Role role = new Role(roleName, permission);
            roles.put(roleName, role);
        }

        return roles;
    }

    private Map<String, Group> parseGroups(Element rootElement, Map<String, Role> roles) {
        NodeList groupNodes = rootElement.getElementsByTagName("group");
        Map<String, Group> groups = new HashMap<>();

        for (int i = 0; i < groupNodes.getLength(); i++) {
            NamedNodeMap attributes = groupNodes.item(i).getAttributes();
            Node nameNode = attributes.getNamedItem("name");
            Node rolesNode = attributes.getNamedItem("roles");

            String groupName = nameNode.getNodeValue();

            Group group = new Group(groupName);

            String[] roleNames = rolesNode.getNodeValue().split("\\s+");

            for (String roleName : roleNames) {
                Role role = roles.get(roleName);
                group.addRole(role);
            }

            groups.put(groupName, group);
        }

        return groups;
    }

    private File loadFile(String path) {
        if (path == null || path.isEmpty()) {
            throw new IllegalArgumentException("Groups file can not be empty.");
        }

        File file = new File(path);

        if (!file.exists()) {
            throw new IllegalArgumentException(
                    String.format("Groups file does not exists: '%s'", path)
            );
        }

        return file;
    }

    private Document loadDocument(File file) {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setValidating(true);

        DocumentBuilder builder;

        try {
            builder = factory.newDocumentBuilder();
        } catch (ParserConfigurationException exception) {
            throw new IllegalArgumentException(
                    "Exception while parsing user xml. Document builder not created.", exception);
        }

        builder.setEntityResolver(new EntityResolver() {
            @Override
            public InputSource resolveEntity(String publicId, String systemId) throws SAXException, IOException {
                return new InputSource(getClass().getResourceAsStream(XML_DTD_FILE_PATH));
            }
        });

        builder.setErrorHandler(new ErrorHandler() {
            @Override
            public void warning(SAXParseException exception) throws SAXException {
                throw new IllegalArgumentException(
                        String.format("Xml file is malformed: '%s'", exception.toString()));
            }

            @Override
            public void error(SAXParseException exception) throws SAXException {
                throw new IllegalArgumentException(
                        String.format("Xml file is malformed: '%s'", exception.toString()));
            }

            @Override
            public void fatalError(SAXParseException exception) throws SAXException {
                exception.printStackTrace();throw new IllegalArgumentException(
                        String.format("Xml file is malformed: '%s'", exception.toString()));
            }
        });

        Document document;

        try {
            document = builder.parse(file);
        } catch (SAXException | IOException exception) {
            throw new IllegalArgumentException(
                    String.format("Invalid XML: '%s'", file),
                    exception);
        }

        return document;
    }
}
