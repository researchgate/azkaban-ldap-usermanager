Azkaban Ldap UserManager
========================

[![Build Status](https://travis-ci.org/researchgate/azkaban-ldap-usermanager.svg?branch=master)](https://travis-ci.org/researchgate/azkaban-ldap-usermanager)

This plugin enables ldap authentication for the Azkaban workflow manager (https://azkaban.github.io/)

This plugin is work in progress, configuration options may change.

Installation
------------

Build the plugin

```
gradle build
```

and place the created jar from ./build/libs into the ./extlib folder of Azkaban (see also http://azkaban.github.io/azkaban/docs/latest/#custom-usermanager) for details.

In your azkaban.properties file set the UserManager to the new Ldap one:

```
user.manager.class=net.researchgate.azkaban.LdapUserManager
```

Configuration
-------------

The following configuration options are currently available:

```
user.manager.ldap.host=ldap.example.com
user.manager.ldap.port=636
user.manager.ldap.useSsl=true
user.manager.ldap.userBase=dc=example,dc=com
user.manager.ldap.userIdProperty=uid
user.manager.ldap.emailProperty=mail
user.manager.ldap.bindAccount=cn=read-only-admin,dc=example,dc=com
user.manager.ldap.bindPassword=password
user.manager.ldap.allowedGroups=azkaban-ldap-group
user.manager.ldap.groupSearchBase=ou=Groups,dc=example,dc=com
user.manager.ldap.embeddedGroups=false
```

Embedded Groups
---------------

Some LDAP schemas return the list of groups to which a DN belongs as a
<List>memberOf attribute.  To use that group list, set
```user.manager.ldap.embeddedGroups=true```.  Note: the lookup will be
case-sensitive.

Release new version
-------------------
To release a new version you need to set the property "githubToken" in your "gradle.proeprties" inside your gradle home directory that is usually "~/.gradle/".
If the "gradle.properties" file doesn't exists you need to create it.

The token can be created under https://github.com/settings/tokens. And an example of the config is like:

![Github Token example config](https://github.com/researchgate/azkaban-ldap-usermanager/raw/master/doc/github_token_settings.png)

If this is done you can run the release task in gradle.
```
    gradle release
```
