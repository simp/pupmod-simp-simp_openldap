[![License](https://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/73/badge)](https://bestpractices.coreinfrastructure.org/projects/73)
[![Puppet Forge](https://img.shields.io/puppetforge/v/simp/simp_openldap.svg)](https://forge.puppetlabs.com/simp/simp_openldap)
[![Puppet Forge Downloads](https://img.shields.io/puppetforge/dt/simp/simp_openldap.svg)](https://forge.puppetlabs.com/simp/simp_openldap)
[![Build Status](https://travis-ci.org/simp/pupmod-simp-simp_openldap.svg)](https://travis-ci.org/simp/pupmod-simp-simp_openldap)

## This is a SIMP module

This module is a component of the [System Integrity Management Platform](https://simp-project.com),
a compliance-management framework built on Puppet.

If you find any issues, they can be submitted to our [JIRA](https://simp-project.atlassian.net/).

Please read our [Contribution Guide](https://simp.readthedocs.io/en/stable/contributors_guide/index.html).

#### Table of Contents

<!-- vim-markdown-toc GFM -->

* [Description](#description)
* [This is a SIMP module](#this-is-a-simp-module)
* [Setup](#setup)
  * [What simp_openldap affects](#what-simp_openldap-affects)
* [Using simp_openldap](#using-simp_openldap)
  * [As a client](#as-a-client)
  * [As a server](#as-a-server)
* [Advanced configuration](#advanced-configuration)
* [Limitations](#limitations)
* [Development](#development)
  * [Acceptance tests](#acceptance-tests)

<!-- vim-markdown-toc -->

## Description

This module provides a SIMP-oriented profile for configuring OpenLDAP server
and client components.

See [REFERENCE.md](./REFERENCE.md) for API documentation.

## This is a SIMP module

This module is a component of the [System Integrity Management Platform](https://simp-project.com),
a compliance-management framework built on Puppet.

If you find any issues, they can be submitted to our [JIRA](https://simp-project.atlassian.net/).

Please read our [Contribution Guide](https://simp.readthedocs.io/en/stable/contributors_guide/index.html)

This module is optimally designed for use within a larger SIMP ecosystem, but
it can be used independently:

  * When included within the SIMP ecosystem, security compliance settings will
    be managed from the Puppet server.

  * If used independently, all SIMP-managed security subsystems are disabled by
    default and must be explicitly opted into by administrators.  Please review
    the `simp-simp_options` module for details.

## Setup

### What simp_openldap affects

* Installs LDAP client applications for interacting with an LDAP server
* Installs and configures OpenLDAP for TLS-enabled communication using both
  legacy TLS and STARTTLS
* Provides access control capabilities

**NOTE**: As a convenience, this module will configure ``/root/.ldaprc`` with
global variables that facilitate LDAP client communication, *only if* the file
does not already exist. This behavior prevents the module from modifying any
custom configuration you have created, but also means the file will not be
updated when you make module configuration changes that would result in
different ``/root/.ldaprc`` content (e.g., enable/disable use of TLS, change the
TLS certificate filenames, or change the root directory for TLS certificates).
You must remove ``/root/.ldaprc`` and run puppet to pick up the changes.

## Using simp_openldap

### As a client

To use this module for an LDAP client system, just include the class:

```puppet
include 'simp_openldap'
```

### As a server

To use the module to configure an LDAP server, include the following:

```puppet
include 'simp_openldap::server'
```

This will configure a server with TLS and STARTTLS enabled. It will also
populate the directory with a basic LDAP schema suitable for UNIX-system
logins.

To configure the password policy, you will also need to include the
``simp_openldap::slapo::ppolicy`` class **PRIOR TO INITIAL CONFIGURATION**.
Once the LDAP server has been configured, it will not update any data inside of
the LDAP server itself, only the surrounding configuration.

For additional information, please see the [SIMP Documentation](https://simp.readthedocs.io/en/stable).

## Advanced configuration

It is possible to configure most aspects of the OpenLDAP server through this
module. However, this gets complex quickly. The [SIMP Documentation](https://simp.readthedos.io/en/stable)
has some examples. Additional examples can be found in the [acceptance tests](./spec/acceptance/suites).

## Limitations

SIMP Puppet modules are generally intended for use on Red Hat Enterprise Linux
and compatible distributions, such as CentOS. Please see the [`metadata.json` file](./metadata.json)
for the most up-to-date list of supported operating systems, Puppet versions,
and module dependencies.

## Development

Please see the [SIMP Contribution Guidelines](https://simp.readthedocs.io/en/stable/contributors_guide/index.html).


### Acceptance tests

This module includes [Beaker](https://github.com/puppetlabs/beaker) acceptance
tests using the SIMP [Beaker Helpers](https://github.com/simp/rubygem-simp-beaker-helpers).
By default the tests use [Vagrant](https://www.vagrantup.com/) with
[VirtualBox](https://www.virtualbox.org) as a back-end; Vagrant and VirtualBox
must both be installed to run these tests without modification. To execute the
tests run the following:

```shell
bundle install
bundle exec rake beaker:suites
```

Please refer to the [SIMP Beaker Helpers documentation](https://github.com/simp/rubygem-simp-beaker-helpers/blob/master/README.md)
for more information.

Some environment variables may be useful:

```shell
BEAKER_debug=true
BEAKER_provision=no
BEAKER_destroy=no
BEAKER_use_fixtures_dir_for_modules=yes
```

* `BEAKER_debug`: show the commands being run on the STU and their output.
* `BEAKER_destroy=no`: prevent the machine destruction after the tests finish so you can inspect the state.
* `BEAKER_provision=no`: prevent the machine from being recreated. This can save a lot of time while you're writing the tests.
* `BEAKER_use_fixtures_dir_for_modules=yes`: cause all module dependencies to be loaded from the `spec/fixtures/modules` directory, based on the contents of `.fixtures.yml`.  The contents of this directory are usually populated by `bundle exec rake spec_prep`.  This can be used to run acceptance tests to run on isolated networks.
