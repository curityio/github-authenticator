Github Authenticator Plugin
=============================

Github Oauth Authenticator plugin for the Curity Identity Server.

Create `Github app`_

Create Github Authenticator and configure following values.

Config
~~~~~~

+-------------------+--------------------------------------------------+-----------------------------+
| Name              | Default                                          | Description                 |
+===================+==================================================+=============================+
| ``Client ID``     |                                                  | Github app client id        |
|                   |                                                  |                             |
+-------------------+--------------------------------------------------+-----------------------------+
| ``Client Secret`` |                                                  | Github app secret key       |
|                   |                                                  |                             |
+-------------------+--------------------------------------------------+-----------------------------+
| ``Authorization`` | https://github.com/login/oauth/authorize         | URL to the Github           |
| ``Endpoint``      |                                                  | authorization endpoint      |
|                   |                                                  |                             |
+-------------------+--------------------------------------------------+-----------------------------+
| ``Token``         | https://github.com/login/oauth/access_token      | URL to the Github           |
| ``Endpoint``      |                                                  | authorization endpoint      |
+-------------------+--------------------------------------------------+-----------------------------+
| ``Scope``         |                                                  | A space-separated list of   |
|                   |                                                  | scopes to request from      |
|                   |                                                  | Github                      |
+-------------------+--------------------------------------------------+-----------------------------+
| ``User Info``     | https://api.github.com/user                      | URL to the Github           |
| ``Endpoint``      |                                                  | userinfo(profile) endpoint  |
|                   |                                                  |                             |
+-------------------+--------------------------------------------------+-----------------------------+

Build plugin
~~~~~~~~~~~~

First, collect credentials to the Curity Nexus, to be able to fetch the SDK. Add nexus credentials in maven settings.

Then, build the plugin by: ``mvn clean package``

Install plugin
~~~~~~~~~~~~~~

| To install a plugin into the server, simply drop its jars and all of
  its required resources, including Server-Provided Dependencies, in the
  ``<plugin_group>`` directory.
| Please visit `curity.io/plugins`_ for more information about plugin
  installation.

Required dependencies/jars
"""""""""""""""""""""""""""""""""""""

Following jars must be in plugin group classpath.

-  `commons-codec-1.9.jar`_
-  `commons-logging-1.2.jar`_
-  `google-collections-1.0-rc2.jar`_
-  `httpclient-4.5.jar`_
-  `httpcore-4.4.1.jar`_
-  `identityserver.plugins.authenticators-1.0.0.jar`_

Please visit `curity.io`_ for more information about the Curity Identity
Server.

.. _Github app: https://github.com/settings/applications/new
.. _curity.io/plugins: https://support.curity.io/docs/latest/developer-guide/plugins/index.html#plugin-installation
.. _commons-codec-1.9.jar: http://central.maven.org/maven2/commons-codec/commons-codec/1.9/commons-codec-1.9.jar
.. _commons-logging-1.2.jar: http://central.maven.org/maven2/commons-logging/commons-logging/1.2/commons-logging-1.2.jar
.. _google-collections-1.0-rc2.jar: http://central.maven.org/maven2/com/google/collections/google-collections/1.0-rc2/google-collections-1.0-rc2.jar
.. _httpclient-4.5.jar: http://central.maven.org/maven2/org/apache/httpcomponents/httpclient/4.5/httpclient-4.5.jar
.. _httpcore-4.4.1.jar: http://central.maven.org/maven2/org/apache/httpcomponents/httpcore/4.4.1/httpcore-4.4.1.jar
.. _identityserver.plugins.authenticators-1.0.0.jar: https://github.com/curityio/authenticator-plugin
.. _curity.io: https://curity.io/
