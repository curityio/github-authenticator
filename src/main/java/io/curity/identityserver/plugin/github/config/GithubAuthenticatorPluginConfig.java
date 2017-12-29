/*
 *  Copyright 2017 Curity AB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package io.curity.identityserver.plugin.github.config;

import se.curity.identityserver.sdk.config.Configuration;
import se.curity.identityserver.sdk.config.OneOf;
import se.curity.identityserver.sdk.config.annotation.DefaultBoolean;
import se.curity.identityserver.sdk.config.annotation.DefaultEnum;
import se.curity.identityserver.sdk.config.annotation.DefaultString;
import se.curity.identityserver.sdk.config.annotation.DefaultURI;
import se.curity.identityserver.sdk.config.annotation.Description;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.HttpClient;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.service.WebServiceClientFactory;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;

import java.net.URI;
import java.util.Optional;

@SuppressWarnings("InterfaceNeverImplemented")
public interface GithubAuthenticatorPluginConfig extends Configuration {
    @Description("client id")
    String getClientId();

    @Description("Secret key used for communication with github")
    String getClientSecret();

    @Description("URL to the Github token endpoint")
    @DefaultURI("https://github.com/login/oauth/access_token")
    URI getTokenEndpoint();

    @Description("URL to the Github user info endpoint")
    @DefaultURI("https://api.github.com/user")
    URI getUserInfoEndpoint();

    Optional<ManageOrganization> getManageOrganization();

    WebServiceClientFactory getWebServiceClientFactory();

    interface ManageOrganization
    {

        @Description("Name of the organization to check that the user is a member of")
        String getOrganizationName();
        Access getAccess();
        @DefaultEnum("READ")
        enum Access
        {
            WRITE, READ, READ_WRITE;

        }
    }
    // Services that don't require any configuration

    Json getJson();
    
    SessionManager getSessionManager();

    Optional<HttpClient> getHttpClient();

    ExceptionFactory getExceptionFactory();

    AuthenticatorInformationProvider getAuthenticatorInformationProvider();
}
