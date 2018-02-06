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
import se.curity.identityserver.sdk.config.annotation.DefaultBoolean;
import se.curity.identityserver.sdk.config.annotation.DefaultEnum;
import se.curity.identityserver.sdk.config.annotation.Description;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.HttpClient;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.service.WebServiceClientFactory;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;

import java.util.Optional;

@SuppressWarnings("InterfaceNeverImplemented")
public interface GitHubAuthenticatorPluginConfig extends Configuration
{
    @Description("client id")
    String getClientId();

    @Description("Secret key used for communication with github")
    String getClientSecret();

    @Description("Enable the application to manage an organization in GitHub")
    Optional<ManageOrganization> getManageOrganization();

    WebServiceClientFactory getWebServiceClientFactory();

    enum Access
    {
        NONE, WRITE, READ, READ_WRITE
    }

    interface ManageOrganization
    {
        @Description("Name of the organization to check that the user is a member of")
        Optional<String> getOrganizationName();

        @Description("The level of access to the organization's data that the application requires")
        @DefaultEnum("READ")
        Access getAccess();
    }

    @Description("Enable the application to manage repositories in GitHub")
    Optional<ManageRepo> getManageRepo();

    interface ManageRepo
    {
        @Description("Request a scope (repo:status) that grants read/write access to public and private repository " +
                "commit statuses. This scope is only necessary to grant other users or services access to private " +
                "repository commit statuses without granting access to the code.")
        @DefaultBoolean(true)
        boolean isReadWriteCommitStatus();

        @Description("Request a scope (repo_deployment) that grants access to deployment statuses for public and " +
                "private repositories. This scope is only necessary to grant other users or services access to " +
                "deployment statuses, without granting access to the code.")
        @DefaultBoolean(true)
        boolean isDeploymentStatusesAccess();

        @Description("Request a scope (public_repo) that grants read/write access to code, commit statuses, " +
                "collaborators, and deployment statuses for public repositories and organizations. Also required for " +
                "starring public repositories.")
        @DefaultBoolean(true)
        boolean isPublicReposAccess();

        @Description("Request a scope (repo:invite) that grants accept/decline abilities for invitations to " +
                "collaborate on a repository. This scope is only necessary to grant other users or services access to" +
                " invites without granting access to the code.")
        @DefaultBoolean(true)
        boolean isInviteAccess();
    }

    @Description("Enable the application to manage public keys in GitHub")
    @DefaultEnum("NONE")
    Access getPublicKeysAccess();

    @Description("Enable the application to manage hooks in GitHub")
    @DefaultEnum("NONE")
    Access getRepoHooksAccess();

    @Description("Request a scope (admin:org_hook) that grants read, write, ping, and delete access to organization " +
            "hooks.")
    @DefaultBoolean(false)
    boolean isOrganizationHooks();

    @Description("Request a scope (gist) that grants write access to gists.")
    @DefaultBoolean(false)
    boolean isGistsAccess();

    @Description("Request a scope (notifications) that grants read access to a user's notifications.")
    @DefaultBoolean(false)
    boolean isNotificationsAccess();

    @Description("Enable the application to manage user in GitHub")
    Optional<ManageUser> getManageUser();

    interface ManageUser
    {
        @Description("Request a scope (user:email) that grants read access to a user's email addresses")
        @DefaultBoolean(false)
        boolean isEmailAccess();

        @Description("Request a scope (user:follow) that grants access to follow or unfollow other users.")
        @DefaultBoolean(false)
        boolean isFollowAccess();
    }

    @Description("Request a scope (delete_repo) that grants access to delete adminable repositories.")
    @DefaultBoolean(false)
    boolean isDeleteRepo();

    @Description("Enable the application to manage GPG keys in GitHub")
    @DefaultEnum("NONE")
    Access getGpgKeysAccess();

    // Services that don't require any configuration

    Json getJson();

    SessionManager getSessionManager();

    Optional<HttpClient> getHttpClient();

    ExceptionFactory getExceptionFactory();

    AuthenticatorInformationProvider getAuthenticatorInformationProvider();
}
