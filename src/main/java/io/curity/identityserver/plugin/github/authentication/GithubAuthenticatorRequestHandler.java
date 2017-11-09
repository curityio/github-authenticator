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

package io.curity.identityserver.plugin.github.authentication;

import com.google.common.collect.ImmutableMap;
import io.curity.identityserver.plugin.authentication.CodeFlowOAuthClient;
import io.curity.identityserver.plugin.authentication.OAuthClient;
import io.curity.identityserver.plugin.github.config.GithubAuthenticatorPluginConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.authentication.AuthenticationResult;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.util.Map;
import java.util.Optional;

import static io.curity.identityserver.plugin.authentication.Constants.Params.PARAM_REDIRECT_URI;

public class GithubAuthenticatorRequestHandler implements AuthenticatorRequestHandler<RequestModel> {
    private static final Logger _logger = LoggerFactory.getLogger(GithubAuthenticatorRequestHandler.class);

    private final GithubAuthenticatorPluginConfig _config;
    private final OAuthClient _oauthClient;

    public GithubAuthenticatorRequestHandler(GithubAuthenticatorPluginConfig config,
                                               ExceptionFactory exceptionFactory,
                                               Json json,
                                               AuthenticatorInformationProvider provider) {
        _config = config;
        _oauthClient = new CodeFlowOAuthClient(exceptionFactory, provider, json, config.getSessionManager());
    }

    @Override
    public Optional<AuthenticationResult> get(RequestModel requestModel, Response response) {
        _logger.info("GET request received for authentication authentication");

        _oauthClient.setServiceProviderId(requestModel.getRequest());
        return requestAuthentication(response, ImmutableMap.of(PARAM_REDIRECT_URI, _oauthClient.getCallbackUrl()));
    }

    @Override
    public Optional<AuthenticationResult> post(RequestModel requestModel, Response response) {
        return Optional.empty();
    }

    @Override
    public RequestModel preProcess(Request request, Response response) {
        return new RequestModel(request);
    }

    public Optional<AuthenticationResult> requestAuthentication(Response response, Map<String, String> extraAuthorizeParameters) {
        ImmutableMap.Builder<String, String> builder = ImmutableMap.<String, String>builder()
                .putAll(extraAuthorizeParameters);


        _oauthClient.redirectToAuthorizationEndpoint(response,
                _config.getAuthorizationEndpoint().toString(),
                _config.getClientId(),
                _config.getScope(), builder.build());

        return Optional.empty();
    }
}
