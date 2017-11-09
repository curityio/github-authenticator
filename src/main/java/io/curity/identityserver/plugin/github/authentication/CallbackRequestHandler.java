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

import io.curity.identityserver.plugin.authentication.CodeFlowOAuthClient;
import io.curity.identityserver.plugin.authentication.OAuthClient;
import io.curity.identityserver.plugin.github.config.GithubAuthenticatorPluginConfig;
import se.curity.identityserver.sdk.authentication.AuthenticationResult;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.util.Map;
import java.util.Optional;

import static io.curity.identityserver.plugin.authentication.Constants.Params.PARAM_ACCESS_TOKEN;

public class CallbackRequestHandler
        implements AuthenticatorRequestHandler<CallbackGetRequestModel> {
    private final ExceptionFactory _exceptionFactory;
    private final OAuthClient _oauthClient;
    private final GithubAuthenticatorPluginConfig _config;

    public CallbackRequestHandler(ExceptionFactory exceptionFactory,
                                  AuthenticatorInformationProvider provider,
                                  Json json,
                                  GithubAuthenticatorPluginConfig config) {
        _exceptionFactory = exceptionFactory;
        _oauthClient = new CodeFlowOAuthClient(exceptionFactory, provider, json, config.getSessionManager());
        _config = config;
    }

    @Override
    public CallbackGetRequestModel preProcess(Request request, Response response) {
        if (request.isGetRequest()) {
            return new CallbackGetRequestModel(request);
        } else {
            throw _exceptionFactory.methodNotAllowed();
        }
    }

    @Override
    public Optional<AuthenticationResult> get(CallbackGetRequestModel requestModel,
                                              Response response) {
        _oauthClient.redirectToAuthenticationOnError(requestModel.getRequest(), _config.id());

        Map<String, Object> tokenMap = _oauthClient.getTokens(_config.getTokenEndpoint().toString(),
                _config.getClientId(),
                _config.getClientSecret(),
                requestModel.getCode(),
                requestModel.getState());
        return _oauthClient.getAuthenticationResult(tokenMap.get(PARAM_ACCESS_TOKEN).toString(), _config.getUserInfoEndpoint().toString());
    }

    @Override
    public Optional<AuthenticationResult> post(CallbackGetRequestModel requestModel,
                                               Response response) {
        throw _exceptionFactory.methodNotAllowed();
    }

}
