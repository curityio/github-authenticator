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

import io.curity.identityserver.plugin.github.config.GithubAuthenticatorPluginConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.attribute.Attribute;
import se.curity.identityserver.sdk.authentication.AuthenticationResult;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.errors.ErrorCode;
import se.curity.identityserver.sdk.http.HttpResponse;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.HttpClient;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.WebServiceClient;
import se.curity.identityserver.sdk.service.WebServiceClientFactory;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.net.URI;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import static se.curity.identityserver.sdk.http.HttpRequest.createFormUrlEncodedBodyProcessor;

public class CallbackRequestHandler implements AuthenticatorRequestHandler<CallbackGetRequestModel>
{
    private static final Logger _logger = LoggerFactory.getLogger(CallbackRequestHandler.class);

    private final ExceptionFactory _exceptionFactory;
    private final GithubAuthenticatorPluginConfig _config;
    private final WebServiceClientFactory _webServiceClientFactory;
    private final AuthenticatorInformationProvider _authenticatorInformationProvider;
    private final Json _json;

    public CallbackRequestHandler(GithubAuthenticatorPluginConfig config)
    {
        _exceptionFactory = config.getExceptionFactory();
        _config = config;
        _json = config.getJson();
        _webServiceClientFactory = config.getWebServiceClientFactory();
        _authenticatorInformationProvider = config.getAuthenticatorInformationProvider();
    }

    @Override
    public CallbackGetRequestModel preProcess(Request request, Response response)
    {
        if (request.isGetRequest())
        {
            return new CallbackGetRequestModel(request);
        }
        else
        {
            throw _exceptionFactory.methodNotAllowed();
        }
    }

    @Override
    public Optional<AuthenticationResult> get(CallbackGetRequestModel requestModel,
                                              Response response)
    {
        validateState(requestModel.getState());
        handleError(requestModel);

        Map<String, Object> tokenResponseData = redeemCodeForTokens(requestModel);
        @Nullable Object accessToken = tokenResponseData.get("access_token");
        Map<String, String> userInfoResponseData = getUserInfo(accessToken);
        List<Attribute> subjectAttributes = new LinkedList<>(), contextAttributes = new LinkedList<>();

        // TODO: Build attribute collections

        // FIXME: Org check
        //checkUserOrganizationMembership(authenticationResult, tokenMap.get(PARAM_ACCESS_TOKEN).toString());

        // TODO: Send back actual authentication result

        return Optional.empty();
    }

    private Map<String, String> getUserInfo(@Nullable Object accessToken)
    {
        if (accessToken == null)
        {
            _logger.warn("No access token was available. Cannot get user info.");

            throw _exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR);
        }

        HttpResponse userInfoResponse = getWebServiceClient("https://api.github.com/user")
                .request()
                .accept("application/json")
                .header("Authorization", "Bearer " + accessToken.toString())
                .get()
                .response();
        int statusCode = userInfoResponse.statusCode();

        if (statusCode != 200)
        {
            if (_logger.isWarnEnabled())
            {
                _logger.warn("Got an error response from the user info endpoint. Error = {}, {}", statusCode,
                        userInfoResponse.body(HttpResponse.asString()));
            }

            throw _exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR);
        }

        return _json.fromJson(userInfoResponse.body(HttpResponse.asString()))
                .entrySet().stream()
                .filter(e -> e.getValue() instanceof String)
                .collect(Collectors.toMap(Map.Entry::getKey, e -> (String)e.getValue()));
    }

    private WebServiceClient getWebServiceClient(String uri)
    {
        Optional<HttpClient> httpClient = _config.getHttpClient();

        if (httpClient.isPresent())
        {
            return _webServiceClientFactory.create(httpClient.get()).withHost(URI.create(uri).getHost());
        }
        else
        {
            return _webServiceClientFactory.create(URI.create(uri));
        }
    }

    private Map<String, Object> redeemCodeForTokens(CallbackGetRequestModel requestModel)
    {
        HttpResponse tokenResponse = getWebServiceClient("https://github.com/login/oauth/access_token")
                .request()
                .contentType("application/x-www-form-urlencoded")
                .body(createFormUrlEncodedBodyProcessor(createPostData(_config.getClientId(),
                        _config.getClientSecret(), requestModel.getCode(), requestModel.getRequestUrl())))
                .post()
                .response();
        int statusCode = tokenResponse.statusCode();

        if (statusCode != 200)
        {
            if (_logger.isInfoEnabled())
            {
                _logger.info("Got error response from token endpoint: error = {}, {}", statusCode,
                        tokenResponse.body(HttpResponse.asString()));
            }

            throw _exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR);
        }

        return _json.fromJson(tokenResponse.body(HttpResponse.asString()));
    }

    private static Map<String, String> createPostData(String clientId, String clientSecret, String code, String callbackUri)
    {
        Map<String, String> data = new HashMap<>(5);

        data.put("client_id", clientId);
        data.put("client_secret", clientSecret);
        data.put("code", code);
        data.put("grant_type", "authorization_code");
        data.put("redirect_uri", callbackUri);

        return data;
    }

//    private void checkUserOrganizationMembership(Optional<AuthenticationResult> authenticationResult, String
//            accessToken)
//    {
//        Attribute loginAttrubute = authenticationResult.get().getAttributes().getSubjectAttributes().get(LOGIN);
//        String username = null;
//        if (loginAttrubute != null)
//        {
//            username = loginAttrubute.getValue().toString();
//        }
//        if (notNullOrEmpty(username) && notNullOrEmpty(_config.getOrganizationName()))
//        {
//            HttpGet getRequest = new HttpGet(ORGANIZATION_MEMBER_CHECK_URL + _config.getOrganizationName() +
//                    "/members/" + username);
//            getRequest.addHeader(AUTHORIZATION, BEARER + accessToken);
//
//            try
//            {
//                HttpResponse response = _client.execute(getRequest);
//                if (response.getStatusLine().getStatusCode() == HttpStatus.NOT_FOUND.getCode())
//                {
//                    _oauthClient.redirectToAuthenticationOnError("org_not_found", "ACCESS DENIED TO ORGANIZATION",
//                            _config.id());
//                }
//
//            }
//            catch (IOException e)
//            {
//                _logger.warn("Could not communicate with organization endpoint", e);
//
//                throw _exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR, "Authentication " +
//                        "failed");
//            }
//        }
//    }

    @Override
    public Optional<AuthenticationResult> post(CallbackGetRequestModel requestModel, Response response)
    {
        throw _exceptionFactory.methodNotAllowed();
    }

    private void handleError(CallbackGetRequestModel requestModel)
    {
        if (!Objects.isNull(requestModel.getError()))
        {

            if ("access_denied".equals(requestModel.getError()))
            {
                _logger.debug("Got an error from StackExchange: {} - {}", requestModel.getError(),
                        requestModel.getErrorDescription());

                throw _exceptionFactory.redirectException(
                        _authenticatorInformationProvider.getAuthenticationBaseUri().toASCIIString());
            }

            _logger.warn("Got an error from StackExchange: {} - {}", requestModel.getError(),
                    requestModel.getErrorDescription());

            throw _exceptionFactory.externalServiceException("Login with StackExchange failed");
        }
    }

    private void validateState(String state)
    {
        @Nullable Attribute sessionAttribute = _config.getSessionManager().get("state");

        if (sessionAttribute != null && state.equals(sessionAttribute.getValueOfType(String.class)))
        {
            _logger.debug("State matches session");
        }
        else
        {
            _logger.debug("State did not match session");

            throw _exceptionFactory.badRequestException(ErrorCode.INVALID_SERVER_STATE, "Bad state provided");
        }
    }
}
