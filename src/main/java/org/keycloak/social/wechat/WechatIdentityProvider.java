package org.keycloak.social.wechat;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.*;
import org.infinispan.Cache;
import org.infinispan.commons.api.CacheContainerAdmin;
import org.infinispan.configuration.cache.CacheMode;
import org.infinispan.configuration.cache.ConfigurationBuilder;
import org.infinispan.configuration.cache.ConfigurationChildBuilder;
import org.infinispan.configuration.global.GlobalConfigurationBuilder;
import org.infinispan.manager.DefaultCacheManager;
import org.infinispan.manager.EmbeddedCacheManager;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.io.IOException;
import java.net.URI;
import java.util.Objects;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * 微信用户授权登录实现
 */
public class WechatIdentityProvider extends AbstractOAuth2IdentityProvider<WechatIdentityProviderConfig>
        implements SocialIdentityProvider<WechatIdentityProviderConfig> {
    private static final Logger log = Logger.getLogger(WechatIdentityProvider.class);

    // 应用授权作用域，拥有多个作用域用逗号（,）分隔，网页应用目前仅填写snsapi_login即可
    private static final String SCOPE_LOGIN = "snsapi_login";
    // private static final String SCOPE_BASE = "snsapi_base";
    private static final String SCOPE_USERINFO = "snsapi_userinfo";

    private static final String AUTH_URL = "https://open.weixin.qq.com/connect/qrconnect";
    private static final String TOKEN_URL = "https://api.weixin.qq.com/sns/oauth2/access_token";
    private static final String REFRESH_TOKEN_URL = "https://api.weixin.qq.com/sns/oauth2/refresh_token";
    private static final String USERINFO_URL = "https://api.weixin.qq.com/sns/userinfo";

    private static final String OAUTH2_AUTH_URL = "https://open.weixin.qq.com/connect/oauth2/authorize";
    private static final String OAUTH2_PARAMETER_CLIENT_ID = "appid";
    private static final String OAUTH2_PARAMETER_CLIENT_SECRET = "secret";

    private static final String WECHAT_MP_AUTH_URL_1 = "https://api.weixin.qq.com/sns/jscode2session?appid=";
    private static final String WECHAT_MP_AUTH_URL_2 = "&secret=";
    private static final String WECHAT_MP_AUTH_URL_3 = "&js_code=";
    private static final String WECHAT_MP_AUTH_URL_4 = "&grant_type=authorization_code";

    private static final String WECHAT_ACCESS_TOKEN_URL_1 =
            "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=";
    private static final String WECHAT_ACCESS_TOKEN_URL_2 = "&secret=";

    private static final String WECHAT_USER_AGENT = "micromessenger";
    private static final String WECHAT_REDIRECT_FRAGMENT = "wechat_redirect";
    private static final String HTTP_REDIRECT_LOCATION_HEADER = "X-Redirect-Location";

    private static final String UNION_ID = "unionid";
    private static final String OPEN_ID = "openid";
    private static final String SESSION_KEY = "session_key";
    private static final String APP_ID = "appid";
    private static final String USER_ID = "userid";
    private static final String LOGIN_TYPE = "login_type";
    private static final String EXPIRES_IN = "expires_in";

    // 微信 access_token 失效类错误码（触发 refresh_token 刷新）
    private static final int ERR_ACCESS_TOKEN_INVALID = 40001;
    private static final int ERR_ACCESS_TOKEN_ILLEGAL = 40014;
    private static final int ERR_ACCESS_TOKEN_EXPIRED = 42001;

    private static final String WECHAT_CACHE_NAME = "wechatAccessTokens";
    private static final String CACHE_LOCK_PREFIX = "__lock__";
    // 缓存键前缀：区分小程序 client_credential token 与网页授权 token，避免同 appId 互相覆盖
    private static final String MP_CACHE_KEY_PREFIX = "mp:";
    private static final String SNS_CACHE_KEY_PREFIX = "sns:";
    private final Cache<String, String> tokenCache;
    private final String cacheLockMark;

    public WechatIdentityProvider(KeycloakSession session, WechatIdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        config.setUserInfoUrl(USERINFO_URL);
        config.setDefaultScope(SCOPE_LOGIN);

        log.info("Create global cache for wechat access token");
        InfinispanConnectionProvider ispnProvider = session.getProvider(InfinispanConnectionProvider.class);
        EmbeddedCacheManager cacheManager;
        ConfigurationChildBuilder builder = new ConfigurationBuilder();
        if (ispnProvider != null) {
            log.info("Prepare distributed volatile cache with synchronous replication on Infinispan cluster");
            cacheManager = ispnProvider.getCache(InfinispanConnectionProvider.WORK_CACHE_NAME).getCacheManager();
            builder = builder.clustering().cacheMode(CacheMode.REPL_SYNC);
        } else {
            log.warn("Prepare local in-memory Infinispan cache");
            cacheManager = new DefaultCacheManager(new GlobalConfigurationBuilder().nonClusteredDefault().build());
            builder = builder.memory();
        }
        tokenCache = cacheManager.administration().withFlags(CacheContainerAdmin.AdminFlag.VOLATILE)
                                 .getOrCreateCache(WECHAT_CACHE_NAME, builder.build());
        cacheLockMark = CACHE_LOCK_PREFIX +
                        Objects.requireNonNullElse(tokenCache.getCacheManager().getAddress(), "local");
        log.info("WeChat access token cache created, lock mark is " + cacheLockMark);
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new WechatEndpoint(callback, realm, event, this);
    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    @Override
    protected String getDefaultScopes() {
        return SCOPE_LOGIN;
    }

    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        final var authSession = request.getAuthenticationSession();

        var loginHint = authSession.getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
        if (loginHint != null) {
            // 微信小程序需要将appid和code编码到loginHint中
            var sep = loginHint.indexOf(' ');
            if (sep > 0) {
                // 微信小程序
                var appId = loginHint.substring(0, sep);
                var code = loginHint.substring(sep + 1);
                log.info("WeChatMP: appid=" + appId + ", code=" + code);

                authSession.setUserSessionNote(APP_ID, appId);
                authSession.setUserSessionNote(LOGIN_TYPE, WechatLoginType.MINI_PROGRAM.name());
                return UriBuilder.fromUri(URI.create(request.getUriInfo().getAbsolutePath() + "/../endpoint"))
                                 .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
                                 .queryParam(OAUTH2_PARAMETER_CODE, code);
            } else {
                // 微信公众号可以将appid编码到loginHint中
                authSession.setUserSessionNote(APP_ID, loginHint);
                log.info("WeChatOA: appid=" + loginHint);
            }
        }

        final var config = getConfig();
        final var weChatBrowser = isWechatBrowser(request.getHttpRequest().getHttpHeaders());
        final UriBuilder uriBuilder;
        final WechatLoginType loginType;

        if (weChatBrowser) {
            // 微信公众号
            loginType = WechatLoginType.OFFICIAL_ACCOUNT;
            var officialAccountId = config.getWechatOfficialAccountId();
            if (officialAccountId == null) {
                throw new IdentityBrokerException("WeChat Official Account ID is not configured");
            }
            uriBuilder = UriBuilder.fromUri(OAUTH2_AUTH_URL)
                                   .queryParam(OAUTH2_PARAMETER_CLIENT_ID, officialAccountId)
                                   .queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, OAUTH2_PARAMETER_CODE)
                                   .queryParam(OAUTH2_PARAMETER_SCOPE, SCOPE_USERINFO)
                                   .fragment(WECHAT_REDIRECT_FRAGMENT);
        } else {
            var loginUrlForPc = config.getCustomizedLoginUrl();
            if (loginUrlForPc != null && !loginUrlForPc.isEmpty()) {
                // 同时登录微信公众号和第三方网站
                loginType = WechatLoginType.CUSTOMIZED;
                var officialAccountId = config.getWechatOfficialAccountId();
                if (officialAccountId == null) {
                    throw new IdentityBrokerException("WeChat Official Account ID is not configured");
                }
                uriBuilder = UriBuilder.fromUri(loginUrlForPc)
                                       .queryParam(OAUTH2_PARAMETER_CLIENT_ID, officialAccountId)
                                       .queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, OAUTH2_PARAMETER_CODE)
                                       .queryParam(OAUTH2_PARAMETER_SCOPE, SCOPE_USERINFO);
            } else {
                // 使用微信认证的第三方网站
                loginType = WechatLoginType.BROWSER;
                var clientId = config.getClientId();
                if (clientId == null) {
                    throw new IdentityBrokerException("Client ID is not configured");
                }
                var scope = config.getDefaultScope();
                if (scope == null) {
                    scope = SCOPE_LOGIN;
                }
                uriBuilder = UriBuilder.fromUri(AUTH_URL)
                                       .queryParam(OAUTH2_PARAMETER_CLIENT_ID, clientId)
                                       .queryParam(OAUTH2_PARAMETER_SCOPE, scope);
            }
        }
        uriBuilder.queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri())
                  .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded());
        authSession.setUserSessionNote(LOGIN_TYPE, loginType.name());
        log.info("LoginType: " + loginType.name());

        if (config.isLoginHint() && loginHint != null) {
            uriBuilder.queryParam(OIDCLoginProtocol.LOGIN_HINT_PARAM, loginHint);
        }

        if (config.isUiLocales()) {
            uriBuilder.queryParam(OIDCLoginProtocol.UI_LOCALES_PARAM,
                                  session.getContext().resolveLocale(null).toLanguageTag());
        }

        var prompt = config.getPrompt();
        if (prompt == null || prompt.isEmpty()) {
            prompt = authSession.getClientNote(OAuth2Constants.PROMPT);
        }
        if (prompt != null) {
            uriBuilder.queryParam(OAuth2Constants.PROMPT, prompt);
        }

        var acr = authSession.getClientNote(OAuth2Constants.ACR_VALUES);
        if (acr != null) {
            uriBuilder.queryParam(OAuth2Constants.ACR_VALUES, acr);
        }

        var nonce = authSession.getClientNote(OIDCLoginProtocol.NONCE_PARAM);
        if (nonce == null || nonce.isEmpty()) {
            nonce = Base64Url.encode(SecretGenerator.getInstance().randomBytes(16));
            authSession.setClientNote(OIDCLoginProtocol.NONCE_PARAM, nonce);
        }
        uriBuilder.queryParam(OIDCLoginProtocol.NONCE_PARAM, nonce);

        return uriBuilder;
    }

    /**
     * 判断是否在微信浏览器里面请求
     */
    private static boolean isWechatBrowser(HttpHeaders headers) {
        if (headers != null) {
            var ua = headers.getHeaderString("user-agent");
            return ua != null && ua.toLowerCase().contains(WECHAT_USER_AGENT);
        }
        return false;
    }

    private String getAccessToken(String appId) {
        String cacheKey = MP_CACHE_KEY_PREFIX + appId;
        String accessToken = tokenCache.get(cacheKey);
        if (accessToken == null || accessToken.startsWith(CACHE_LOCK_PREFIX)) {
            for (int i = 0; i < 15; i++) {
                accessToken = tokenCache.computeIfAbsent(cacheKey, k -> cacheLockMark, 10000, MILLISECONDS);
                if (!accessToken.startsWith(CACHE_LOCK_PREFIX)) {
                    break;
                }
                if (accessToken.equals(cacheLockMark)) {
                    log.info("WeChat application " + appId + ": refresh access token");
                    var secret = getConfig().getWechatMiniProgramSecret(appId);
                    if (secret == null) {
                        log.warn("Unknown WeChat application: " + appId);
                        break;
                    }

                    JsonNode tokenResponse = null;
                    try {
                        tokenResponse = SimpleHttp
                                .doGet(WECHAT_ACCESS_TOKEN_URL_1 + appId + WECHAT_ACCESS_TOKEN_URL_2 + secret, session)
                                .asJson();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                    if (tokenResponse != null) {
                        accessToken = getJsonProperty(tokenResponse, getAccessTokenResponseParameter());
                        int expireInSeconds = Integer.parseInt(getJsonProperty(tokenResponse, EXPIRES_IN)) - 60;
                        tokenCache.put(cacheKey, accessToken, expireInSeconds, SECONDS);
                        break;
                    }
                }
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ignored) {
                }
            }
        }
        return accessToken;
    }

    /**
     * 使用 refresh_token 刷新 access_token
     */
    private String refreshAccessToken(String appId, String refreshToken) {
        log.info("Refreshing access token for appId: " + appId);
        try {
            JsonNode tokenResponse = SimpleHttp
                    .doGet(REFRESH_TOKEN_URL, session)
                    .param(OAUTH2_PARAMETER_CLIENT_ID, appId)
                    .param("refresh_token", refreshToken)
                    .param(OAUTH2_PARAMETER_GRANT_TYPE, "refresh_token")
                    .asJson();

            if (tokenResponse != null) {
                String accessToken = getJsonProperty(tokenResponse, getAccessTokenResponseParameter());
                String newRefreshToken = getJsonProperty(tokenResponse, "refresh_token");
                String expiresIn = getJsonProperty(tokenResponse, EXPIRES_IN);

                // 微信在 refresh_token 失效时返回错误体（errcode/errmsg，无 access_token/expires_in），
                // 此时判定刷新失败，避免 parseInt(null) 抛 NumberFormatException 逃逸出 catch。
                if (accessToken == null || accessToken.isEmpty()
                        || newRefreshToken == null || newRefreshToken.isEmpty()
                        || expiresIn == null || expiresIn.isEmpty()) {
                    log.warn("Failed to refresh access token for appId: " + appId
                            + ", errcode=" + getJsonProperty(tokenResponse, "errcode")
                            + ", errmsg=" + getJsonProperty(tokenResponse, "errmsg"));
                    return null;
                }

                int expireInSeconds = Integer.parseInt(expiresIn) - 60;

                // 更新缓存中的 access_token（网页授权 token，使用 sns 前缀避免与小程序 token 冲突）
                tokenCache.put(SNS_CACHE_KEY_PREFIX + appId, accessToken, expireInSeconds, SECONDS);
                
                // 返回新的 refresh_token
                return newRefreshToken;
            }
        } catch (Exception e) {
            log.error("Failed to refresh access token for appId: " + appId, e);
        }
        return null;
    }

    /**
     * 判断响应是否表示 access_token 失效（需刷新）。
     */
    private static boolean isAccessTokenError(JsonNode response) {
        if (response == null || !response.has("errcode")) {
            return false;
        }
        int errcode = response.get("errcode").asInt();
        return errcode == ERR_ACCESS_TOKEN_INVALID
                || errcode == ERR_ACCESS_TOKEN_ILLEGAL
                || errcode == ERR_ACCESS_TOKEN_EXPIRED;
    }

    /**
     * 判断响应是否为错误响应（含非零 errcode）。
     */
    private static boolean isErrorResponse(JsonNode response) {
        return response != null && response.has("errcode") && response.get("errcode").asInt() != 0;
    }

    /**
     * 调用微信 userinfo 接口获取用户详细信息。
     */
    private JsonNode fetchUserInfo(String accessToken, String openId) throws IOException {
        return SimpleHttp
                .doGet(USERINFO_URL, session)
                .param("access_token", accessToken)
                .param("openid", openId)
                .param("lang", "zh_CN")
                .asJson();
    }

    /**
     * 获取登录信息
     */
    public BrokeredIdentityContext getFederatedIdentity(String response, WechatLoginType loginType, String appId) {
        JsonNode profile;
        try {
            profile = new ObjectMapper().readTree(response);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            throw new IdentityBrokerException("Can't parse OAuth server response: " + response);
        }
        // 脱敏记录：profile 含 access_token/refresh_token/openid，禁止整体打印
        log.info("User profile received for appId: " + appId);
        var context = extractIdentityFromProfile(profile, appId);

        String accessToken = getJsonProperty(profile, getAccessTokenResponseParameter());
        String refreshToken = getJsonProperty(profile, "refresh_token");
        
        if (WechatLoginType.MINI_PROGRAM.equals(loginType)) {
            accessToken = getAccessToken(appId);
        }
        if (accessToken == null) {
            throw new IdentityBrokerException("No access token available in OAuth server response: " + response);
        }
        context.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);
        
        // 保存 refresh_token
        if (refreshToken != null) {
            context.getContextData().put("refresh_token", refreshToken);
        }

        // 获取用户详细信息
        if (!WechatLoginType.MINI_PROGRAM.equals(loginType)) {
            String openId = getJsonProperty(profile, OPEN_ID);
            try {
                JsonNode userInfo = fetchUserInfo(accessToken, openId);
                
                // 如果 access_token 过期，尝试使用 refresh_token 刷新
                if (isAccessTokenError(userInfo)) {
                    log.info("Access token expired, trying to refresh");
                    String newRefreshToken = refreshAccessToken(appId, refreshToken);
                    if (newRefreshToken != null) {
                        // 使用新的 access_token 重试（网页授权 token，用 sns 前缀读取）
                        accessToken = tokenCache.get(SNS_CACHE_KEY_PREFIX + appId);
                        userInfo = fetchUserInfo(accessToken, openId);
                        // 刷新成功：同步更新 context 中的 token，避免存储过期凭据
                        context.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);
                        context.getContextData().put("refresh_token", newRefreshToken);
                    }
                }
                
                // 脱敏记录：避免将 openid/unionid/nickname 等 PII 明文写入日志
                log.info("User info fetched, has errcode: " + userInfo.has("errcode"));
                
                // 设置用户详细信息
                String nickname = getJsonProperty(userInfo, "nickname");
                if (nickname != null) {
                    context.setFirstName(nickname);
                }
                
                String headimgurl = getJsonProperty(userInfo, "headimgurl");
                if (headimgurl != null) {
                    context.setUserAttribute("picture", headimgurl);
                }
                
                String unionId = getJsonProperty(userInfo, UNION_ID);
                if (unionId != null) {
                    context.setUserAttribute(UNION_ID, unionId);
                }
                
                // 仅在成功获取用户信息时存入 mapper，避免错误响应污染用户属性
                if (isErrorResponse(userInfo)) {
                    log.warn("User info request failed, errcode=" + userInfo.get("errcode").asInt()
                            + ", falling back to basic profile from token response");
                } else {
                    AbstractJsonUserAttributeMapper.storeUserProfileForMapper(context, userInfo, getConfig().getAlias());
                }
            } catch (IOException e) {
                log.error("Failed to get user info", e);
            }
        }

        return context;
    }

    /**
     * 获取用户信息
     */
    protected BrokeredIdentityContext extractIdentityFromProfile(JsonNode profile, String appId) {
        String openId = getJsonProperty(profile, OPEN_ID);
        if (openId == null) {
            throw new IdentityBrokerException("Can't parse unionid/openid from server response: ");
        }
        // keycloak not allow capital in username, so need to encode to lowercase
        StringBuilder sb = new StringBuilder();
        sb.append(appId).append('-');
        for (char c : openId.toCharArray()) {
            if (c == '#') {
                sb.append(c);
                sb.append(c);
            } else if ((c < 'A') || (c > 'Z')) {
                sb.append(c);
            } else {
                sb.append('#');
                sb.append((char) (c - 'A' + 'a'));
            }
        }
        String id = sb.toString();

        var user = new BrokeredIdentityContext(id, getConfig());
        user.setBrokerUserId(id);
        user.setUsername(id);
        user.setModelUsername(id);
        user.setUserAttribute(APP_ID, appId);
        user.setUserAttribute(OPEN_ID, openId);
        user.setUserAttribute(USER_ID, appId + "-" + openId);
        String unionId = getJsonProperty(profile, UNION_ID);
        if (unionId != null) {
            user.setUserAttribute(UNION_ID, unionId);
        }
        String sessionKey = getJsonProperty(profile, SESSION_KEY);
        if (sessionKey != null) {
            user.setUserAttribute(SESSION_KEY, sessionKey);
        }
        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());
        return user;
    }

    /**
     * 微信请求节点
     */
    protected class WechatEndpoint extends Endpoint {
        private final OAuth2IdentityProviderConfig providerConfig;

        public WechatEndpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event,
                              AbstractOAuth2IdentityProvider<WechatIdentityProviderConfig> provider) {
            super(callback, realm, event, provider);
            providerConfig = provider.getConfig();
        }

        @Override
        @GET
        public Response authResponse(@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
                                     @QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
                                     @QueryParam(OAuth2Constants.ERROR) String error,
                                     @QueryParam(OAuth2Constants.ERROR_DESCRIPTION) String errorDescription) {
            if (state == null) {
                return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_MISSING_STATE_ERROR);
            }

            try {
                AuthenticationSessionModel authSession = this.callback.getAndVerifyAuthenticationSession(state);
                session.getContext().setAuthenticationSession(authSession);

                if (error != null) {
                    logger.error(error + " for broker login " + getConfig().getProviderId());
                    if (error.equals(ACCESS_DENIED)) {
                        return callback.cancelled(providerConfig);
                    } else if (error.equals(OAuthErrorException.LOGIN_REQUIRED) ||
                               error.equals(OAuthErrorException.INTERACTION_REQUIRED)) {
                        return callback.error(error);
                    } else {
                        return callback.error(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                    }
                }

                if (authorizationCode != null) {
                    final var config = getConfig();
                    final var sessionNotes = authSession.getUserSessionNotes();
                    final var loginType = WechatLoginType.valueOf(sessionNotes.get(LOGIN_TYPE));
                    final var appId = findRealAppId(config, loginType, sessionNotes.get(APP_ID));

                    var tokenRequest = generateTokenRequest(config, authorizationCode, loginType, appId);
                    if (tokenRequest != null) {
                        var response = tokenRequest.asString();
                        logger.info("Response from auth code = " + response);

                        var federatedIdentity = getFederatedIdentity(response, loginType, appId);
                        if (config.isStoreToken() && federatedIdentity.getToken() == null) {
                            // make sure that token wasn't already set by getFederatedIdentity();
                            // want to be able to allow provider to set the token itself.
                            federatedIdentity.setToken(response);
                        }
                        federatedIdentity.setIdp(WechatIdentityProvider.this);
                        federatedIdentity.setAuthenticationSession(authSession);
                        var authenticated = callback.authenticated(federatedIdentity);

                        if (WechatLoginType.MINI_PROGRAM.equals(loginType) &&
                            authenticated.getStatus() == Response.Status.FOUND.getStatusCode()) {
                            // 微信小程序处理不了重定向时生成的Cookie，需要分步处理
                            var location = authenticated.getLocation().toString();
                            authenticated = Response.status(Response.Status.NO_CONTENT)
                                                    .header(HTTP_REDIRECT_LOCATION_HEADER, location)
                                                    .build();
                        }

                        return authenticated;
                    }
                }
            } catch (WebApplicationException e) {
                return e.getResponse();
            } catch (Exception e) {
                logger.error("Failed to make identity provider oauth callback", e);
            }

            return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
        }

        private Response errorIdentityProviderLogin(String message) {
            event.event(EventType.IDENTITY_PROVIDER_LOGIN);
            event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
            return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY, message);
        }

        public String findRealAppId(WechatIdentityProviderConfig config, WechatLoginType loginType, String appId) {
            if (appId == null) {
                switch (loginType) {
                    case BROWSER:
                        return config.getClientId();
                    case OFFICIAL_ACCOUNT:
                        return config.getWechatOfficialAccountId();
                    case MINI_PROGRAM:
                        return config.getWechatMiniProgramId();
                    case CUSTOMIZED:
                        return config.getWechatOfficialAccountId();
                }
            }
            return appId;
        }

        public SimpleHttp generateTokenRequest(WechatIdentityProviderConfig config, String authorizationCode,
                                               WechatLoginType loginType, String appId) {
            String secret;

            if (WechatLoginType.MINI_PROGRAM.equals(loginType)) {
                secret = config.getWechatMiniProgramSecret(appId);
                log.info("WeChatMP: appId=" + appId + ", appSecret=" + secret);
                if (secret != null) {
                    var url = WECHAT_MP_AUTH_URL_1 + appId + WECHAT_MP_AUTH_URL_2 + secret +
                            WECHAT_MP_AUTH_URL_3 + authorizationCode + WECHAT_MP_AUTH_URL_4;
                    log.info("WeChatMP request URL: " + url);
                    log.info("WeChatMP request parameters: code=" + authorizationCode);
                    return SimpleHttp.doGet(url, session);
                }
            } else {
                if (WechatLoginType.BROWSER.equals(loginType)) {
                    secret = config.getClientSecret();
                } else {
                    secret = config.getWechatOfficialAccountSecret(appId);
                }
                log.info("WeChatOA: appId=" + appId + ", appSecret=" + secret);
                if (secret != null) {
                    log.info("WeChat token request URL: " + TOKEN_URL);
                    log.info("WeChat request parameters: code=" + authorizationCode + ", appId=" + appId);
                    return SimpleHttp
                            .doPost(TOKEN_URL, session)
                            .param(OAUTH2_PARAMETER_CLIENT_ID, appId)
                            .param(OAUTH2_PARAMETER_CLIENT_SECRET, secret)
                            .param(OAUTH2_PARAMETER_CODE, authorizationCode)
                            .param(OAUTH2_PARAMETER_GRANT_TYPE, OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);
                }
            }

            return null;
        }
    }

    public enum WechatLoginType {
        BROWSER,
        OFFICIAL_ACCOUNT,
        MINI_PROGRAM,
        CUSTOMIZED,
    }
}
