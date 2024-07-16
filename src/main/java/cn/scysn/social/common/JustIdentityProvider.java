package cn.scysn.social.common;


import cn.hutool.json.JSONUtil;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.request.AuthDefaultRequest;
import me.zhyd.oauth.request.AuthRequest;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.provider.util.IdentityBrokerState;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.function.Function;

/**
 * @author yanfeiwuji
 * @date 2021/1/10 4:37 下午
 */
public class JustIdentityProvider<T extends AuthDefaultRequest> extends AbstractOAuth2IdentityProvider<JustIdentityProviderConfig> implements SocialIdentityProvider<JustIdentityProviderConfig> {

    private static final Logger log = LoggerFactory.getLogger(JustIdentityProvider.class);
    public final String DEFAULT_SCOPES = "default";
    //OAuth2IdentityProviderConfig
    public final AuthConfig AUTH_CONFIG;
    public final Function<AuthConfig, T> authToReqFunc;
    protected EventBuilder event;
    public final String providerId;

    public JustIdentityProvider(KeycloakSession session, JustIdentityProviderConfig<T> config) {
        super(session, config);
        this.AUTH_CONFIG = JustAuthKey.getAuthConfig(config);
        this.authToReqFunc = config.getAuthToReqFunc();
        this.providerId = config.getProviderId();
    }

    private AuthRequest getAuthRequest(AuthConfig authConfig, String redirectUri) {
        authConfig.setRedirectUri(redirectUri);
        return authToReqFunc.apply(authConfig);
    }

    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        logger.infof("开始构建链接");
        final UriBuilder uriBuilder;
        AuthRequest authRequest = getAuthRequest(AUTH_CONFIG, request.getRedirectUri());
        logger.infof("auth Url:%s ,clientId:%s ,redirect_uri:%s ", getConfig().getAuthorizationUrl(), getConfig().getClientId(), request.getRedirectUri());
        String uri = authRequest.authorize(request.getState().getEncoded());
        uriBuilder = UriBuilder.fromUri(uri);
        logger.info("授权链接是：" + uri);
        return uriBuilder;
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPES;
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        logger.infof("callback: start realm:%s  ,event:%s", realm.getName(), event);
        return new Endpoint(session, callback, event, providerId, this.AUTH_CONFIG, authToReqFunc, this);
    }


    public static class Endpoint {
        protected final RealmModel realm;
        protected final AuthenticationCallback callback;
        protected final EventBuilder event;

        protected final KeycloakSession session;

        protected final ClientConnection clientConnection;

        protected final HttpHeaders headers;
        protected final String providerId;

        protected final AuthConfig authConfig;

        protected final Function<AuthConfig, ? extends AuthRequest> authToReqFunc;

        protected final JustIdentityProvider identityProvider;

        public Endpoint(KeycloakSession session, AuthenticationCallback callback, EventBuilder event, String providerId, AuthConfig authConfig, Function<AuthConfig, ? extends AuthRequest> authToReqFunc, JustIdentityProvider identityProvider) {
            this.session = session;
            this.realm = session.getContext().getRealm();
            this.clientConnection = session.getContext().getConnection();
            this.callback = callback;
            this.event = event;
            this.headers = session.getContext().getRequestHeaders();
            this.providerId = providerId;
            this.authConfig = authConfig;
            this.authToReqFunc = authToReqFunc;
            this.identityProvider = identityProvider;
        }


        private AuthRequest getAuthRequest(AuthConfig authConfig, String redirectUri) {
            authConfig.setRedirectUri(redirectUri);
            return authToReqFunc.apply(authConfig);
        }


        private void sendErrorEvent() {
            event.event(EventType.LOGIN);
            logger.info("失败");
            event.error(providerId + "_login_failed");
        }

        @GET
        @Produces(MediaType.APPLICATION_JSON)
        @Consumes(MediaType.APPLICATION_JSON)
        @Path("")
        public Response authResponse(@QueryParam("state") String state,
                                     @QueryParam("code") String authorizationCode,
                                     @QueryParam("error") String error) {
            // logger params
            logger.infof("authResponse: state=%s,code=%s,error=%s", state, authorizationCode, error);
            if (state == null) {
                logger.error("state参数为空");
                sendErrorEvent();
            }
            AuthCallback authCallback = AuthCallback.builder()
                .code(authorizationCode)
                .state(state)
                .build();

            IdentityBrokerState idpState = IdentityBrokerState.encoded(state, realm);
            String clientId = idpState.getClientId();
            String tabId = idpState.getTabId();

            if (clientId == null || tabId == null) {
                logger.errorf("状态参数无效: %s", state);
                sendErrorEvent();
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
            }

            ClientModel client = realm.getClientByClientId(clientId);

            AuthenticationSessionModel
                authSession = ClientSessionCode.getClientSession(state, tabId, session, realm, client, event, AuthenticationSessionModel.class);

            // 没有check 不通过
            String redirectUri = "https://io.github.yanfeiwuji";
            AuthRequest authRequest = getAuthRequest(authConfig, redirectUri);
            AuthResponse<AuthUser> response = authRequest.login(authCallback);
            if (response.ok()) {
                AuthUser authUser = response.getData();
                OAuth2IdentityProviderConfig config = identityProvider.getConfig();
                BrokeredIdentityContext federatedIdentity = new BrokeredIdentityContext(authUser.getUuid());
                authUser.getRawUserInfo().forEach((k, v) -> {
                    String value = (v instanceof String) ? v.toString() : JSONUtil.toJsonStr(v);
                    // v  不能过长
                    federatedIdentity.setUserAttribute(config.getAlias() + "-" + k, value);
                });

                if (identityProvider.getConfig().isStoreToken()) {
                    if (federatedIdentity.getToken() == null) {
                        federatedIdentity.setToken(authUser.getToken().getAccessToken());
                    }
                }
                federatedIdentity.setUsername(authUser.getUuid());
                federatedIdentity.setBrokerUserId(authUser.getUuid());
                federatedIdentity.setIdpConfig(config);
                federatedIdentity.setIdp(identityProvider);
                federatedIdentity.setAuthenticationSession(authSession);
                return this.callback.authenticated(federatedIdentity);
            } else {
                logger.errorf("授权失败: %s", response.getMsg());
                sendErrorEvent();
                return ErrorPage.error(session, authSession, Response.Status.BAD_GATEWAY, Messages.UNEXPECTED_ERROR_HANDLING_RESPONSE);
            }
        }
    }

    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
        return Response.ok(identity.getToken()).type(MediaType.APPLICATION_JSON).build();
    }

    @Override
    public void authenticationFinished(AuthenticationSessionModel authSession, BrokeredIdentityContext context) {
        authSession.setUserSessionNote(IdentityProvider.FEDERATED_ACCESS_TOKEN, (String) context.getContextData().get(IdentityProvider.FEDERATED_ACCESS_TOKEN));
    }

    private Response errorIdentityProviderLogin(String message) {
        event.event(EventType.IDENTITY_PROVIDER_LOGIN);
        event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
        return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY, message);
    }
}
