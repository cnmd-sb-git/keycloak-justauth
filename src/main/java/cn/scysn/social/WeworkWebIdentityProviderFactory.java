package cn.scysn.social;

import cn.scysn.social.common.JustAuthKey;
import cn.scysn.social.common.JustIdentityProvider;
import cn.scysn.social.common.JustIdentityProviderConfig;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import me.zhyd.oauth.request. AuthWeChatEnterpriseWebRequest;

/**
 企业微信客户端内登陆
 */

public class WeworkWebIdentityProviderFactory extends
        AbstractIdentityProviderFactory<JustIdentityProvider< AuthWeChatEnterpriseWebRequest>>
        implements SocialIdentityProviderFactory<JustIdentityProvider< AuthWeChatEnterpriseWebRequest>> {

  public static final JustAuthKey JUST_AUTH_KEY = JustAuthKey.  WEWORK_WEB;

  @Override
  public String getName() {
    return JUST_AUTH_KEY.getName();
  }

  @Override
  public JustIdentityProvider< AuthWeChatEnterpriseWebRequest> create(KeycloakSession session, IdentityProviderModel model) {
    return new JustIdentityProvider<>(session, new JustIdentityProviderConfig<>(model,JUST_AUTH_KEY, AuthWeChatEnterpriseWebRequest::new));
  }

  @Override
  public OAuth2IdentityProviderConfig createConfig() {
    return new OAuth2IdentityProviderConfig();
  }

  @Override
  public String getId() {
    return JUST_AUTH_KEY.getId();
  }
}
