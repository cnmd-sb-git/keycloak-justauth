package cn.scysn.social;

import cn.scysn.social.common.JustAuthKey;
import cn.scysn.social.common.JustIdentityProvider;
import cn.scysn.social.common.JustIdentityProviderConfig;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import me.zhyd.oauth.request. AuthWeChatOpenRequest;

/**
 微信开放平台
 */

public class WechatOpenIdentityProviderFactory extends
        AbstractIdentityProviderFactory<JustIdentityProvider< AuthWeChatOpenRequest>>
        implements SocialIdentityProviderFactory<JustIdentityProvider< AuthWeChatOpenRequest>> {

  public static final JustAuthKey JUST_AUTH_KEY = JustAuthKey.  WE_CHAT_OPEN;

  @Override
  public String getName() {
    return JUST_AUTH_KEY.getName();
  }

  @Override
  public JustIdentityProvider< AuthWeChatOpenRequest> create(KeycloakSession session, IdentityProviderModel model) {
    return new JustIdentityProvider<>(session, new JustIdentityProviderConfig<>(model,JUST_AUTH_KEY, AuthWeChatOpenRequest::new));
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
