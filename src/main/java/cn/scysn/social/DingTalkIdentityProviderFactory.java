package cn.scysn.social;

import cn.scysn.social.common.JustIdentityProvider;
import cn.scysn.social.common.JustAuthKey;
import cn.scysn.social.common.JustIdentityProviderConfig;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import me.zhyd.oauth.request. AuthDingTalkRequest;

/**
 钉钉
 */

public class DingTalkIdentityProviderFactory extends
        AbstractIdentityProviderFactory<JustIdentityProvider< AuthDingTalkRequest>>
        implements SocialIdentityProviderFactory<JustIdentityProvider< AuthDingTalkRequest>> {

  public static final JustAuthKey JUST_AUTH_KEY = JustAuthKey.  DING_TALK;

  @Override
  public String getName() {
    return JUST_AUTH_KEY.getName();
  }

  @Override
  public JustIdentityProvider< AuthDingTalkRequest> create(KeycloakSession session, IdentityProviderModel model) {
    return new JustIdentityProvider<>(session, new JustIdentityProviderConfig<>(model,JUST_AUTH_KEY, AuthDingTalkRequest::new));
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
