package cn.scysn.social;

import cn.scysn.social.common.JustAuthKey;
import cn.scysn.social.common.JustIdentityProvider;
import cn.scysn.social.common.JustIdentityProviderConfig;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import me.zhyd.oauth.request. AuthAlipayRequest;

/**
 * 支付宝
 */

public class AlipayIdentityProviderFactory extends
        AbstractIdentityProviderFactory<JustIdentityProvider< AuthAlipayRequest>>
        implements SocialIdentityProviderFactory<JustIdentityProvider< AuthAlipayRequest>> {

  public static final JustAuthKey JUST_AUTH_KEY = JustAuthKey.  ALIPAY;

  @Override
  public String getName() {
    return JUST_AUTH_KEY.getName();
  }

  @Override
  public JustIdentityProvider< AuthAlipayRequest> create(KeycloakSession session, IdentityProviderModel model) {
    return new JustIdentityProvider<>(session, new JustIdentityProviderConfig<>(model,JUST_AUTH_KEY, AuthAlipayRequest::new));
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
