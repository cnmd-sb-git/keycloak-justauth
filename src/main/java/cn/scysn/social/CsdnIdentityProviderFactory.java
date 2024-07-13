package cn.scysn.social;

import cn.scysn.social.common.JustAuthKey;
import cn.scysn.social.common.JustIdentityProvider;
import cn.scysn.social.common.JustIdentityProviderConfig;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import me.zhyd.oauth.request. AuthCsdnRequest;

/**
 * csdn
 */

public class CsdnIdentityProviderFactory extends
        AbstractIdentityProviderFactory<JustIdentityProvider< AuthCsdnRequest>>
        implements SocialIdentityProviderFactory<JustIdentityProvider< AuthCsdnRequest>> {

  public static final JustAuthKey JUST_AUTH_KEY = JustAuthKey.  CSDN;

  @Override
  public String getName() {
    return JUST_AUTH_KEY.getName();
  }

  @Override
  public JustIdentityProvider< AuthCsdnRequest> create(KeycloakSession session, IdentityProviderModel model) {
    return new JustIdentityProvider<>(session, new JustIdentityProviderConfig<>(model,JUST_AUTH_KEY, AuthCsdnRequest::new));
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
