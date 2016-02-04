package it.infn.web.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;

@Configuration
@EnableResourceServer
@Import(IamConfig.class)
public class IamResourceServer extends ResourceServerConfigurerAdapter {

  @Autowired
  IamConfig iamConfig;

  @Override
  public void configure(final ResourceServerSecurityConfigurer resources)
    throws Exception {

    resources.tokenServices(iamConfig.defaultOAuth2ProviderTokenService());
  }
}
