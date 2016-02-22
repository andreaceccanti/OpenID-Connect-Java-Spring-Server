package org.mitre.web.config;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;

import javax.sql.DataSource;

import org.mitre.jose.keystore.JWKSetKeyStore;
import org.mitre.jwt.encryption.service.impl.DefaultJWTEncryptionAndDecryptionService;
import org.mitre.jwt.signer.service.impl.DefaultJWTSigningAndValidationService;
import org.mitre.oauth2.token.StructuredScopeAwareOAuth2RequestValidator;
import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.mitre.openid.connect.config.JsonMessageSource;
import org.mitre.openid.connect.filter.MultiUrlRequestMatcher;
import org.mitre.openid.connect.token.TofuUserApprovalHandler;
import org.mitre.openid.connect.web.ServerConfigInterceptor;
import org.mitre.openid.connect.web.UserInfoInterceptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.boot.context.embedded.ServletRegistrationBean;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.init.DatabasePopulator;
import org.springframework.jdbc.datasource.init.DatabasePopulatorUtils;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.orm.jpa.JpaVendorAdapter;
import org.springframework.orm.jpa.vendor.EclipseLinkJpaVendorAdapter;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.view.BeanNameViewResolver;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.springframework.web.servlet.view.JstlView;

import com.nimbusds.jose.JWEAlgorithm;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

@Configuration
public class IamConfig {

  @Value("${spring.application.issuer}")
  private String issuer;

  @Value("${spring.application.logoImageUrl}")
  private String logoImageUrl;

  @Value("${spring.application.topbarTitle}")
  private String topbarTitle;

  @Value("${spring.datasource.driverClassName}")
  private String dbDriverClassName;

  @Value("${spring.datasource.url}")
  private String dbUrl;

  @Value("${spring.datasource.username}")
  private String dbUsername;

  @Value("${spring.datasource.password}")
  private String dbPassword;

  @Value("${spring.datasource.databasePlatform}")
  private String dbPlatform;

  @Bean
  public PlatformTransactionManager defaultTransactionManager() {

    return new DataSourceTransactionManager(iamDataSource());
  }

  @Bean
  public OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint() {

    OAuth2AuthenticationEntryPoint entryPoint = new OAuth2AuthenticationEntryPoint();
    entryPoint.setRealmName("openidconnect");
    return entryPoint;
  }

  @Bean
  public Http403ForbiddenEntryPoint http403EntryPoint() {

    return new Http403ForbiddenEntryPoint();
  }

  @Bean
  public WebResponseExceptionTranslator oauth2ExceptionTranslator() {

    return new DefaultWebResponseExceptionTranslator();
  }

  @Bean
  public RequestMatcher clientAuthMatcher() {

    Set<String> endpoints = new LinkedHashSet<String>(
      Arrays.asList("/introspect", "/revoke", "/token"));
    return new MultiUrlRequestMatcher(endpoints);
  }

  // server-config.xml
  @Bean
  public ConfigurationPropertiesBean config() {

    ConfigurationPropertiesBean config = new ConfigurationPropertiesBean();
    config.setIssuer(issuer);
    config.setLogoImageUrl(logoImageUrl);
    config.setTopbarTitle(topbarTitle);
    config.setRegTokenLifeTime(172800L);
    config.setForceHttps(false);
    config.setLocale(Locale.ENGLISH);

    return config;
  }

  @Bean
  public ServerConfigInterceptor serverConfigInterceptor() {

    return new ServerConfigInterceptor();
  }

  @Bean
  public UserInfoInterceptor userInfoInterceptor() {

    return new UserInfoInterceptor();
  }

  // data-context.xml
  @Bean
  public DataSource iamDataSource() {

    Properties props = new Properties();
    props.setProperty("driverClassName", dbDriverClassName);
    props.setProperty("jdbcUrl", dbUrl);
    props.setProperty("username", dbUsername);
    props.setProperty("password", dbPassword);

    HikariConfig config = new HikariConfig(props);
    DataSource dataSource = new HikariDataSource(config);

    DatabasePopulatorUtils.execute(createDatabasePopulator(), dataSource);

    return dataSource;
  }

  private DatabasePopulator createDatabasePopulator() {

    ResourceDatabasePopulator databasePopulator = new ResourceDatabasePopulator();
    databasePopulator.setContinueOnError(false);
    databasePopulator
      .addScript(new ClassPathResource("db/tables/hsql_database_tables.sql"));
    databasePopulator
      .addScript(new ClassPathResource("db/tables/security-schema.sql"));
    databasePopulator
      .addScript(new ClassPathResource("db/tables/loading_temp_tables.sql"));
    databasePopulator.addScript(new ClassPathResource("db/users.sql"));
    databasePopulator.addScript(new ClassPathResource("db/clients.sql"));
    databasePopulator.addScript(new ClassPathResource("db/scopes.sql"));
    return databasePopulator;
  }

  @Bean
  public JpaVendorAdapter jpaAdapter() {

    EclipseLinkJpaVendorAdapter jpaAdapter = null;
    jpaAdapter = new EclipseLinkJpaVendorAdapter();
    jpaAdapter.setDatabasePlatform(dbPlatform);
    jpaAdapter.setShowSql(true);

    return jpaAdapter;
  }

  // authz-config.xml
  @Bean
  public OAuth2AccessDeniedHandler oauthAccessDeniedHandler() {

    return new OAuth2AccessDeniedHandler();
  }

  @Bean
  public UserApprovalHandler tofuUserAppovalHandler() {

    return new TofuUserApprovalHandler();
  }

  @Bean
  public OAuth2RequestValidator oauthRequestValidator() {

    return new StructuredScopeAwareOAuth2RequestValidator();
  }

  @Bean
  public MessageSource messageSource() {

    DefaultResourceLoader loader = new DefaultResourceLoader();
    JsonMessageSource messageSource = new JsonMessageSource();
    messageSource
      .setBaseDirectory(loader.getResource("classpath:resources/js/locale/"));
    messageSource.setUseCodeAsDefaultMessage(true);

    return messageSource;
  }

  // crypto-config.xml
  @Bean
  public JWKSetKeyStore defaultKeyStore() {

    Resource location = new FileSystemResource(
      "src/main/resources/keystore.jwks");
    JWKSetKeyStore keyStore = new JWKSetKeyStore();
    keyStore.setLocation(location);

    return keyStore;
  }

  @Bean
  public DefaultJWTSigningAndValidationService defaultSignerService()
    throws Exception {

    DefaultJWTSigningAndValidationService signerService = null;

    signerService = new DefaultJWTSigningAndValidationService(
      defaultKeyStore());
    signerService.setDefaultSignerKeyId("rsa1");
    signerService.setDefaultSigningAlgorithmName("RS256");

    return signerService;
  }

  @Bean
  public DefaultJWTEncryptionAndDecryptionService defaultEncryptionService()
    throws Exception {

    DefaultJWTEncryptionAndDecryptionService encryptionService = null;
    encryptionService = new DefaultJWTEncryptionAndDecryptionService(
      defaultKeyStore());
    encryptionService.setDefaultAlgorithm(JWEAlgorithm.RSA1_5);
    encryptionService.setDefaultDecryptionKeyId("rsa1");
    encryptionService.setDefaultEncryptionKeyId("rsa1");

    return encryptionService;
  }

  @Bean
  public InternalResourceViewResolver defaultViewResolver() {

    InternalResourceViewResolver resolver = new InternalResourceViewResolver();
    resolver.setViewClass(JstlView.class);
    resolver.setPrefix("WEB-INF/views/");
    resolver.setSuffix(".jsp");
    resolver.setOrder(2);
    return resolver;
  }

  @Bean
  public BeanNameViewResolver beanNameViewResolver() {

    BeanNameViewResolver resolver = new BeanNameViewResolver();
    resolver.setOrder(1);
    return resolver;
  }

  // local-config.xml

  /// web.xml
  @Bean
  public ServletRegistrationBean servlet() {

    ServletRegistrationBean srb = new ServletRegistrationBean();
    srb.setName("spring");
    srb.setServlet(new DispatcherServlet());
    srb.setLoadOnStartup(1);
    srb.addUrlMappings("/");

    return srb;
  }

  @Bean
  public FilterRegistrationBean filter() {

    FilterRegistrationBean frb = new FilterRegistrationBean();
    frb.setName("springSecurityFilterChain");
    frb.setFilter(new DelegatingFilterProxy());
    frb.addInitParameter("contextAttribute",
      "org.springframework.web.servlet.FrameworkServlet.CONTEXT.spring");
    frb.addUrlPatterns("/*");

    return frb;
  }

}
