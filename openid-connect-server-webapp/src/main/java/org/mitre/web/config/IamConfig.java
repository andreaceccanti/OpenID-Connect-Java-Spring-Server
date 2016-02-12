package org.mitre.web.config;

import java.util.Locale;
import java.util.Properties;

import javax.sql.DataSource;

import org.mitre.jose.keystore.JWKSetKeyStore;
import org.mitre.jwt.encryption.service.impl.DefaultJWTEncryptionAndDecryptionService;
import org.mitre.jwt.signer.service.impl.DefaultJWTSigningAndValidationService;
import org.mitre.oauth2.service.impl.DefaultOAuth2AuthorizationCodeService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.mitre.oauth2.web.CorsFilter;
import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.mitre.openid.connect.config.JsonMessageSource;
import org.mitre.openid.connect.service.ApprovedSiteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.transaction.PlatformTransactionManager;

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

  @Autowired
  DefaultOAuth2ProviderTokenService tokenService;

  @Autowired
  ApprovedSiteService defaultApprovedSiteService;

  @Bean
  public PlatformTransactionManager defaultTransactionManager() {

    return new DataSourceTransactionManager(iamDataSource());
  }

  @Bean
  public DefaultOAuth2AuthorizationCodeService codeService() {

    return new DefaultOAuth2AuthorizationCodeService();
  }

  @Bean
  public CorsFilter corsFilter() {

    return new CorsFilter();
  }

  @Bean
  public OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint() {

    OAuth2AuthenticationEntryPoint entryPoint = new OAuth2AuthenticationEntryPoint();
    entryPoint.setRealmName("openidconnect");
    return entryPoint;
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
  public AccessDeniedHandler oauthAccessDeniedHandler() {

    return new OAuth2AccessDeniedHandler();
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

  // local-config.xml

}
