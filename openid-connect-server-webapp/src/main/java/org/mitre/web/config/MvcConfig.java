package org.mitre.web.config;

import java.util.List;

import org.mitre.openid.connect.web.ServerConfigInterceptor;
import org.mitre.openid.connect.web.UserInfoInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@Configuration
@EnableWebMvc
public class MvcConfig extends WebMvcConfigurerAdapter {

  @Autowired
  private ServerConfigInterceptor serverConfigInterceptor;

  @Autowired
  private UserInfoInterceptor userInfoInterceptor;

  @Override
  public void configureMessageConverters(
    final List<HttpMessageConverter<?>> converters) {

    super.configureMessageConverters(converters);
    converters.add(new StringHttpMessageConverter());
    converters.add(new MappingJackson2HttpMessageConverter());
  }

  @Override
  public void addInterceptors(final InterceptorRegistry registry) {

    super.addInterceptors(registry);
    registry.addInterceptor(userInfoInterceptor);
    registry.addInterceptor(serverConfigInterceptor);
  }

  @Override
  public void addResourceHandlers(final ResourceHandlerRegistry registry) {

    registry.addResourceHandler("/resources/**")
      .addResourceLocations("/resources/");
    registry.addResourceHandler("/css/**").addResourceLocations("/css/");
    registry.addResourceHandler("/images/**").addResourceLocations("/images/");
    registry.addResourceHandler("/js/**").addResourceLocations("/js/");
  }

  @Override
  public void configureDefaultServletHandling(
    final DefaultServletHandlerConfigurer configurer) {

    configurer.enable();
  }

  @Override
  public void addViewControllers(final ViewControllerRegistry registry) {

    registry.addViewController("/login").setViewName("login");
    registry.addViewController("/error").setViewName("error");
  }

}
