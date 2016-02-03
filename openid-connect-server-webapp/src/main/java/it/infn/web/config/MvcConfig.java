package it.infn.web.config;

import java.util.List;

import org.mitre.openid.connect.web.ServerConfigInterceptor;
import org.mitre.openid.connect.web.UserInfoInterceptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.view.BeanNameViewResolver;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

@Configuration
@ComponentScan({ "it.infn.web" })
public class MvcConfig extends WebMvcConfigurerAdapter {

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
    registry.addInterceptor(new UserInfoInterceptor());
    registry.addInterceptor(new ServerConfigInterceptor());
  };

  @Bean
  public ViewResolver getViewResolver() {

    InternalResourceViewResolver resolver = new InternalResourceViewResolver();
    resolver.setPrefix("/WEB-INF/views");
    resolver.setSuffix(".jsp");
    resolver.setOrder(2);
    return resolver;
  }

  @Bean
  public ViewResolver beanNameViewResolver() {

    BeanNameViewResolver resolver = new BeanNameViewResolver();
    resolver.setOrder(1);
    return resolver;
  }

}
