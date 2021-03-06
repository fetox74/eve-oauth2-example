package com.example;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

@SpringBootApplication
@RestController
@EnableOAuth2Client
public class EveOAuth2Example
  extends WebSecurityConfigurerAdapter
{
  @Autowired
  private OAuth2ClientContext oauth2ClientContext;

  private Integer characterId;

  @RequestMapping("/user")
  public Map<String, Object> user(OAuth2Authentication authentication)
  {
    Map<String, Object> details = (Map<String, Object>)authentication.getUserAuthentication().getDetails();
    characterId = (Integer)details.get("CharacterID");
    return details;
  }

  @RequestMapping("/test")
  public Map<String, Object> test()
    throws IOException
  {
    final String uri = "https://crest-tq.eveonline.com/characters/" + characterId + "/contacts/";
    JsonFactory factory = new JsonFactory();
    ObjectMapper mapper = new ObjectMapper(factory);

    OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(new AuthorizationCodeResourceDetails(), oauth2ClientContext);

    Map<String,Object> result = mapper.readValue(restTemplate.getForObject(uri, String.class), new TypeReference<HashMap<String,Object>>(){});

    return result;
  }

  @Override
  protected void configure(HttpSecurity http)
    throws Exception
  {
    // @formatter:off
    http.antMatcher("/**")
      .authorizeRequests()
      .antMatchers("/", "/login**", "/webjars/**").permitAll()
      .anyRequest().authenticated()
      .and().exceptionHandling().authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/"))
      .and().logout().logoutSuccessUrl("/").permitAll()
      .and().csrf().csrfTokenRepository(csrfTokenRepository())
      .and().addFilterAfter(csrfHeaderFilter(), CsrfFilter.class)
      .addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
    // @formatter:on
  }

  public static void main(String[] args)
  {
    SpringApplication.run(EveOAuth2Example.class, args);
  }

  @Bean
  protected FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter)
  {
    FilterRegistrationBean registration = new FilterRegistrationBean();
    registration.setFilter(filter);
    registration.setOrder(-100);
    return registration;
  }

  private Filter ssoFilter()
  {
    OAuth2ClientAuthenticationProcessingFilter eveFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/eve");
    OAuth2RestTemplate eveTemplate = new OAuth2RestTemplate(eve(), oauth2ClientContext);
    eveFilter.setRestTemplate(eveTemplate);
    eveFilter.setTokenServices(new UserInfoTokenServices(eveResource().getUserInfoUri(), eve().getClientId()));
    return eveFilter;
  }

  @Bean
  @ConfigurationProperties("eve.client")
  protected OAuth2ProtectedResourceDetails eve()
  {
    return new AuthorizationCodeResourceDetails();
  }

  @Bean
  @ConfigurationProperties("eve.resource")
  protected ResourceServerProperties eveResource()
  {
    return new ResourceServerProperties();
  }

  private Filter csrfHeaderFilter()
  {
    return new OncePerRequestFilter()
    {
      @Override
      protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                      FilterChain filterChain)
        throws ServletException, IOException
      {
        CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if(csrf != null)
        {
          Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
          String token = csrf.getToken();
          if(cookie == null || token != null && !token.equals(cookie.getValue()))
          {
            cookie = new Cookie("XSRF-TOKEN", token);
            cookie.setPath("/");
            response.addCookie(cookie);
          }
        }
        filterChain.doFilter(request, response);
      }
    };
  }

  private CsrfTokenRepository csrfTokenRepository()
  {
    HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
    repository.setHeaderName("X-XSRF-TOKEN");
    return repository;
  }
}
