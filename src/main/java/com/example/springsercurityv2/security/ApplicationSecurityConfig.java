package com.example.springsercurityv2.security;

import com.example.springsercurityv2.auth.ApplicationUserService;
import com.example.springsercurityv2.jwt.JwtConfig;
import com.example.springsercurityv2.jwt.JwtTokenVerifier;
import com.example.springsercurityv2.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.SecretKey;

@Configuration
@EnableWebSecurity
//NEED THIS TO USE @PreAuthorized in StudentManagementController class.
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;

    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService, SecretKey secretKey, JwtConfig jwtConfig) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }

    //FOR NOT JWT
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http
//                .csrf().disable()
////                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
////                .and()
//                .authorizeRequests()
//                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
//                .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
//                //REPLACED WIH permissions. COURSE_WRITE.name -> COURSE_WRITE.getPermission()
////                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.name())
//
//                //REPLACED WITH @PreAuthorized in StudentManagementController class.
////                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
////                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
////                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
////                .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMIN_TRAINEE.name())
//                .anyRequest()
//                .authenticated()
//                .and()
////                .httpBasic();
//                .formLogin()
//                    .loginPage("/login")
//                    .permitAll()
//                    .defaultSuccessUrl("/courses", true)
//                    .passwordParameter("password") //default.
//                    .usernameParameter("username") //default -> change if in login page used other than NAME="inThisCaseUsername"
//                .and()
//                .rememberMe()
//                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
//                    .key("somethingveryseccured") // defaults 2 weeks
//                    .rememberMeParameter("remember-me") //default
//                .and()
//                .logout()
//                    .logoutUrl("/logout")
//                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")) // TODO: DELETE THIS IF USE CSRF TO MAKE IT POST (safer);
//                    .clearAuthentication(true)
//                    .invalidateHttpSession(true)
//                    .deleteCookies("JSESSIONID", "remember-me")
//                    .logoutSuccessUrl("/login");
//
//
//        return http.build();
//    }


    //JWT IMPLEMENTATION
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                //make sure using stateless
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(http.getSharedObject(AuthenticationConfiguration.class)), jwtConfig, secretKey))
                .addFilterAfter(new JwtTokenVerifier(jwtConfig, secretKey), JwtUsernameAndPasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
                .anyRequest()
                .authenticated();

        return http.build();
    }

//    @Bean
//    protected UserDetailsService userDetailsService() {
//
//        UserDetails gabeSzawaraUser = User.builder()
//                .username("gabeszawara")
//                .password(passwordEncoder.encode("password"))
////                .roles(ApplicationUserRole.STUDENT.name()) //ROLE_STUDENT
//                .authorities(ApplicationUserRole.STUDENT.grantedAuthorities())
//                .build();
//
//        UserDetails karolinaSzawaraUser = User.builder()
//                .username("karoszawara")
//                .password(passwordEncoder.encode("password"))
////                .roles(ApplicationUserRole.STUDENT.name()) //ROLE_STUDENT
//                .authorities(ApplicationUserRole.STUDENT.grantedAuthorities())
//                .build();
//
//        UserDetails matayUser = User.builder()
//                .username("matay")
//                .password(passwordEncoder.encode("admin"))
////                .roles(ApplicationUserRole.ADMIN.name()) //ROLE_ADMIN
//                .authorities(ApplicationUserRole.ADMIN.grantedAuthorities())
//                .build();
//
//        UserDetails oloUser = User.builder()
//                .username("olo")
//                .password(passwordEncoder.encode("password"))
////                .roles(ApplicationUserRole.ADMIN_TRAINEE.name()) //ROLE_ADMIN_TRAINEE
//                .authorities(ApplicationUserRole.ADMIN_TRAINEE.grantedAuthorities())
//                .build();
//
//        return new InMemoryUserDetailsManager(
//                gabeSzawaraUser,
//                matayUser,
//                oloUser,
//                karolinaSzawaraUser
//        );
//    }


//DALEM RADE BEZ TEGO. NIE WIEM PO CO TO DOKLADANIE
//    public void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.authenticationProvider(daoAuthenticationProvider());
//    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    //NEED TO USE OWN UserServiceDetails
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        //my password encoder
        provider.setPasswordEncoder(passwordEncoder);
        //my own implementation of userDetailsService
        provider.setUserDetailsService(applicationUserService);

        return provider;
    }
}
