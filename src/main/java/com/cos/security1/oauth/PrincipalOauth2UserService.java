package com.cos.security1.oauth;

import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    
    // 구글로부터 받은 userRequest 데이터에 대한 후처리 함수
    // 메서드 종료 시 @AuthenticationPrincipal 어노테이션 생성
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("userRequest = " + userRequest);
        System.out.println("userRequest.getClientRegistration() = " + userRequest.getClientRegistration()); // 여기서 있는 registrationId 로 어떤 OAuth 로 로그인 했는지 확인 가능
        System.out.println("userRequest.getAccessToken() = " + userRequest.getAccessToken());
        System.out.println("userRequest.getAccessToken().getTokenValue() = " + userRequest.getAccessToken().getTokenValue());
        // 구글 로그인 버튼 클릭 -> 구글 로그인 창 -> 로그인 완료 -> code 를 리턴 -> 이 값을 OAuth-Client 가 받음 -> AccessToken 요청
        // userRequest 접오 -> loadUser 호출 -> 구글로부터 회원 프로필을 받아준다.
        System.out.println("super.loadUser(userRequest).getAttributes() = " + super.loadUser(userRequest).getAttributes());
        /*
        {
            sub=100062039857346886280,
            name=JiWeon Park,
            given_name=JiWeon,
            family_name=Park,
            picture=https://lh3.googleusercontent.com/a/AItbvmm5wI2cs4KtgaDg6glixx5hPwnh6IG_1NDi5HX6=s96-c,
            email=kor98won@gmail.com,
            email_verified=true,
            locale=ko
        }

        위와 같은 정보들이 getAttributes 를 통해서 나오는데, 이를 이용해 다음과 같이 회원가입을 진행할 것이다.
        username = "google_{sub}"
        password = "암호화(박지원)" 비밀번호는 null 만 아니면 딱히 상관이 없다.
        email = "{email}"
        role = "ROLE_USER"
        provider = "google"
        providerId = "{sub}"
         */
        OAuth2User oAuth2User = super.loadUser(userRequest);
        String provider = userRequest.getClientRegistration().getRegistrationId(); // google
        String providerId = oAuth2User.getAttribute("sub");
        String username = provider + providerId;
        String email = oAuth2User.getAttribute("email");
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);
        if (userEntity == null) {
            // 소셜 로그인 사용자는 비밀번호가 null 이라 일반적 방식으로 로그인 할 수 없음
            userEntity = User.builder()
                    .username(username)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }
        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
