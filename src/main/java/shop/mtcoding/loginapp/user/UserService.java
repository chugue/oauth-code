package shop.mtcoding.loginapp.user;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.UUID;

@RequiredArgsConstructor
@Service
public class UserService {
    private final UserRepository userRepository;

    @Transactional
    public void 회원가입(String username, String password, String email) {
        User user = User.builder()
                .username(username)
                .password(password)
                .email(email)
                .build();
        userRepository.save(user);
    }

    public User 로그인(String username, String password) {
        User user = userRepository.findByUsername(username);
        if(user == null){
            throw new RuntimeException("아이디가 없습니다");
        }else{
            if(user.getPassword().equals(password)){
                return user;
            }else{
                throw new RuntimeException("비밀번호가 틀렸습니다");
            }
        }
    }

    public User 카카오로그인(String code) {
        // 1. code로 카카오에서 토큰 받기 (위임완료) - oauth2.0

        // 1.1 RestTemplate 설정
        RestTemplate rt = new RestTemplate();

        // 1.2 http header 설정
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");

        // 1.3 http body 설정
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("client_id", "f00bd4f8c9f911e1f0e602eda55bbd52");
        body.add("redirect_uri", "http://localhost:8080/oauth/callback");
        body.add("code", code);

        // 1.4 body+header 객체 만들기
        HttpEntity<MultiValueMap<String, String>> request =
                new HttpEntity<>(body, headers);

        // 1.5 api 요청하기 (토큰 받기)
        ResponseEntity<KakaoResponse.TokenDTO> response = rt.exchange(
                "https://kauth.kakao.com/oauth/token",
                HttpMethod.POST,
                request,
                KakaoResponse.TokenDTO.class);

        // 1.6 값 확인
        System.out.println(response.getBody().toString());

        // 2. 토큰으로 사용자 정보 받기 (PK, Email)
        HttpHeaders headers2 = new HttpHeaders();
        headers2.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");
        headers2.add("Authorization", "Bearer "+response.getBody().getAccessToken());

        HttpEntity<MultiValueMap<String, String>> request2 =
                new HttpEntity<>(headers2);

        ResponseEntity<KakaoResponse.KakaoUserDTO> response2 = rt.exchange(
                "https://kapi.kakao.com/v2/user/me",
                HttpMethod.GET,
                request2,
                KakaoResponse.KakaoUserDTO.class);

        System.out.println("response2 : "+response2.getBody().toString());

        // 3. 해당정보로 DB조회 (있을수, 없을수)
        String username = "kakao_"+response2.getBody().getId();
        User userPS = userRepository.findByUsername(username);

        // 4. 있으면? - 조회된 유저정보 리턴
        if(userPS != null){
            System.out.println("어? 유저가 있네? 강제로그인 진행");
            return userPS;
        }else{
            System.out.println("어? 유저가 없네? 강제회원가입 and 강제로그인 진행");
            // 5. 없으면? - 강제 회원가입
            // 유저네임 : (provider_pk)
            // 비밀번호 : UUID
            // 이메일 : email 받은 값
            // 프로바이더 : kakao
            User user = User.builder()
                    .username(username)
                    .password(UUID.randomUUID().toString())
                    .email(response2.getBody().getProperties().getNickname()+"@nate.com")
                    .provider("kakao")
                    .build();
            User returnUser = userRepository.save(user);
            return returnUser;
        }
    }
}
