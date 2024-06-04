package shop.mtcoding.loginapp.user;

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
        if (user == null) {
            throw new RuntimeException("아이디가 없습니다");
        } else {
            if (user.getPassword().equals(password)) {
                return user;
            } else {
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
        ResponseEntity<UserResponse.KakaoTokenDTO> response = rt.exchange(
                "https://kauth.kakao.com/oauth/token",
                HttpMethod.POST,
                request,
                UserResponse.KakaoTokenDTO.class);

        // 1.6 값 확인
        System.out.println(response.getBody().toString());

        // 2. 토큰으로 사용자 정보 받기 (PK, Email)
        HttpHeaders headers2 = new HttpHeaders();
        headers2.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");
        headers2.add("Authorization", "Bearer " + response.getBody().getAccessToken());

        HttpEntity<MultiValueMap<String, String>> request2 =
                new HttpEntity<>(headers2);

        ResponseEntity<UserResponse.KakaoUserDTO> response2 = rt.exchange(
                "https://kapi.kakao.com/v2/user/me",
                HttpMethod.GET,
                request2,
                UserResponse.KakaoUserDTO.class);

        System.out.println("response2 : " + response2.getBody().toString());

        // 3. 해당정보로 DB조회 (있을수, 없을수)
        String username = "kakao_" + response2.getBody().getId();
        User userPS = userRepository.findByUsername(username);

        // 4. 있으면? - 조회된 유저정보 리턴
        if (userPS != null) {
            System.out.println("어? 유저가 있네? 강제로그인 진행");
            return userPS;
        } else {
            System.out.println("어? 유저가 없네? 강제회원가입 and 강제로그인 진행");
            // 5. 없으면? - 강제 회원가입
            // 유저네임 : (provider_pk)
            // 비밀번호 : UUID
            // 이메일 : email 받은 값
            // 프로바이더 : kakao
            User user = User.builder()
                    .username(username)
                    .password(UUID.randomUUID().toString())
                    .email(response2.getBody().getProperties().getNickname() + "@nate.com")
                    .provider("kakao")
                    .build();
            User returnUser = userRepository.save(user);
            return returnUser;
        }
    }

    @Transactional
    public User 네이버로그인(String code, String savedState, String state, String error, String errorDescription) throws Exception {
        RestTemplate rt = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();

        // 1. CSRF 검증
        if (savedState == null || !savedState.equals(state)) {
            throw new Exception("state 값이 일치하지 않습니다.");
        }

        // 2. 토큰 발급 요청 url 만들기

        // 2-1. 헤더 만들기
        headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");

        // 2-2. 바디 만들기
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("client_id", "5n2S0QuIYkxvAZ750gCw");
        body.add("client_secret", "z6aeFyWPSN");
        body.add("code", code);
        body.add("state", state);

        HttpEntity<MultiValueMap<String, String>> request =
                new HttpEntity<>(body, headers);

        // 3. 토큰 발급 요청 ( 이 시점에서 NaverTokenDTO먼저 만들고 와야됨!! )
        ResponseEntity<UserResponse.NaverTokenDTO> response = rt.exchange(
                "https://nid.naver.com/oauth2.0/token",
                HttpMethod.POST,
                request,
                UserResponse.NaverTokenDTO.class);

        // 값 확인
        System.out.println(response.getBody().toString());

        // 4. 사용자 정보 요청 url 만들기

        // 4-1. 헤더 만들기
        HttpHeaders headers2 = new HttpHeaders();
        headers2.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");
        headers2.add("Authorization", "Bearer " + response.getBody().getAccessToken());

        HttpEntity<MultiValueMap<String, String>> request2 =
                new HttpEntity<>(headers2);

        // 4-2. NaverUserDTO 만들기
        // 4-3. 사용자 정보 요청하기
        ResponseEntity<UserResponse.NaverUserDTO> response2 = rt.exchange(
                "https://openapi.naver.com/v1/nid/me",
                HttpMethod.GET,
                request2,
                UserResponse.NaverUserDTO.class);

        // 값 확인
        System.out.println("response2 : " + response2.getBody().toString());

        // 5. 사용자 정보로 DB 조회
        String username = "naver_" + response2.getBody().getResponse().getId();
        User userPS = userRepository.findByUsername(username);

        // 5-1. 사용자 정보가 DB에 있으면??
        if (userPS != null) {
            System.out.println("어? 유저가 있네? 강제로그인 진행시켜!");
            return userPS;

        // 5-2. 사용자 정보가 DB에 없으면??
        } else {
            System.out.println("어? 유저가 없네? 강제회원가입 and 강제로그인 진행시켜!!");

            User user = User.builder()
                    .username(username)
                    .password(UUID.randomUUID().toString())
                    .email(response2.getBody().getResponse().getEmail())
                    .provider("naver")
                    .build();
            User returnUser = userRepository.save(user);
            return returnUser;
        }
    }

    public String 네이버요청주소생성(String state) {
        String clientId = "5n2S0QuIYkxvAZ750gCw";
        String redirectUri = "http://localhost:8080/oauth/callback/naver";
        String naverAuthUrl = "https://nid.naver.com/oauth2.0/authorize?response_type=code&client_id=" + clientId
                + "&redirect_uri=" + redirectUri + "&state=" + state;
        return naverAuthUrl;
    }
}
