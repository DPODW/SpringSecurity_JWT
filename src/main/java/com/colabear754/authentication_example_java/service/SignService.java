package com.colabear754.authentication_example_java.service;

import com.colabear754.authentication_example_java.dto.sign_in.request.SignInRequest;
import com.colabear754.authentication_example_java.dto.sign_in.response.SignInResponse;
import com.colabear754.authentication_example_java.dto.sign_up.request.SignUpRequest;
import com.colabear754.authentication_example_java.dto.sign_up.response.SignUpResponse;
import com.colabear754.authentication_example_java.entity.Member;
import com.colabear754.authentication_example_java.repository.MemberRepository;
import com.colabear754.authentication_example_java.security.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@RequiredArgsConstructor
@Service
public class SignService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder encoder;
    private final TokenProvider tokenProvider;

    @Transactional
    public SignUpResponse registMember(SignUpRequest request) {
        Member member = memberRepository.save(Member.from(request,encoder));
        try {
            memberRepository.flush(); //DB 무결성 제약 조건을 검사하는 역할을 함 -> 중복된 아이디면 무결설 위반, CATCH 의 예외 출력
        } catch (DataIntegrityViolationException e) {
            throw new IllegalArgumentException("이미 사용중인 아이디입니다.");
        }
        return SignUpResponse.from(member);
    }

    @Transactional(readOnly = true) //읽기 작업만 수행한다는 어노테이션
    public SignInResponse signIn(SignInRequest request) {
        Member member = memberRepository.findByAccount(request.account())
                .filter(it -> encoder.matches(request.password(), it.getPassword())) //it == member(it 에 사용자 정보가 들어있는 거임)
                .orElseThrow(() -> new IllegalArgumentException("아이디 또는 비밀번호가 일치하지 않습니다..."));
        String token = tokenProvider.createToken(String.format("%s:%s", member.getId(), member.getType()));	// 토큰 생성 , String.format("%s:%s") -> 문자열 수정
        return new SignInResponse(member.getName(), member.getType(),token);
    }
}
