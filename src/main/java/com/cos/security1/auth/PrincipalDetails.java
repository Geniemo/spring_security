package com.cos.security1.auth;

import com.cos.security1.model.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

// 시큐리티가 /login 을 낚아채서 로그인을 진행시킨다.
// 로그인을 완료하면 시큐리티 session 을 만들어준다. (Security ContextHolder 라는 키 값에다가 세션 정보를 저장한다.)
// 이 때 세션에 들어갈 수 있는 오브젝트는 정해져있다. => Authentication 타입 객체
// Authentication 안에 User 정보가 있어야 한다.
// User 오브젝트 타입 => UserDetails 타입 객체

// Security Session 에 정보를 저장하는데 여기에 들어갈 수 있는 객체가 Authentication 이고,
// Authentication 에 유저 정보 저장할 때 UserDetails 로 저장한다.
@AllArgsConstructor
@Getter
public class PrincipalDetails implements UserDetails {

    private User user;
    
    // 해당 유저의 권한을 리턴하는 곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collection;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    // 만료된 계정인지?
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 잠긴 계정인지?
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 비밀번호 같은 인증 정보가 너무 오래된 건 아닌지?
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 계정이 활성화 됐는지?
    @Override
    public boolean isEnabled() {
        // 예를 들어 유저에 마지막 로그인 시간이 있다면 현재 시간 - 로그인 시간 해서 1년 지났다면 false 반환하는 식으로 구현
        return true;
    }
}
