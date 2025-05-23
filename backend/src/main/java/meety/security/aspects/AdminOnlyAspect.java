package meety.security.aspects;

import meety.models.GroupMember;
import meety.models.User;
import meety.models.enums.Role;
import meety.repositories.GroupMemberRepository;
import meety.services.auth.AuthService;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Optional;


@Aspect
@Component
public class AdminOnlyAspect {

    @Autowired
    private AuthService authService;

    @Autowired
    private GroupMemberRepository groupMemberRepository;

    @Before("@annotation(meety.security.annotations.AdminOnly)")
    public void checkAdmin(JoinPoint joinPoint) {
        User currentUser = authService.getCurrentUser();

        if (currentUser == null) {
            throw new SecurityException("Access denied: Not authenticated.");
        }

        Object[] args = joinPoint.getArgs();
        if (args.length == 0 || !(args[0] instanceof Long)) {
            throw new IllegalArgumentException("Method with @AdminOnly must have groupId (Long) as first argument.");
        }

        Long groupId = (Long) args[0];

        Optional<GroupMember> groupMemberOpt = groupMemberRepository.findByGroupIdAndUserId(groupId, currentUser.getId());

        if (groupMemberOpt.isEmpty() || groupMemberOpt.get().getRole() != Role.ADMIN) {
            throw new SecurityException("Access denied: Admin privileges for this group required.");
        }
    }
}