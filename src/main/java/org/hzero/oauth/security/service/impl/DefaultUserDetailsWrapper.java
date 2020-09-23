package org.hzero.oauth.security.service.impl;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.choerodon.core.exception.CommonException;
import io.choerodon.core.oauth.CustomUserDetails;

import org.hzero.common.HZeroService;
import org.hzero.core.base.BaseConstants;
import org.hzero.core.redis.RedisHelper;
import org.hzero.core.redis.safe.SafeRedisHelper;
import org.hzero.oauth.domain.repository.UserRepository;
import org.hzero.oauth.domain.service.RootUserService;
import org.hzero.oauth.domain.vo.Role;
import org.hzero.oauth.domain.vo.UserRoleDetails;
import org.hzero.oauth.security.exception.LoginExceptions;
import org.hzero.oauth.security.service.UserDetailsWrapper;

/**
 * 处理 UserDetails
 *
 * @author bojiangzhou 2019/02/27
 */
public class DefaultUserDetailsWrapper implements UserDetailsWrapper {
    private static final Logger logger = LoggerFactory.getLogger(DefaultUserDetailsWrapper.class);
    private static final String ROLE_MERGE_PREFIX = "hpfm:config:ROLE_MERGE.";

    private UserRepository userRepository;
    private RedisHelper redisHelper;

    public DefaultUserDetailsWrapper(UserRepository userRepository, RedisHelper redisHelper) {
        this.userRepository = userRepository;
        this.redisHelper = redisHelper;
    }

    @Override
    public void warp(CustomUserDetails details, Long userId, Long tenantId, boolean login) {
        logger.debug(">>>>> Before warp[{},{}] : {}", userId, tenantId, details);
        if (details.getTenantId() != null) {
            tenantId = details.getTenantId();
        }
        List<UserRoleDetails> roleDetailList = selectUserRoles(details, tenantId);
        if (CollectionUtils.isNotEmpty(roleDetailList)) {
            List<Long> tenantIds = roleDetailList.stream().map(UserRoleDetails::getTenantId).distinct().collect(Collectors.toList());
            // 如果是登录
            if (login) {
                UserRoleDetails userRoleDetails = roleDetailList.get(0);
                // 如果有设置默认租户并且默认租户在可访问租户列表中取默认租户
                if (userRoleDetails.getDefaultTenantId() != null && tenantIds.contains(userRoleDetails.getDefaultTenantId())) {
                    tenantId = userRoleDetails.getDefaultTenantId();
                }
                // 如果没有默认租户，有租户访问历史并且最近访问租户再可访问租户列表中，默认登录最近访问租户
                else if (userRoleDetails.getAccessDatetime() != null && tenantIds.contains(userRoleDetails.getTenantId())) {
                    tenantId = userRoleDetails.getTenantId();
                }
            }
            // 如果当前租户不属于可访问租户列表，取可访问租户列表第一条
            if (!tenantIds.contains(tenantId)) {
                tenantId = tenantIds.stream()
                        .findFirst()
                        .orElseThrow(() -> new CommonException(LoginExceptions.ROLE_NONE.value()));
            }
            for (UserRoleDetails roleDetails : roleDetailList) {
                if (Objects.equals(tenantId, roleDetails.getTenantId())) {
                    // 筛选当前租户下可访问的角色（出现冲突时必定是数据问题，这里留一手）
                    Map<Long, Role> roleMap = roleDetails.getRoles().stream().collect(Collectors.toMap(Role::getId, Function.identity(), (v1, v2) -> v1));
                    // 防止加载用户信息时覆盖掉当前用户选择的租户
                    if (details.getRoleId() == null || !roleMap.containsKey(details.getRoleId())) {
                        Role role;
                        if (roleMap.containsKey(roleDetails.getDefaultRoleId())) {
                            role = roleMap.get(roleDetails.getDefaultRoleId());
                        } else {
                            role = roleDetails.getRoles().stream().findFirst().orElse(new Role());
                        }
                        details.setRoleId(role.getId());
                    }
                    details.setRoleIds(new ArrayList<>(roleMap.keySet()));
                    details.setSiteRoleIds(roleMap.values().stream()
                            .filter(item -> "site".equals(item.getLevel())).map(Role::getId)
                            .collect(Collectors.toList()));
                    details.setTenantRoleIds(roleMap.values().stream()
                            .filter(item -> "organization".equals(item.getLevel())).map(Role::getId)
                            .collect(Collectors.toList()));
                    details.setTenantIds(tenantIds);
                    if (details.getTenantId() != null && !tenantIds.contains(details.getTenantId())) {
                        details.setTenantId(null);
                    } else {
                        details.setTenantId(tenantId);
                        details.setTenantNum(roleDetails.getTenantNum());
                        details.setRoleMergeFlag(Optional.ofNullable(roleDetails.getRoleMergeFlag())
                                .orElseGet(() -> {
                                    String roleMergeFlag = SafeRedisHelper.execute(HZeroService.Platform.REDIS_DB, () -> {
                                        String str = redisHelper.strGet(ROLE_MERGE_PREFIX + details.getTenantId());
                                        if (StringUtils.isBlank(str)) {
                                            str = redisHelper.strGet(ROLE_MERGE_PREFIX + BaseConstants.DEFAULT_TENANT_ID.toString());
                                        }
                                        return str;
                                    });

                                    return "1".equals(roleMergeFlag);
                                }));
                    }
                    break;
                }
            }
        }

        if (CollectionUtils.isEmpty(details.getRoleIds())) {
            logger.warn("User not assign any role! userId: {}", details.getUserId());
        }

        logger.debug(">>>>> After warp[{},{}] : {}", userId, tenantId, details);
    }

    protected List<UserRoleDetails> selectUserRoles(CustomUserDetails details, Long tenantId) {
        List<UserRoleDetails> roleDetailList = userRepository.selectRoleDetails(details.getUserId());

        if (RootUserService.isRootUser(details)) {
            // 查询出 root 用户可访问的其它租户
            userRepository.selectRootUserRoleDetails(details.getUserId(), tenantId)
                .stream()
                .findFirst()
                .ifPresent((tenant) -> {
                    UserRoleDetails userRoleDetails = roleDetailList.stream().filter(item -> Objects.equals(item.getTenantId(), tenantId)).findFirst().orElse(null);
                    if (userRoleDetails == null) {
                        roleDetailList.add(tenant);
                    } else {
                        Set<Long> ids = userRoleDetails.getRoles().stream().map(Role::getId).collect(Collectors.toSet());
                        List<Role> adminRoles = tenant.getRoles().stream().filter(r -> !ids.contains(r.getId())).collect(Collectors.toList());
                        userRoleDetails.getRoles().addAll(adminRoles);
                    }
                });
        }

        return roleDetailList;
    }
}
