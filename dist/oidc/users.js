import { findTenant, findUser } from "./validation.js";
export function listEffectiveUsers(config, tenant) {
    const users = tenant.users.map((user) => ({ user, homeTenant: tenant, shared: false }));
    for (const sharedUser of tenant.sharedUsers ?? []) {
        const homeTenant = findTenant(config, sharedUser.tenantId);
        const user = homeTenant ? findUser(homeTenant, sharedUser.userSub) : undefined;
        if (homeTenant && user && !users.some((entry) => entry.user.sub === user.sub)) {
            users.push({ user, homeTenant, shared: true });
        }
    }
    return users;
}
export function resolveEffectiveUser(config, tenant, userSub) {
    return listEffectiveUsers(config, tenant).find((entry) => entry.user.sub === userSub);
}
export function resolveEffectiveUserByUsername(config, tenant, username) {
    const normalized = username.toLowerCase();
    return listEffectiveUsers(config, tenant).find(({ user }) => user.email.toLowerCase() === normalized ||
        user.preferred_username.toLowerCase() === normalized);
}
