import type { AppConfig, MockTenant, MockUser } from "../config.js";
import { findTenant, findUser } from "./validation.js";

export type ResolvedUser = {
  user: MockUser;
  homeTenant: MockTenant;
  shared: boolean;
};

export function listEffectiveUsers(config: AppConfig, tenant: MockTenant): ResolvedUser[] {
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

export function resolveEffectiveUser(config: AppConfig, tenant: MockTenant, userSub: string): ResolvedUser | undefined {
  return listEffectiveUsers(config, tenant).find((entry) => entry.user.sub === userSub);
}

export function resolveEffectiveUserByUsername(
  config: AppConfig,
  tenant: MockTenant,
  username: string
): ResolvedUser | undefined {
  const normalized = username.toLowerCase();
  return listEffectiveUsers(config, tenant).find(({ user }) =>
    user.email.toLowerCase() === normalized ||
    user.preferred_username.toLowerCase() === normalized
  );
}
