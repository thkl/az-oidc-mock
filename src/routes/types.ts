import type { AppConfig } from "../config.js";
import type { Logger } from "../logger.js";
import type { SigningKeys } from "../oidc/keys.js";
import type { PasswordStore } from "../oidc/passwords.js";
import type { OidcState } from "../oidc/state.js";

export type RouteContext = {
  getConfig: () => AppConfig;
  keys: SigningKeys;
  logger: Logger;
  state: OidcState;
  passwordStore: PasswordStore;
  adminToken?: string;
  sessionSecret: string;
  configPath?: string;
  onConfigSaved?: (config: AppConfig) => void;
};
