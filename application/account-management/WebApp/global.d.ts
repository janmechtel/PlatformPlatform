export declare global {
  /**
   * Build Environment Variables
   */
  interface BuildEnv {}

  /**
   * Runtime Environment Variables
   */
  interface RuntimeEnv {
    /* Public url / base url */
    PUBLIC_URL: string;
    /* CDN url / location of client bundle files */
    CDN_URL: string;
    /* Application version */
    APPLICATION_VERSION: string;

  }

  interface UserInfoEnv {
    /* User locale */
    LOCALE: string;
    /* User email */
    USER_EMAIL: string;
    /* Tenant id */
    TENANT_ID: string;
    /* User role */
    USER_ROLE: string;
    /* User name */
    USER_NAME: string;
    /* Is user authenticated */
    IS_USER_AUTHENTICATED: string;
  }

  /**
   * Both Build and Runtime Environment variables
   */
  type Environment = BuildEnv & RuntimeEnv & UserInfoEnv;

  declare interface ImportMeta {
    env: Environment;
    build_env: BuildEnv;
    runtime_env: RuntimeEnv & UserInfoEnv;
  }
}
