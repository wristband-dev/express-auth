export const FORM_URLENCODED_MEDIA_TYPE: string = 'application/x-www-form-urlencoded';
export const JSON_MEDIA_TYPE: string = 'application/json;charset=UTF-8';
export const LOGIN_REQUIRED_ERROR: string = 'login_required';
export const LOGIN_STATE_COOKIE_SEPARATOR: string = '#';
export const LOGIN_STATE_COOKIE_PREFIX: string = `login${LOGIN_STATE_COOKIE_SEPARATOR}`;
export const MAX_REFRESH_ATTEMPTS: number = 3;
export const MAX_REFRESH_ATTEMPT_DELAY_MS: number = 100;
export const TENANT_DOMAIN_PLACEHOLDER: string = '{tenant_domain}';
export const TENANT_NAME_PLACEHOLDER: string = '{tenant_name}';
// Regex to match either placeholder
export const TENANT_PLACEHOLDER_REGEX = /\{tenant_(?:domain|name)\}/;
export const TENANT_PLACEHOLDER_MSG = '"{tenant_name}" or "{tenant_domain}" placeholder';
