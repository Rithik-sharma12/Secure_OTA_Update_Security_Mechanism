export const OTA_AUTH_TOKEN_KEY = 'ota_auth_token';
export const OTA_AUTH_USER_KEY = 'ota_auth_user';

export type StoredAuthUser = {
  id: string;
  username: string;
  role: 'admin' | 'operator' | 'viewer';
};

export function getStoredAuthToken() {
  if (typeof window === 'undefined') {
    return null;
  }

  return localStorage.getItem(OTA_AUTH_TOKEN_KEY);
}

export function getStoredAuthUser(): StoredAuthUser | null {
  if (typeof window === 'undefined') {
    return null;
  }

  const raw = localStorage.getItem(OTA_AUTH_USER_KEY);
  if (!raw) {
    return null;
  }

  try {
    return JSON.parse(raw) as StoredAuthUser;
  } catch {
    return null;
  }
}

export function persistAuthSession(token: string, user: StoredAuthUser) {
  if (typeof window === 'undefined') {
    return;
  }

  localStorage.setItem(OTA_AUTH_TOKEN_KEY, token);
  localStorage.setItem(OTA_AUTH_USER_KEY, JSON.stringify(user));
}

export function clearAuthSession() {
  if (typeof window === 'undefined') {
    return;
  }

  localStorage.removeItem(OTA_AUTH_TOKEN_KEY);
  localStorage.removeItem(OTA_AUTH_USER_KEY);
}

export async function apiFetch(input: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers || {});
  const token = getStoredAuthToken();

  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  return fetch(input, {
    ...init,
    headers,
  });
}
