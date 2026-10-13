export const OTA_AUTH_USER_KEY = 'ota_auth_user';
export const OTA_AUTH_TOKEN_KEY = 'ota_auth_token';
 
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

export function persistAuthSession(userOrToken: StoredAuthUser | string, maybeUser?: StoredAuthUser) {
  if (typeof window === 'undefined') {
    return;
  }

  const user = typeof userOrToken === 'string' ? maybeUser : userOrToken;
  if (!user) {
    return;
  }

  // Token is now handled by HttpOnly cookie on the server.
  // Only user data is stored in localStorage for client-side display.
  // Note: Storing user data in localStorage still carries an XSS risk.
  localStorage.setItem(OTA_AUTH_USER_KEY, JSON.stringify(user));
}

export async function clearAuthSession() {
  if (typeof window === 'undefined') {
    return;
  }

  // Make an API call to the server to clear the HttpOnly cookie
  try {
    await apiFetch('/api/auth/logout', { method: 'POST' });
  } catch (error) {
    console.error('Failed to clear session on server:', error);
  }

  localStorage.removeItem(OTA_AUTH_TOKEN_KEY);
  localStorage.removeItem(OTA_AUTH_USER_KEY);
}

export async function apiFetch(input: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers || {});

  // Removed Authorization header setting from client-side.
  // The HttpOnly cookie will be sent automatically by the browser.
  // Ensure 'credentials: include' is set to send cookies with cross-origin requests.
  // For same-origin requests, it's usually the default, but explicit is better.
  return fetch(input, {
    ...init,
    headers,
    credentials: 'include', // Important for sending HttpOnly cookies
  });
}
