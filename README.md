A simple authentication service in Go, implementing cookie-based session management secured with CSRF tokens. 
It provides user authentication with secure signup, signin, signout, and protected resource access.

APIs:
/signup
/signin
/signout
/home

Signup API (/signup):
  -> Creates accounts with hashed passwords.
  -> Enforces password strength (minimum 8 characters).
  -> Prevents duplicate user registration.
Signin API (/signin):
  -> Authenticates users with username and password.
  -> Issues a session token (stored in an HttpOnly, Secure cookie) and a CSRF token (in response headers).
Home API (/home):
  -> Verifies the session token (cookie) and CSRF token (header) for access to protected resources.
Signout API (/signout):
  -> Invalidates the session and CSRF tokens, clearing cookies securely.

Security:
-> Password Hashing: Ensures secure password storage.
-> Session Cookies: HttpOnly, Secure, and SameSite flags for enhanced security.
-> CSRF Protection: Validates CSRF tokens to prevent cross-site attacks.
