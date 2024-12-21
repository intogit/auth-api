# Go Authentication Service

A simple **authentication service** in Go, implementing cookie-based session management secured with **CSRF tokens**. 
It provides user authentication with secure signup, login, logout, and protected resource access.

---

## API Features

1. **Signup API** (`/signup`):
   - Creates accounts with hashed passwords.
   - Enforces password strength (minimum 8 characters).
   - Prevents duplicate user registration.

2. **Signin API** (`/signin`):
   - Authenticates users with username and password.
   - Issues a **session token** (stored in an HttpOnly, Secure cookie) and a **CSRF token** (in response headers).

3. **Home API** (`/home`):
   - Verifies the session token (cookie) and CSRF token (header) for access to protected resources.

4. **Signout API** (`/signout`):
   - Invalidates the session and CSRF tokens, clearing cookies securely.

---

## Security Features

- **Password Hashing**: Ensures secure password storage.
- **Session Cookies**: HttpOnly, Secure, and SameSite flags for enhanced security.
- **CSRF Protection**: Validates CSRF tokens to prevent cross-site attacks.

---

## How to Run
Clone the repository:
   ```bash
   git clone https://github.com/your-username/your-repo-name.git
   cd your-repo-name
   go run main.go
```
Access at: http://localhost:8080
