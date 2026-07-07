# How to Securely Store JWT Tokens in Cookies (Avoid XSS Risks)

> **Author**: Oviyan S
> **Published**: Feb 12, 2026

---

![Oviyan S](https://miro.medium.com/v2/resize:fill:32:32/1*F2KTkv3ClQuvXh6bwAwtAA.png)

8

Listen

Share

So there I was, feeling pretty proud of myself. I’d just finished building a full-stack authentication system with Django and React. JWT tokens, protected routes, the whole nine yards.

I pushed my code for review, confident it would sail through.

Two hours later, my senior dev dropped a comment that made my stomach sink:

“Why are you storing tokens in localStorage? That’s an XSS vulnerability waiting to happen.”

Wait, what?

I’d followed tutorials. Everyone stores tokens in localStorage. How is that insecure?

That’s when I learned about cookies, HttpOnly flags, and why every security expert rolls their eyes when they see JWT tokens sitting in localStorage like an unlocked safe.

Let me save you from the same embarrassing code review.

### The localStorage Problem (That Nobody Talks About)

Here’s what I thought I understood: “localStorage is persistent storage in the browser. Perfect for tokens!”

Here’s what I didn’t understand: Any JavaScript code can read localStorage.

Think about that. Any script running on your page — including malicious scripts injected through XSS attacks — can access your tokens.

It’s like writing your bank PIN on a sticky note and leaving it on your desk. Sure, it’s convenient. But anyone who walks by can see it.

### The Attack Scenario

Imagine this:

- A hacker finds an XSS vulnerability in your app
- They inject malicious JavaScript
- That script runs: localStorage.getItem('accessToken')
- Boom — they have your token
- They impersonate you, access your data, and cause havoc

This isn’t theoretical. This happens in real apps every day.

### Enter Cookies (The Secure Alternative)

“But wait,” I said when my senior explained this. “Cookies are old technology. Aren’t they less secure?”

“Not if you configure them properly,” he replied.

Cookies have three superpowers that localStorage doesn’t:

HttpOnly Flag → JavaScript can’t access the cookie at all. Even malicious scripts are blocked.

Secure Flag → Cookie only travels over HTTPS. No one intercepts it on public WiFi.

SameSite Flag → Prevents CSRF attacks by restricting cross-site requests.

It’s like putting your bank PIN in a locked vault instead of a sticky note. Way better.

If you haven’t read the previous blog about JWT authentication, read it

- JWT Authentication in Django: How Login Actually Works (After Months of Confusion)
- JWT Authentication with Django REST & React: Making Login Work on the Frontend (Part 2)

### What We’re Building Today

We’re taking a standard JWT authentication system and upgrading it to store tokens in secure cookies instead of localStorage.

Here’s the flow:

- User logs in with username/password
- Backend generates JWT access and refresh tokens
- Backend sets tokens in HttpOnly cookies (not in response body)
- Backend sends user data (id, username, email) in response
- Browser automatically includes cookies in all future requests
- Frontend never touches the tokens directly

Cleaner, safer, more professional.

![image](https://miro.medium.com/v2/resize:fit:700/1*dLgKDu1K6fQpyAAy9Rl-lA.png)

### Step 1: The Foundation (JWT Setup)

First, install SimpleJWT if you haven’t:

```
pip install djangorestframework-simplejwt
```

Configure your settings.py:

```
INSTALLED_APPS = [
    # ... Django defaults
    "rest_framework",
    "rest_framework_simplejwt",
]
```

```
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    )
}
# Token lifetimes
from datetime import timedelta
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=5),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
}
```

Nothing fancy here. Standard JWT setup. Access tokens expire quickly (5 minutes), refresh tokens last longer (1 day).

### Step 2: The Custom Login View (Where the Magic Happens)

Here’s where we diverge from the tutorials. We’re NOT returning tokens in the response body.

Create core/views.py:

```
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.response import Response
from django.contrib.auth.models import User
class CookieTokenObtainPairView(TokenObtainPairView):
    
    def post(self, request, *args, **kwargs):
        # Generate tokens like normal
        response = super().post(request, *args, **kwargs)
        
        # Extract tokens from response
        access_token = response.data.get("access")
        refresh_token = response.data.get("refresh")
        
        # Get user data
        user = User.objects.get(username=request.data["username"])
        
        # Replace response data (remove tokens, add user info)
        response.data = {
            "message": "Login successful",
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email
            }
        }
        
        # Store access token in secure cookie
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,      # JavaScript can't access
            secure=False,       # True in production (HTTPS only)
            samesite="Lax"      # CSRF protection
        )
        
        # Store refresh token in secure cookie
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=False,       # True in production
            samesite="Lax"
        )
        
        return response
```

### What’s Happening Here?

Let me break this down step by step:

Line 6: We call the parent class’s post() method, which generates the tokens normally.

Lines 9–10: We extract the tokens from the response. They’re still there, just temporarily.

Lines 13: We look up the user who just logged in.

Lines 16–23: We replace the response data. Instead of sending tokens, we send a success message and user info.

Lines 26–33: We store the access token in a cookie with security flags.

Lines 36–42: We store the refresh token in a cookie with the same security flags.

The tokens never appear in the response body. They’re hiding in secure cookies where JavaScript can’t touch them.

### Step 3: Understanding the Cookie Flags (Critical)

Let’s talk about those flags because they’re the whole point:

### httponly=True

This is the killer feature. It tells the browser: “JavaScript cannot access this cookie. Not even the code running on this website.”

Even if a hacker injects malicious JavaScript, they can’t do:

javascript

```
document.cookie  // Returns nothing for HttpOnly cookies
```

The token is invisible to scripts. Beautiful.

### secure=False (for now)

In development, you’re running HTTP (not HTTPS), so use False.

In production, ALWAYS set secure=True. This ensures the cookie only travels over encrypted HTTPS connections.

No HTTPS? No cookie sent. Simple.

### samesite=”Lax”

This prevents CSRF (Cross-Site Request Forgery) attacks.

“Lax” means the cookie is sent with top-level navigation but not with cross-site POST requests from other domains.

## Get Oviyan S’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Translation: Your site can use the cookie, but malicious sites can’t trick your browser into sending it.

## Step 4: Wire Up the URLs

Create core/urls.py:

```
from django.urls import path
from .views import CookieTokenObtainPairView
urlpatterns = [
    path("login/", CookieTokenObtainPairView.as_view(), name="cookie_login"),
]
```

Include it in main urls.py:

```
from django.contrib import admin
from django.urls import path, include
urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/auth/", include("core.urls")),
]
```

Now, when users POST to /api/auth/login/, They get:

- User data in the response body
- Tokens in secure cookies (invisible)

## Step 5: The CORS Configuration (Don’t Skip This)

Here’s where I got stuck for an hour.

If your React app runs on localhost:5173 and Django runs on localhost:8000, Cookies won't work without CORS configuration.

Install CORS headers:

```
pip install django-cors-headers
```

Update settings.py:

```
INSTALLED_APPS = [
    # ... other apps
    "corsheaders",
]
```

```
MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",  # Must be at the top
    # ... other middleware
]
# Allow your React app's origin
CORS_ALLOWED_ORIGINS = [
    "http://localhost:5173",  # React dev server
]
# CRITICAL: Allow credentials (cookies)
CORS_ALLOW_CREDENTIALS = True
```

Without CORS_ALLOW_CREDENTIALS = True, the browser refuses to send cookies cross-origin. Took me way too long to figure that out.

## Step 6: Frontend Configuration (Axios)

On the frontend, you need to tell Axios to include cookies with every request.

Globally:

javascript

```
axios.defaults.withCredentials = true;
```

Or per request:

javascript

```
axios.get("http://localhost:8000/api/protected/", {
  withCredentials: true
});
```

This tells the browser: “Yes, please include cookies when making this request.”

Without this, cookies stay in the browser and never get sent. Your backend sees no token and rejects the request.

## Step 7: Testing It Out

Let’s see if this works.

Login Request (Postman or Frontend):

```
POST http://localhost:8000/api/auth/login/
Body: {
  "username": "testuser",
  "password": "testpass123"
}
```

Response:

```
{
  "message": "Login successful",
  "user": {
    "id": 1,
    "username": "testuser",
    "email": "test@example.com"
  }
}
```

Notice: No tokens in the response. But check the cookies in your browser dev tools:

```
access_token: eyJ0eXAiOiJKV1QiLCJhbGc...
refresh_token: eyJ0eXAiOiJKV1QiLCJhbGc...
```

Both marked as HttpOnly. JavaScript can't see them. Perfect.

Protected Request:

```
GET http://localhost:8000/api/protected/
```

The browser automatically includes the cookies. Django sees the token, validates it, and grants access.

You never manually attached a token. The browser did it for you.

## Bonus: Logout (Clearing the Vault)

When users log out, we need to delete the cookies.

Add to core/views.py:

python

```
from rest_framework.views import APIView
from rest_framework.response import Response
class LogoutView(APIView):
    
    def post(self, request):
        response = Response({"message": "Logout successful"})
        
        # Delete both cookies
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        
        return response
```

Add the URL:

```
path("logout/", LogoutView.as_view(), name="logout"),
```

Now when users log out, both cookies are removed. Clean slate.

## What We Just Accomplished

Let’s recap the upgrade:

Before (localStorage approach):

- Tokens visible to JavaScript
- Vulnerable to XSS attacks
- Frontend manually manages tokens
- Error-prone token handling

After (cookie approach):

- Tokens invisible to JavaScript (HttpOnly)
- Protected from XSS attacks
- Browser manages tokens automatically
- Secure flags prevent CSRF and interception
- Professional security posture

Same functionality, way better security.

## The Production Checklist

Before deploying to production, change these settings:

python

```
response.set_cookie(
    key="access_token",
    value=access_token,
    httponly=True,
    secure=True,        # Changed from False
    samesite="Strict"   # Changed from Lax (stricter)
)
```

secure=True requires HTTPS. If you're deploying to Heroku, Vercel, or any modern platform, you have HTTPS by default.

samesite="Strict" is even more restrictive than "Lax" - better for production security.

## The Reality Check

When my senior dev first explained this, I thought, “Isn’t this overkill? Who’s really going to attack my little app?”

Then he showed me the CVE database thousands of real attacks exploiting localStorage token storage. Companies are losing user data. Lawsuits. PR nightmares.

“Security isn’t about preventing attacks on your app specifically,” he said. “It’s about not being the low-hanging fruit.”

If you’re storing tokens in localStorage, you’re low-hanging fruit. Don’t be that developer.

## What You Learned Today

You now know:

- Why localStorage is insecure for tokens
- How HttpOnly cookies prevent JavaScript access
- How to set secure cookies in Django
- How to configure CORS for cross-origin cookies
- How to make the browser handle token management

This isn’t just a tutorial you followed. This is professional security practice that real companies use.

Next time someone suggests storing tokens in localStorage, you’ll know better.

Questions? Drop a comment:

- Did this change how you think about authentication security?
- Are you refactoring your old projects now?
- What other security topics do you want explained?

You’re not just building apps anymore. You’re building secure apps. That’s a big difference.

Let me know what you want to learn next!



---
*Original URL: [https://medium.com/@oviyan007/how-to-securely-store-jwt-tokens-in-cookies-avoid-xss-risks-13812db41c34?source=search_post---------61-----------------------------------](https://medium.com/@oviyan007/how-to-securely-store-jwt-tokens-in-cookies-avoid-xss-risks-13812db41c34?source=search_post---------61-----------------------------------)*
