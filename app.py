from fastapi import FastAPI, Request
from fastapi.responses import Response
from authentication.src.auth_user import auth_user
from fastapi.middleware.cors import CORSMiddleware
from authentication.src.google_auth import google_user_auth
import os
from scalar_fastapi import get_scalar_api_reference
from starlette.middleware.sessions import SessionMiddleware
app = FastAPI()
app.include_router(auth_user)
app.include_router(google_user_auth)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure this appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET_KEY"))


# @app.middleware("http")
# async def set_security_headers(request: Request, call_next):
#     response: Response = await call_next(request)

#     # Security Headers
#     response.headers["Cache-Control"] = "no-store"
#     response.headers["Pragma"] = "no-cache"
#     response.headers["X-Frame-Options"] = "DENY"
#     response.headers["X-Content-Type-Options"] = "nosniff"
#     response.headers["Referrer-Policy"] = "no-referrer"
#     response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    
#     # Adjusted CSP for Google Fonts, JS/CDN, and secure defaults
#     response.headers["Content-Security-Policy"] = (
#         "default-src 'self'; "
#         "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://ajax.googleapis.com https://unpkg.com; "
#         "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
#         "font-src 'self' https://fonts.gstatic.com; "
#         "img-src 'self' data:; "
#         "connect-src 'self'; "
#         "frame-ancestors 'none';"
#     )

#     return response

@app.get("/scalar", include_in_schema=False)
def get_scalar_docs():
    return get_scalar_api_reference(
        openapi_url=app.openapi_url,
        title="Scalar API"
    )