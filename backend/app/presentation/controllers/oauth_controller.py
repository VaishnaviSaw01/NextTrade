"""
OAuth2 + TOTP Controller
========================

FastAPI controller for the admin login flow: Google OAuth2 followed by a
real, server-verified TOTP second factor.

Flow:
1. POST /auth/oauth/google   — exchanges the OAuth code, checks the email
   allow-list, and returns a short-lived *pre-auth* token. This token
   carries no "admin" permission and is rejected by every protected
   admin route — it exists only to prove *who* is completing login.
2. GET  /auth/totp/setup     — (bearer: pre-auth token) returns/creates
   the admin's TOTP secret + QR code.
3. POST /auth/totp/verify    — (bearer: pre-auth token) checks the
   submitted code against the stored secret with pyotp. Only on success
   does it mint a full, `totp_verified` access token — the one accepted
   by admin routes.
"""

from typing import Annotated, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import httpx
import structlog

from app.infrastructure.security.auth_service import AuthService
from app.infrastructure.security.jwt_handler import JWTHandler
from app.infrastructure.security.totp_service import TOTPService
from app.infrastructure.config.settings import Settings, get_settings


logger = structlog.get_logger()
router = APIRouter()
security = HTTPBearer(auto_error=False)


class OAuth2CallbackRequest(BaseModel):
    """OAuth2 callback request from frontend"""
    code: str
    redirect_uri: str


class OAuth2TokenResponse(BaseModel):
    """
    Response after a successful Google OAuth exchange.

    `access_token` here is a *pre-auth* token — good only for the TOTP
    setup/verify endpoints below, not for any admin API route.
    """
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: int
    totp_enabled: bool
    user: dict


class TOTPVerificationRequest(BaseModel):
    """TOTP verification request"""
    email: str
    totp_code: str


class TOTPVerificationResponse(BaseModel):
    """
    TOTP verification response.

    The token fields are populated only when `verified` is true — that's
    the moment a fully-privileged, `totp_verified` admin session is
    actually minted.
    """
    verified: bool
    message: str
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: Optional[str] = None
    expires_in: Optional[int] = None


async def _get_pre_auth_email(
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(security)],
    settings: Annotated[Settings, Depends(get_settings)]
) -> str:
    """
    Resolve the email of the caller completing second-factor login.

    Accepts either a pre-auth token (the normal case, right after Google
    OAuth) or an already fully-verified admin token (so an authenticated
    admin can re-run setup, e.g. to re-enroll a new device). Rejects
    everything else — this is what stops `/auth/totp/setup` and
    `/auth/totp/verify` from being callable anonymously.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = JWTHandler(settings).verify_token(credentials.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    email = payload.get("email") or payload.get("sub")
    token_type = payload.get("type")

    if email and token_type == "pre_auth":
        return email
    if email and token_type == "access" and payload.get("totp_verified") and "admin" in payload.get("permissions", []):
        return email

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.post("/auth/oauth/google", response_model=OAuth2TokenResponse)
async def google_oauth_callback(
    request: OAuth2CallbackRequest,
    settings: Annotated[Settings, Depends(get_settings)]
):
    """
    Handle Google OAuth2 callback and issue a pre-auth token.

    This endpoint:
    1. Exchanges the OAuth2 code for Google tokens
    2. Fetches the user's profile from Google
    3. Checks the email against ADMIN_EMAILS
    4. Issues a short-lived pre-auth token — NOT an admin session; that
       only happens after TOTP verification succeeds below.
    """
    try:
        # Exchange code for tokens with Google
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": request.code,
                    "client_id": settings.google_client_id,
                    "client_secret": settings.google_client_secret,
                    "redirect_uri": request.redirect_uri,
                    "grant_type": "authorization_code",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )

            if not token_response.is_success:
                error_data = token_response.json() if token_response.content else {}
                logger.error("Google token exchange failed",
                           error=error_data.get("error_description", "Unknown error"))
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Token exchange failed: {error_data.get('error_description', 'Unknown error')}"
                )

            tokens = token_response.json()

            # Get user info from Google
            user_response = await client.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {tokens['access_token']}"}
            )

            if not user_response.is_success:
                logger.error("Failed to fetch user info from Google")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to retrieve user information"
                )

            user_info = user_response.json()

        # Validate admin authorization
        admin_emails = settings.admin_emails or []

        if user_info["email"].lower() not in [email.lower() for email in admin_emails]:
            logger.warning("Unauthorized admin access attempt", email=user_info["email"])
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Unauthorized: You are not authorized to access the admin panel"
            )

        jwt_handler = JWTHandler(settings)
        pre_auth_token = jwt_handler.create_pre_auth_token({
            "sub": user_info["email"],
            "email": user_info["email"],
        })

        totp_enabled = TOTPService().has_secret(user_info["email"])

        logger.info("Admin OAuth2 exchange successful, awaiting TOTP", email=user_info["email"])

        return OAuth2TokenResponse(
            access_token=pre_auth_token,
            refresh_token=None,
            expires_in=600,  # 10 minutes — matches JWTHandler.pre_auth_token_expire_minutes
            totp_enabled=totp_enabled,
            user={
                "email": user_info["email"],
                "name": user_info.get("name", user_info["email"]),
                "picture": user_info.get("picture")
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("OAuth2 authentication error", error=str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed due to server error"
        )


@router.post("/auth/totp/verify", response_model=TOTPVerificationResponse)
async def verify_totp(
    request: TOTPVerificationRequest,
    token_email: Annotated[str, Depends(_get_pre_auth_email)],
    settings: Annotated[Settings, Depends(get_settings)]
):
    """
    Verify a TOTP code and, on success, issue a fully-verified admin
    session. This is the actual second factor — every submitted code is
    checked against the admin's stored secret with pyotp; nothing here
    is a placeholder.
    """
    try:
        if request.email.lower() != token_email.lower():
            logger.warning("TOTP verify email/token mismatch", requested=request.email, token=token_email)
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token does not match requested account")

        if not request.totp_code or len(request.totp_code) != 6 or not request.totp_code.isdigit():
            return TOTPVerificationResponse(verified=False, message="Invalid TOTP code format")

        if not TOTPService().verify_code(token_email, request.totp_code):
            logger.warning("TOTP verification failed", email=token_email)
            return TOTPVerificationResponse(verified=False, message="Incorrect verification code")

        auth_service = AuthService(settings)
        session_data = {
            "sub": token_email,
            "email": token_email,
            "permissions": ["admin", "view_logs", "manage_watchlist", "configure_apis", "manage_storage", "view_analytics"],
            "auth_method": "oauth2_google_totp",
        }
        tokens = await auth_service.create_admin_session(token_email, session_data)

        logger.info("TOTP verification successful, admin session granted", email=token_email)

        return TOTPVerificationResponse(
            verified=True,
            message="TOTP verification successful",
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_type="bearer",
            expires_in=1800,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("TOTP verification error", error=str(e), exc_info=True)
        return TOTPVerificationResponse(verified=False, message="TOTP verification failed")


@router.get("/auth/totp/setup")
async def setup_totp(
    token_email: Annotated[str, Depends(_get_pre_auth_email)],
    settings: Annotated[Settings, Depends(get_settings)]
):
    """
    Get (or create) the TOTP secret for the caller identified by their
    pre-auth token, and return QR code data for an authenticator app.

    Requires a valid pre-auth (or already-verified admin) bearer token —
    this can no longer be called anonymously for an arbitrary email.
    """
    try:
        totp_service = TOTPService()
        secret, created = totp_service.get_or_create_secret(token_email)
        issuer = settings.app_name or "InsightBull"
        otpauth_url = totp_service.provisioning_uri(token_email, secret, issuer=issuer)

        logger.info("TOTP setup", email=token_email, created=created)

        return {
            "secret": secret,
            "qrcode_url": otpauth_url,
            "manual_entry_key": secret,
            "issuer": issuer
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("TOTP setup error", error=str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to setup TOTP"
        )
