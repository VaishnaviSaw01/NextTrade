"""
Authentication Service for Admin Management

This service integrates with the existing frontend TOTP authentication system
and provides backend validation for admin sessions.

Features:
- JWT token validation from frontend
- Admin session management
- Integration with existing OAuth2 + TOTP flow
- Activity logging for admin actions

Following FYP security requirements for admin authentication.
"""

from typing import Optional, Dict, Any
from datetime import datetime
from app.utils.timezone import utc_now

from .jwt_handler import JWTHandler
from .security_utils import SecurityUtils
from app.infrastructure.config.settings import Settings

# Use centralized logging system
from app.infrastructure.log_system import get_logger
logger = get_logger()


class AdminUser:
    """Admin user model for authentication"""
    
    def __init__(self, user_id: str, email: str, is_active: bool = True):
        self.user_id = user_id
        self.email = email
        self.is_active = is_active
        self.last_login: Optional[datetime] = None
        self.permissions = ["admin"]  # Admin has all permissions


class AuthService:
    """
    Authentication service for admin management
    
    Integrates with existing frontend authentication system:
    - Validates JWT tokens from frontend OAuth2 + TOTP flow
    - Manages admin sessions
    - Provides authorization checks
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.jwt_handler = JWTHandler(settings)
        self.security_utils = SecurityUtils()

    async def validate_admin_token(self, token: str) -> Optional[AdminUser]:
        """
        Validate JWT token from frontend authentication

        This method validates tokens created by the existing frontend
        OAuth2 + TOTP authentication system.

        Requires a full "access" token that was minted only after TOTP
        verification succeeded — a pre-auth token (issued right after
        Google OAuth, before TOTP) always fails this check, even though
        it's signed with the same secret and carries the right email.

        Args:
            token: JWT token from frontend

        Returns:
            AdminUser if token is valid, None otherwise
        """
        try:
            # Remove 'Bearer ' prefix if present
            if token.startswith('Bearer '):
                token = token[7:]

            # Verify token signature and expiration
            payload = self.jwt_handler.verify_token(token)
            if not payload:
                logger.warning("Invalid JWT token provided")
                return None

            if payload.get("type") != "access":
                logger.warning(f"Rejected non-access token of type '{payload.get('type')}' for admin route")
                return None

            # Extract user information from token
            user_email = payload.get("sub") or payload.get("email")
            user_id = payload.get("user_id") or payload.get("sub")

            if not user_email or not user_id:
                logger.warning("Missing user information in token")
                return None

            # Validate admin permissions AND that TOTP was actually
            # completed for this session — permissions alone are not
            # enough, since a pre-auth token could otherwise be forged
            # into carrying them.
            permissions = payload.get("permissions", [])
            if "admin" not in permissions or not payload.get("totp_verified"):
                logger.warning(f"User {user_email} does not have a fully-verified admin session")
                return None

            # Create or update admin user
            admin_user = AdminUser(user_id, user_email)
            admin_user.last_login = utc_now()
            
            # Debug-level log to reduce noise (auth happens on every request)
            logger.debug(f"Admin user {user_email} authenticated")
            return admin_user
            
        except Exception as e:
            logger.error(f"Error validating admin token: {str(e)}")
            return None
    
    async def get_admin_from_token(self, token: str) -> Optional[AdminUser]:
        """
        Get admin user from valid token
        
        Args:
            token: JWT token string
            
        Returns:
            AdminUser if token is valid, None otherwise
        """
        return await self.validate_admin_token(token)
    
    async def verify_admin_permissions(self, admin_user: AdminUser, required_permission: str = "admin") -> bool:
        """
        Verify admin has required permissions
        
        Args:
            admin_user: Admin user object
            required_permission: Permission to check
            
        Returns:
            True if admin has permission, False otherwise
        """
        if not admin_user or not admin_user.is_active:
            return False
        
        return required_permission in admin_user.permissions
    
    async def refresh_admin_token(self, refresh_token: str) -> Optional[Dict[str, str]]:
        """
        Refresh admin access token
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            Dictionary with new tokens or None if refresh failed
        """
        try:
            # Verify refresh token
            payload = self.jwt_handler.verify_token(refresh_token)
            if not payload or payload.get("type") != "refresh":
                return None
            
            user_email = payload.get("sub") or payload.get("email")
            user_id = payload.get("user_id") or payload.get("sub")

            if not user_email or not user_id:
                return None

            # Create new tokens — carries forward the same fully-verified
            # state as the token being refreshed (refresh tokens are only
            # ever issued alongside a totp_verified access token, so this
            # is safe: see create_admin_session)
            token_data = {
                "sub": user_email,
                "user_id": user_id,
                "email": user_email,
                "permissions": ["admin"],
                "totp_verified": True
            }
            
            new_access_token = self.jwt_handler.create_access_token(token_data)
            new_refresh_token = self.jwt_handler.create_refresh_token(token_data)
            
            return {
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
                "token_type": "bearer"
            }
            
        except Exception as e:
            logger.error(f"Error refreshing admin token: {str(e)}")
            return None
    
    async def create_admin_session(self, user_email: str, additional_data: Dict[str, Any] = None) -> Dict[str, str]:
        """
        Create a fully-verified admin session.

        Only call this AFTER TOTP verification has actually succeeded —
        it's the one place that stamps a token as `totp_verified`, which
        is what `validate_admin_token` requires for every protected route.

        Args:
            user_email: Admin email
            additional_data: Additional token data

        Returns:
            Dictionary with access and refresh tokens
        """
        token_data = {
            "sub": user_email,
            "email": user_email,
            "permissions": ["admin"],
            "user_id": f"admin_{hash(user_email) % 10000}"
        }

        if additional_data:
            token_data.update(additional_data)

        # totp_verified is set last and unconditionally — additional_data
        # is caller-supplied and must never be able to unset it.
        token_data["totp_verified"] = True

        access_token = self.jwt_handler.create_access_token(token_data)
        refresh_token = self.jwt_handler.create_refresh_token(token_data)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
    
    async def validate_admin_session(self, token: str) -> bool:
        """
        Validate if admin session is still active
        
        Args:
            token: JWT access token
            
        Returns:
            True if session is valid, False otherwise
        """
        admin_user = await self.validate_admin_token(token)
        return admin_user is not None
    
    async def log_admin_activity(self, admin_user: AdminUser, action: str, details: Dict[str, Any] = None):
        """
        Log admin activity for audit trail
        
        Args:
            admin_user: Admin user performing action
            action: Action description
            details: Additional action details
        """
        log_entry = {
            "timestamp": utc_now().isoformat(),
            "admin_id": admin_user.user_id,
            "admin_email": admin_user.email,
            "action": action,
            "details": details or {}
        }
        
        # In production, this would write to database
        logger.info(f"Admin Activity: {log_entry}")
    
    def get_admin_permissions(self) -> list:
        """Get list of available admin permissions"""
        return [
            "admin",
            "view_logs",
            "manage_watchlist", 
            "configure_apis",
            "manage_storage",
            "view_analytics"
        ]