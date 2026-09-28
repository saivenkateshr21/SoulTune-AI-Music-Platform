"""Shared API dependencies: authentication, CSRF, rate limiting, and helpers."""

from __future__ import annotations

import copy
import hmac
import time
from datetime import datetime, timezone

from fastapi import HTTPException, Request, Response

from ..config.settings import Settings
from ..core.security import new_token, token_hash


API = "/api/v1"
AUTH_ERROR = "Credentials are incorrect."


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def public_user(user: dict) -> dict:
    return {
        key: copy.deepcopy(user.get(key))
        for key in (
            "id",
            "name",
            "email",
            "is_guest",
            "preferences",
            "onboarding_completed",
        )
    }


def public_playlist(playlist: dict) -> dict:
    result = {
        key: value
        for key, value in playlist.items()
        if key not in {"owner_id", "_revision", "request_fingerprint"}
    }
    result["revision"] = playlist.get("_revision", 0)
    return result


def rate(
    request: Request,
    bucket: str,
    limit: int,
    window: int,
    identity: str | None = None,
):
    """Rate-limit a request. Raises HTTPException(429) if limit exceeded."""
    identity = identity or (
        request.client.host if request.client else "unknown"
    )

    key = f"{bucket}:{token_hash(identity)}"

    permitted, retry_after = request.app.state.store.rate_limit(
        key,
        limit,
        window,
    )

    if not permitted:
        raise HTTPException(
            429,
            "Too many requests. Please try again shortly.",
            headers={"Retry-After": str(retry_after)},
        )


def authenticated(request: Request) -> tuple[dict, dict]:
    """Validate the session cookie and CSRF token. Returns (user, session)."""
    config: Settings = request.app.state.settings

    token = request.cookies.get(config.cookie_name)

    if not token or len(token) > 200:
        raise HTTPException(
            401,
            "Please sign in to continue.",
        )

    session = request.app.state.store.get(
        "session",
        token_hash(token),
    )

    if not session:
        raise HTTPException(
            401,
            "Your session has expired. Please sign in again.",
        )

    user = request.app.state.store.get(
        "user",
        session["user_id"],
    )

    if not user:
        raise HTTPException(
            401,
            "Please sign in to continue.",
        )

    if session.get("auth_version", 0) != user.get("auth_version", 0):
        raise HTTPException(
            401,
            "Your session has expired. Please sign in again.",
        )

    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        submitted = request.headers.get("x-csrf-token", "")

        if not hmac.compare_digest(
            submitted.encode("utf-8"),
            session["csrf_token"].encode("utf-8"),
        ):
            raise HTTPException(
                403,
                "Your security token is missing or expired. Refresh and try again.",
            )

        rate(
            request,
            "mutation",
            120,
            60,
            user["id"],
        )

    return user, session


def issue_session(
    request: Request,
    response: Response,
    user: dict,
) -> dict:
    """Create a new session, rotate old tokens, and set the cookie."""
    config: Settings = request.app.state.settings
    store = request.app.state.store

    old_token = request.cookies.get(config.cookie_name)

    if old_token and len(old_token) <= 200:
        old_session = store.get(
            "session",
            token_hash(old_token),
        )

        if old_session:
            old_user = store.get(
                "user",
                old_session["user_id"],
            )

            if (
                old_user
                and old_user["is_guest"]
                and old_user["id"] != user["id"]
            ):
                store.delete_user(old_user["id"])

        store.delete(
            "session",
            token_hash(old_token),
        )

    token, csrf = new_token(), new_token()

    max_age = (
        config.guest_session_hours
        if user["is_guest"]
        else config.session_hours
    ) * 3600

    session = {
        "id": token_hash(token),
        "user_id": user["id"],
        "csrf_token": csrf,
        "auth_version": user.get("auth_version", 0),
        "created_at": utcnow(),
        "expires_at": time.time() + max_age,
    }

    store.put(
        "session",
        session["id"],
        session,
        owner=user["id"],
        expires_at=session["expires_at"],
    )

    response.set_cookie(
        config.cookie_name,
        token,
        max_age=max_age,
        httponly=True,
        secure=config.cookie_secure,
        samesite="none" if config.cookie_samesite.lower() == "none" else "lax",
        path="/",
    )

    return {
        "user": public_user(user),
        "csrf_token": csrf,
    }


def check_revision(
    playlist: dict,
    revision: int | None,
):
    if (
        revision is not None
        and revision != playlist.get("_revision", 0)
    ):
        raise HTTPException(
            409,
            "This playlist changed in another request. "
            "Review the latest version and try again.",
        )


def owned_playlist(
    request: Request,
    playlist_id: str,
    user: dict,
) -> dict:
    if len(playlist_id) > 100:
        raise HTTPException(
            404,
            "Playlist not found.",
        )

    playlist = request.app.state.store.get(
        "playlist",
        playlist_id,
    )

    if not playlist or playlist.get("owner_id") != user["id"]:
        raise HTTPException(
            404,
            "Playlist not found.",
        )

    return playlist


def save_playlist(
    request: Request,
    playlist: dict,
) -> dict:
    playlist["updated_at"] = utcnow()

    previous_revision = playlist.get(
        "_revision",
        0,
    )

    playlist["_revision"] = previous_revision + 1

    if not request.app.state.store.save_playlist(
        playlist,
        previous_revision,
    ):
        raise HTTPException(
            409,
            "This playlist changed while your request was running. "
            "Refresh and try again.",
        )

    return public_playlist(playlist)