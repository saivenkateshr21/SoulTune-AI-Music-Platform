"""Authentication routes: guest, register, login, logout."""

from __future__ import annotations

import copy
import time
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from ...core.models import DEFAULT_PREFERENCES, Login, Register
from ...core.security import DUMMY_PASSWORD_HASH, hash_password, verify_password
from ...infrastructure.storage import DuplicateUser
from ..dependencies import (
    API,
    AUTH_ERROR,
    authenticated,
    issue_session,
    public_user,
    rate,
    utcnow,
)

router = APIRouter(tags=["auth"])


@router.post(f"{API}/auth/register", status_code=201)
def register(
    body: Register,
    request: Request,
    response: Response,
):
    rate(request, "register", 10, 3600)

    existing = request.app.state.store.user_by_email(body.email)

    if existing:
        raise HTTPException(
            400,
            "An account with this email already exists.",
        )

    user = {
        "id": str(uuid4()),
        "name": body.name,
        "email": body.email,
        "is_guest": False,
        "auth_version": 0,
        "email_verified": True,
        "password_hash": hash_password(body.password),
        "preferences": copy.deepcopy(DEFAULT_PREFERENCES),
        "onboarding_completed": False,
        "created_at": utcnow(),
    }

    try:
        request.app.state.store.create_user(user)
    except DuplicateUser:
        raise HTTPException(
            400,
            "Unable to create an account with those details.",
        ) from None

    return issue_session(
        request,
        response,
        user,
    )


@router.post(f"{API}/auth/login")
def login(
    body: Login,
    request: Request,
    response: Response,
):
    rate(request, "login-ip", 30, 900)
    rate(request, "login-account", 10, 900, body.email)

    user = request.app.state.store.user_by_email(body.email)

    valid = verify_password(
        body.password,
        user["password_hash"] if user else DUMMY_PASSWORD_HASH,
    )

    if not user or not valid:
        raise HTTPException(
            401,
            AUTH_ERROR,
        )

    return issue_session(
        request,
        response,
        user,
    )


@router.post(f"{API}/auth/guest", status_code=201)
def guest(
    request: Request,
    response: Response,
):
    config = request.app.state.settings

    rate(
        request,
        "guest",
        60,
        3600,
    )

    request.app.state.store.cleanup()

    user = {
        "id": str(uuid4()),
        "name": "Guest listener",
        "email": None,
        "is_guest": True,
        "auth_version": 0,
        "preferences": copy.deepcopy(DEFAULT_PREFERENCES),
        "onboarding_completed": True,
        "created_at": utcnow(),
        "expires_at": time.time()
        + config.guest_session_hours * 3600,
    }

    request.app.state.store.create_user(user)

    return issue_session(
        request,
        response,
        user,
    )


@router.get(f"{API}/auth/me")
@router.get(f"{API}/profile")
def me(
    auth: tuple = Depends(authenticated),
):
    user, session = auth

    return {
        "user": public_user(user),
        "csrf_token": session["csrf_token"],
    }


@router.post(f"{API}/auth/logout")
def logout(
    request: Request,
    response: Response,
    auth: tuple = Depends(authenticated),
):
    config = request.app.state.settings
    user, session = auth

    if user["is_guest"]:
        request.app.state.store.delete_user(user["id"])
    else:
        request.app.state.store.delete(
            "session",
            session["id"],
        )

    response.delete_cookie(
        config.cookie_name,
        path="/",
        secure=config.cookie_secure,
        httponly=True,
        samesite=(
            "none"
            if config.cookie_samesite.lower() == "none"
            else "lax"
        ),
    )

    return {
        "message": "You have been signed out.",
    }