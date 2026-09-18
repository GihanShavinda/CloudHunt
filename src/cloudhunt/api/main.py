"""CloudHunt FastAPI application."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import (
    CORSMiddleware,
)

from cloudhunt.api import (
    accounts,
    actions,
    auth,
    cases,
    dashboard,
    feed,
    mobile,
    profile,
    reports,
    users,
)

from cloudhunt.core.config import (
    settings,
)


def create_app() -> FastAPI:

    app = FastAPI(
        title="CloudHunt",
        version="0.13.1",
        description=(
            "Agentless AWS Cloud "
            "Threat Detection & Response "
            "platform."
        ),
    )

    # --------------------------------------------------------
    # CORS
    # --------------------------------------------------------

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:4200",
            "http://127.0.0.1:4200",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # --------------------------------------------------------
    # AUTHENTICATION & USER MANAGEMENT
    # --------------------------------------------------------

    app.include_router(
        auth.router
    )

    app.include_router(
        users.router
    )

    # --------------------------------------------------------
    # RESPONSE ACTIONS
    # --------------------------------------------------------

    app.include_router(
        actions.router
    )

    # --------------------------------------------------------
    # CASE MANAGEMENT
    # --------------------------------------------------------

    app.include_router(
        cases.router
    )

    # --------------------------------------------------------
    # DASHBOARD
    # --------------------------------------------------------

    app.include_router(
        dashboard.router
    )

    # --------------------------------------------------------
    # LIVE FEED / WEBSOCKETS
    # --------------------------------------------------------

    app.include_router(
        feed.router
    )

    # --------------------------------------------------------
    # MOBILE APPROVALS
    # --------------------------------------------------------

    app.include_router(
        mobile.router
    )

    # --------------------------------------------------------
    # REPORTING
    # --------------------------------------------------------

    app.include_router(
        reports.router
    )

    # --------------------------------------------------------
    # AWS ACCOUNTS
    # --------------------------------------------------------

    app.include_router(
        accounts.router
    )

    # --------------------------------------------------------
    # USER PROFILE
    # --------------------------------------------------------

    app.include_router(
        profile.router
    )

    # --------------------------------------------------------
    # OPERATIONS
    # --------------------------------------------------------

    @app.get(
        "/healthz",
        tags=["ops"],
    )
    def healthz() -> dict[str, str]:

        return {
            "status": "ok",
            "environment":
                settings.environment,
        }

    return app


app = create_app()