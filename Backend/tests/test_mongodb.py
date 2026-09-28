"""Opt-in integration test using a uniquely named, disposable Mongo database."""

import os
import time
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.storage import MongoStore


@pytest.mark.skipif(
    os.getenv("RUN_MONGODB_TESTS") != "1",
    reason="Live MongoDB tests are opt-in",
)
def test_live_mongodb_atomicity_and_collection_persistence(
    monkeypatch,
    tmp_path,
):
    name = "ctest_" + uuid4().hex

    settings = Settings(
        mongodb_database=name,
    )

    if not settings.mongodb_uri:
        pytest.skip("No MongoDB connection configured")

    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("LASTFM_API_KEY", "")
    monkeypatch.setenv(
        "LOCAL_MUSIC_DIR",
        str(tmp_path / "empty"),
    )

    store = MongoStore(
        settings.mongodb_uri,
        name,
    )

    collection = None

    try:
        # ---------------------------------------------------------
        # Test atomic OTP consumption at the storage level.
        # OTP is no longer used by authentication, but the storage
        # method may still exist in the MongoDB implementation.
        # ---------------------------------------------------------

        challenge = {
            "binding": "browser",
            "code_hash": "hash",
            "attempts": 0,
            "consumed": False,
        }

        store.put(
            "otp",
            "atomic-test",
            challenge,
            owner="atomic-test",
            expires_at=time.time() + 60,
        )

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(
                pool.map(
                    lambda _: store.consume_otp(
                        "atomic-test",
                        "browser",
                        "hash",
                    ),
                    range(8),
                )
            )

        assert sum(
            result is not None
            for result in results
        ) == 1

        # ---------------------------------------------------------
        # Test registration without OTP.
        # ---------------------------------------------------------

        with TestClient(create_app(settings)) as client:

            response = client.post(
                "/api/v1/auth/register",
                json={
                    "name": "Integration test",
                    "email": "integration@example.test",
                    "password": "Disposable-test-password-42",
                },
            )

            assert response.status_code == 201

            registration_data = response.json()

            # Registration should immediately create a session.
            assert "user" in registration_data
            assert "csrf_token" in registration_data

            assert (
                registration_data["user"]["email"]
                == "integration@example.test"
            )

            # The user should already be authenticated.
            me_response = client.get(
                "/api/v1/auth/me"
            )

            assert me_response.status_code == 200

            me_data = me_response.json()

            assert (
                me_data["user"]["email"]
                == "integration@example.test"
            )

            # Use the CSRF token returned during registration.
            client.headers["X-CSRF-Token"] = registration_data[
                "csrf_token"
            ]

            # -----------------------------------------------------
            # Playlists
            # -----------------------------------------------------

            playlists_response = client.get(
                "/api/v1/playlists"
            )

            assert playlists_response.status_code == 200
            assert playlists_response.json() == {
                "playlists": []
            }

            # -----------------------------------------------------
            # Generate queue
            # -----------------------------------------------------

            queue_response = client.post(
                "/api/v1/queue/generate",
                json={
                    "description": "Happy road trip"
                },
            )

            assert queue_response.status_code == 200

            queue = queue_response.json()

            # -----------------------------------------------------
            # Create playlist / collection
            # -----------------------------------------------------

            collection_response = client.post(
                "/api/v1/playlists",
                json={
                    "name": "Test collection"
                },
            )

            assert collection_response.status_code == 200

            collection = collection_response.json()

            # -----------------------------------------------------
            # Add track to playlist
            # -----------------------------------------------------

            result = client.post(
                "/api/v1/playlists/"
                + collection["id"]
                + "/tracks",
                json={
                    "source_id": queue["id"],
                    "track_id": queue["tracks"][0]["id"],
                    "revision": collection["revision"],
                },
            )

            assert result.status_code == 200

            result_data = result.json()

            assert len(
                result_data["tracks"]
            ) == 1

            # -----------------------------------------------------
            # Test stale revision protection
            # -----------------------------------------------------

            stale_response = client.patch(
                "/api/v1/playlists/"
                + collection["id"],
                json={
                    "name": "Stale",
                    "revision": collection["revision"],
                },
            )

            assert stale_response.status_code == 409

            # -----------------------------------------------------
            # Verify collection exists
            # -----------------------------------------------------

            playlists_response = client.get(
                "/api/v1/playlists"
            )

            assert playlists_response.status_code == 200

            assert len(
                playlists_response.json()["playlists"]
            ) == 1

        # ---------------------------------------------------------
        # Verify data survives a new connection.
        # ---------------------------------------------------------

        saved_playlist = store.get(
            "playlist",
            collection["id"],
        )

        assert saved_playlist is not None

        assert len(
            saved_playlist["tracks"]
        ) == 1

    finally:
        assert name.startswith("ctest_")
        assert len(name) == len("ctest_") + 32

        assert name != Settings().mongodb_database

        store.client.drop_database(name)
        store.close()