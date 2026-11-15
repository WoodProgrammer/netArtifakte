"""Login / logout / current user / own password."""
from fastapi import APIRouter, Depends, HTTPException, Request, Response

from . import auth, db
from .auth import User, current_user
from .models import LoginRequest, PasswordChange

router = APIRouter(prefix="/auth", tags=["auth"])


def me_out(user: User) -> dict:
    return {"id": user.id, "username": user.username, "is_admin": user.is_admin,
            "teams": [{"id": t["id"], "name": t["name"]} for t in db.list_teams(user.visible_team_ids)],
            "member_team_ids": user.team_ids}


@router.post("/login")
def login(body: LoginRequest, request: Request, response: Response):
    user = auth.authenticate(body.username, body.password, request)
    auth.start_session(response, user["id"])
    return me_out(auth._to_user(user))


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response):
    auth.end_session(request, response)


@router.get("/me")
def me(user: User = Depends(current_user)):
    return me_out(user)


@router.post("/password", status_code=204)
def change_password(body: PasswordChange, request: Request, response: Response,
                    user: User = Depends(current_user)):
    row = db.get_user(user.id)
    if not auth.verify_password(body.current_password, row["password_hash"]):
        raise HTTPException(403, "current password is wrong")
    db.update_user(user.id, password_hash=auth.hash_password(auth.validate_password(body.new_password)))
    # log out other sessions; keep this browser logged in with a fresh session
    db.delete_user_sessions(user.id)
    auth.start_session(response, user.id)
