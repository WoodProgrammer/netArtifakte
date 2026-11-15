"""Admin-only management of users and teams."""
import json
import sqlite3

from fastapi import APIRouter, Depends, HTTPException

from . import auth, db
from .auth import User, require_admin
from .models import TeamCreate, TeamUpdate, UserCreate, UserUpdate

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_admin)])


def _user_out(u: dict) -> dict:
    return {"id": u["id"], "username": u["username"], "is_admin": bool(u["is_admin"]), "active": bool(u["active"]),
            "created_at": u["created_at"], "last_login_at": u["last_login_at"],
            "team_ids": sorted(json.loads(u["team_ids"] or "[]"))}


def _team_out(t: dict) -> dict:
    return {"id": t["id"], "name": t["name"], "created_at": t["created_at"],
            "member_ids": sorted(json.loads(t["member_ids"] or "[]")),
            "analysis_count": t["analysis_count"], "cost_usd": round(t["cost_usd"] or 0, 4)}


def _check_teams(team_ids: list[int]) -> None:
    for t in team_ids:
        if not db.get_team(t):
            raise HTTPException(422, f"team {t} does not exist")


def _check_users(user_ids: list[int]) -> None:
    for u in user_ids:
        if not db.get_user(u):
            raise HTTPException(422, f"user {u} does not exist")


def _find_user(user_id: int) -> dict:
    for u in db.list_users():
        if u["id"] == user_id:
            return u
    raise HTTPException(404, "user not found")


def _find_team(team_id: int) -> dict:
    for t in db.list_teams():
        if t["id"] == team_id:
            return t
    raise HTTPException(404, "team not found")


# ---------------------------------------------------------------- users
@router.get("/users")
def list_users():
    return [_user_out(u) for u in db.list_users()]


@router.post("/users", status_code=201)
def create_user(body: UserCreate):
    username = auth.validate_username(body.username)
    _check_teams(body.team_ids)
    try:
        user_id = db.create_user(username, auth.hash_password(auth.validate_password(body.password)), body.is_admin)
    except sqlite3.IntegrityError:
        raise HTTPException(409, "username already exists")
    db.set_user_teams(user_id, body.team_ids)
    return _user_out(_find_user(user_id))


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: UserUpdate, me: User = Depends(require_admin)):
    _find_user(user_id)
    fields = {}
    losing_admin = body.is_admin is False or body.active is False
    if losing_admin and db.get_user(user_id)["is_admin"] and db.count_active_admins(exclude_user_id=user_id) == 0:
        raise HTTPException(409, "can't remove or deactivate the last active admin")
    if body.active is False and user_id == me.id:
        raise HTTPException(409, "you can't deactivate yourself")
    if body.is_admin is not None:
        fields["is_admin"] = int(body.is_admin)
    if body.active is not None:
        fields["active"] = int(body.active)
    if body.password is not None:
        fields["password_hash"] = auth.hash_password(auth.validate_password(body.password))
    db.update_user(user_id, **fields)
    if body.team_ids is not None:
        _check_teams(body.team_ids)
        db.set_user_teams(user_id, body.team_ids)
    if body.password is not None or body.active is False:
        db.delete_user_sessions(user_id)  # force re-login
    return _user_out(_find_user(user_id))


# ---------------------------------------------------------------- teams
@router.get("/teams")
def list_teams():
    return [_team_out(t) for t in db.list_teams()]


@router.post("/teams", status_code=201)
def create_team(body: TeamCreate):
    _check_users(body.member_ids)
    try:
        team_id = db.create_team(body.name.strip())
    except sqlite3.IntegrityError:
        raise HTTPException(409, "a team with this name already exists")
    db.set_team_members(team_id, body.member_ids)
    return _team_out(_find_team(team_id))


@router.patch("/teams/{team_id}")
def update_team(team_id: int, body: TeamUpdate):
    _find_team(team_id)
    if body.name is not None:
        try:
            db.update_team(team_id, body.name.strip())
        except sqlite3.IntegrityError:
            raise HTTPException(409, "a team with this name already exists")
    if body.member_ids is not None:
        _check_users(body.member_ids)
        db.set_team_members(team_id, body.member_ids)
    return _team_out(_find_team(team_id))


@router.delete("/teams/{team_id}", status_code=204)
def delete_team(team_id: int):
    t = _find_team(team_id)
    if t["analysis_count"]:
        raise HTTPException(409, "team still has analyses; move or delete them first")
    db.delete_team(team_id)
