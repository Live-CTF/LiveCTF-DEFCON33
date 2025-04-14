#!/usr/bin/env python3

import re
import subprocess
import os

from functools import wraps
from flask import Flask, request, jsonify, abort

ALLOW_UPDATE_SCORE = True

sol_id = 0

app = Flask(__name__)
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = False

AUTH_TOKEN = "2d95dfe17e4a26a9c1ffb873aeac4796"

chals = {
    "live-1": dict(
        name="Livectf Chal 1",
        shortname="live-1",
        secret="R4rFpz1SQUhStxAvSsNp-9SUKclL11PhYclkEUMV8so=",
        type="livectf",
        locked=False,
    ),
    "live-2": dict(
        name="Livectf Chal 2",
        shortname="live-2",
        secret="uqzCudGfXvxGI9dynozeG-XIWDZQlQnya63ZiWjnLro=",
        type="livectf",
        locked=False,
    ),
}

teams = {
    "Team-1": dict(
        id=2,
        name="Team 1",
        display_name="Team 1",
        name_punycode="Team 1",
        tickets={
            "live-1": "ticket{SternAnchor6363n22:O0jwvnlc0wC3zC013wY09LGtGwFu-9Jl2Afg6U_Wo3rGt63F}",
            "live-2": "ticket{WindlassBoat2572n22:Szah-5aTCry4tZ5bb4ExzdMRt5CxYJyJE7DMuG9FJmjEdV4W}",
        },
        scores={},
    ),
    "Team-2": dict(
        id=3,
        name="Team 2",
        display_name="Team 2",
        name_punycode="Team 2",
        tickets={
            "live-1": "ticket{KeelJib6482n22:iYuswV-6y_MC79cAed87i5gub2_XSxAIUlD459k_ctMpDke9}",
            "live-2": "ticket{FreeboardPier1937n22:SB7UftFDICePxkiEOuOLxy1lJ6KAC5JNkgK4QRzrVYAnhOKE}",
        },
        scores={},
    ),
    "Team-3": dict(
        id=4,
        name="Team 3",
        display_name="Team 3",
        name_punycode="Team 3",
        tickets={
            "live-1": "ticket{CapstanJetstream5241n22:liRJB9h0JLur0omDmZSHh9LrhM3Bd77yNKv72I_BxtMmBhZk}",
            "live-2": "ticket{JacklineSpinnaker2471n22:gwIp2fi6KM6YA9cSpsPCCTFk5nS3qGgGO5n0MY7QgCZ1njtu}",
        },
        scores={},
    ),
    "Team-4": dict(
        id=5,
        name="Team 4",
        display_name="Team 4",
        name_punycode="Team 4",
        tickets={
            "live-1": "ticket{KeelShip4980n22:k5E6jw7s_JRUqMzNzAgJq5EhRPlW5o2XIJwqDVF0ezRTqpkG}",
            "live-2": "ticket{JetstreamForecastle2309n22:giygXos3IOfq1KTheQW_HYsn0oyUVfFsGpwQcBhkqhOzCywu}",
        },
        scores={},
    ),
}

for tn, te in teams.items():
    print(f"Team {tn}:")
    for c, t in te["tickets"].items():
        print(f"  {c}: {t}")


def get_param(name, default=None):
    if name in request.args:
        return request.args[name]
    if name in request.form:
        return request.form[name]
    if request.json is not None and name in request.json:
        return request.json[name]
    return default


def auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = get_param("auth")

        if token != AUTH_TOKEN:
            abort(404)
        return f(*args, **kwargs)

    return decorated_function


import subprocess


def validate_ticket(t):
    if t is None:
        return None, None
    ticket = None
    slug = None
    for cn, c in chals.items():
        print(f"./validate-ticket -s '{c['secret']}' -t '{t}'")
        try:
            out = (
                subprocess.check_output(
                    ["./validate-ticket", "-p", "-n", "-s", c["secret"], "-t", t]
                )
                .strip()
                .decode("latin-1")
                .strip()
            )
            if len(out) == 0:
                continue
            print("got", repr(out))
            slug = (
                subprocess.check_output(
                    ["./validate-ticket", "-n", "-s", c["secret"], "-t", t]
                )
                .strip()
                .decode("latin-1")
                .strip()
            )
            ticket = out
            break
        except subprocess.CalledProcessError as e:
            print("validation failed")
            continue
    if ticket is None:
        return None, None
    return ticket, slug


def do_validate_ticket(raw_ticket):
    raw_slug_match = re.search("(?<=ticket{).*(?=:)", raw_ticket)
    if not raw_slug_match:
        print(f"Invalid ticket format: `{raw_ticket}`")
        return jsonify(error="invalid ticket")
    raw_slug = raw_slug_match.group(0)
    print(raw_ticket, raw_slug)

    team = None
    chal = None
    for tn, te in teams.items():
        for c, t in te["tickets"].items():
            if raw_slug in t:
                team = te
                chal = chals[c]
                break

    if team is None:
        print(f"No team found for ticket slug `{raw_slug}`")
        return jsonify(error="invalid ticket")

    ticket, slug = validate_ticket(raw_ticket)
    if ticket is None:
        print("No challenge found that could validate the ticket")
        return jsonify(error="invalid ticket, bad sig")

    team = None
    for tn, te in teams.items():
        for c, t in te["tickets"].items():
            # print(repr(t), repr(ticket))
            if t == ticket:
                team = te
                break

    if team is None:
        print("No matching team found for ticket")
        return jsonify(error="invalid ticket")

    if not raw_slug == slug:
        print(f"Ticket slug does not match challenge {repr(raw_slug)} vs {repr(slug)}")
        return jsonify(error="invalid ticket, slug mismatch")

    return [ticket, slug, team, chal]


@app.route("/api/livectf/ticket", methods=["GET"])
@auth
def get_info_with_ticket():
    raw_ticket = request.args.get("ticket")

    r = do_validate_ticket(raw_ticket)
    if type(r) is not list:
        return r

    ticket, slug, team, chal = r
    if chal["type"] != "livectf":
        return jsonify(error="not a livectf challenge")

    cur_score = team["scores"].get(chal["shortname"], None)

    return jsonify(
        success=True,
        slug=slug,
        team=dict(
            id=team["id"],
            name=team["name"],
            display_name=team["display_name"],
            name_punycode=team["name_punycode"],
        ),
        challenge=dict(
            name=chal["name"],
            shortname=chal["shortname"],
        ),
        score=cur_score["value"] if cur_score else None,
    )


@app.route("/api/livectf/ticket/score", methods=["PATCH"])
@auth
def update_score():
    raw_ticket = get_param("ticket")

    r = do_validate_ticket(raw_ticket)
    if type(r) is not list:
        return r

    ticket, slug, team, chal = r

    short_name_valid = get_param("shortname")
    if short_name_valid is not None and short_name_valid != chal["shortname"]:
        return jsonify(error=f"ticket is not for target challenge")

    if chal["type"] != "livectf":
        return jsonify(error="not a livectf challenge")

    if chal["locked"]:
        return jsonify(error="not a livectf challenge, contact nautilus")

    cur_score = team["scores"].get(chal["shortname"], None)
    if cur_score is not None and not ALLOW_UPDATE_SCORE:
        return jsonify(
            error="livectf challenge already solved, not allowed to update score... contact nautilus"
        )

    try:
        score_val = int(get_param("score"))
    except:
        print("Score is not an int")
        score_val = 0

    if score_val < 0 or score_val > 5000:
        return jsonify(error="score out of range")

    global sol_id
    if cur_score is None:
        sol_id += 1
        team["scores"][chal["shortname"]] = dict(id=sol_id, value=score_val)
    else:
        cur_score["value"] = score_val

    return jsonify(
        success=True,
        score=score_val,
        solution_id=sol_id,
        challenge=dict(
            name=chal["name"],
            shortname=chal["shortname"],
        ),
    )


app.run(host="0.0.0.0", debug=True, port=5000)
