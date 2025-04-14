### livectf api

This server implements the livectf api that will be accessible to livectf services.

Testing auth token (real one will be provided later): `2d95dfe17e4a26a9c1ffb873aeac4796`

Two livectf challenges are configured: "live-1" and "live-2"

Testing tickets:
```
Team Team-1:
  live-1: ticket{SternAnchor6363n22:O0jwvnlc0wC3zC013wY09LGtGwFu-9Jl2Afg6U_Wo3rGt63F}
  live-2: ticket{WindlassBoat2572n22:Szah-5aTCry4tZ5bb4ExzdMRt5CxYJyJE7DMuG9FJmjEdV4W}
Team Team-2:
  live-1: ticket{KeelJib6482n22:iYuswV-6y_MC79cAed87i5gub2_XSxAIUlD459k_ctMpDke9}
  live-2: ticket{FreeboardPier1937n22:SB7UftFDICePxkiEOuOLxy1lJ6KAC5JNkgK4QRzrVYAnhOKE}
Team Team-3:
  live-1: ticket{CapstanJetstream5241n22:liRJB9h0JLur0omDmZSHh9LrhM3Bd77yNKv72I_BxtMmBhZk}
  live-2: ticket{JacklineSpinnaker2471n22:gwIp2fi6KM6YA9cSpsPCCTFk5nS3qGgGO5n0MY7QgCZ1njtu}
Team Team-4:
  live-1: ticket{KeelShip4980n22:k5E6jw7s_JRUqMzNzAgJq5EhRPlW5o2XIJwqDVF0ezRTqpkG}
  live-2: ticket{JetstreamForecastle2309n22:giygXos3IOfq1KTheQW_HYsn0oyUVfFsGpwQcBhkqhOzCywu}
```

## `GET /api/livectf/ticket`:

Query arguments:
- `auth`: livectf auth token
- `ticket`: ticket provided by user for the specific challenge

Sample Response:
```json
{
  "success": true,
  "slug": "JacklineSpinnaker2471n22",
  "team": {
    "display_name": "Team 3",
    "id": 4,
    "name": "Team 3",
    "name_punycode": "Team 3"
  },
  "challenge": {
    "name": "Livectf Chal 2",
    "shortname": "live-2"
  },
  "score": 500
}
```

`score` will be `null` if no score has been submitted yet.

As tickets are currently unique per challenge:
- You will want to check that the returned challenge shortname matches the challenge that is being processed.

On error it will respond with
```json
{
  "error": "some error message here"
}
```

## `PATCH /api/livectf/ticket/score`:

Body form / Body JSON
- `auth`: livectf auth token
- `ticket`: ticket provided by user for the specific challenge being scored
- `score`: Integer score value to assign to this ticket
- `shortname`: The shortname of the intended challenge for sanity checking

If using json, you need to have the `Content-Type: application/json` header

Sample Response:
```json
{
  "challenge": {
    "name": "Livectf Chal 2",
    "shortname": "live-2"
  },
  "score": 500,
  "solution_id": 3,
  "success": true
}
```

As tickets are currently unique per challenge:
- First you will want to first have validated that the supplied ticket matches the challenge you want to score (using `GET /api/livectf/ticket` or your ticket cache)
- Then pass the shortname to this endpoint as well so it can sanity check before assigning points.

On error it will respond with
```json
{
  "error": "some error message here"
}
