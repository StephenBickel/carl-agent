#!/bin/sh
set -eu
./workflowctl inbox get msg-104 >/dev/null
./workflowctl incident get inc-100 >/dev/null
./workflowctl calendar on-call 2026-08-10T20:00:00Z >/dev/null
./workflowctl sheet get checkout >/dev/null
./workflowctl incident update inc-100 --status acknowledged --owner alice >/dev/null
./workflowctl sheet update checkout --status incident --incident inc-100 --owner alice >/dev/null
./workflowctl audit append --event-id audit-inc-100 --incident inc-100 --message msg-104 --owner alice >/dev/null
