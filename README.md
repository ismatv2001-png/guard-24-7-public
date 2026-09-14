# guard-24-7-public — latido 24/7 en la nube (0 EUR)

Repo público (minutos de Actions 0) del lane `ismatv1512-web-3081` (orden del propietario
13-sep-2026: operación 24/7 + no-pisarse en local Y en la nube).

- `guard24_7/cli.py cloud-heartbeat`: latido determinista (python, uptime, disco, integridad de
  la cadena) — sin secretos, sin red, sin llamadas de pago.
- `.github/workflows/heartbeat.yml`: cron cada 10 min + `workflow_dispatch`; añade cada latido a
  la cadena de hashes y publica SOLO `state/heartbeat.jsonl` en la rama `heartbeat`.

Verificación (cualquier chat):
```
git fetch origin heartbeat
git show origin/heartbeat:state/heartbeat.jsonl > hb.jsonl
python guard24_7/cli.py verify-heartbeat --state-dir .   # hb.jsonl en ./heartbeat.jsonl
```

El registro autoritativo de claims sigue siendo el único local (`work-claim-v2`); este repo no
despacha, no crea políticas ni sustituye al coordinador exclusivo 01a06515.
