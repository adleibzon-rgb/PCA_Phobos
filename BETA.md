# Каналы PCA Phobos

С версии **1.4.0** все три канала (stable / beta / dev) — одна и та же версия.
Новые фичи по-прежнему сначала выкатываются в `dev`, затем в `beta`, затем в `main`
(`promote.sh`), но база одна — без расхождений.

```bash
phobos-update              # stable (открытый)
GH_TOKEN=… phobos-update beta|dev   # для подписчиков Boosty
```
