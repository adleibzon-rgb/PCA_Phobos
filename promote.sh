#!/bin/bash
# ============================================================
#  PCA Phobos — promote / sync каналов (maintainer-инструмент)
#
#  Каналы и репозитории:
#    stable -> публичный  adleibzon-rgb/PCA_Phobos        ветка main
#    beta   -> приватный  adleibzon-rgb/PCA_Phobos-dev    ветка beta
#    dev    -> приватный  adleibzon-rgb/PCA_Phobos-dev    ветка dev
#
#  Поток фич — строго в одну сторону:  dev -> beta -> stable
#  Хотфикс в stable -> forward-port в beta и dev (чтоб не потерялся).
#
#  Использование (GH_TOKEN в env):
#    GH_TOKEN=ghp_xxx ./promote.sh status
#    GH_TOKEN=ghp_xxx ./promote.sh dev2beta
#    GH_TOKEN=ghp_xxx ./promote.sh beta2stable 1.3.0
#    GH_TOKEN=ghp_xxx ./promote.sh forward          # main->beta->dev (после хотфикса)
#
#  Мёрж обычный (без -X). При конфликте — НЕ пушит, оставляет рабочую копию
#  в $WORK для ручного разбора. Версии (VERSION) выставляются по каналу.
# ============================================================
set -e
GH_TOKEN="${GH_TOKEN:-}"
[ -n "$GH_TOKEN" ] || { echo "Нужен GH_TOKEN (env)."; exit 1; }
PUB="https://adleibzon-rgb:${GH_TOKEN}@github.com/adleibzon-rgb/PCA_Phobos.git"
PRIV="https://adleibzon-rgb:${GH_TOKEN}@github.com/adleibzon-rgb/PCA_Phobos-dev.git"
WORK="${PCA_WORK:-/tmp/pca-promote-work}"

repo_for() { case "$1" in main) echo "$PUB";; beta|dev) echo "$PRIV";; esac; }

init_work() {
    rm -rf "$WORK"; mkdir -p "$WORK"
    git -C "$WORK" init -q
    git -C "$WORK" config user.email "maintainer@pca"
    git -C "$WORK" config user.name "PCA promote"
}

co_branch() {  # $1=branch -> checkout local copy of remote branch
    local br="$1" repo; repo=$(repo_for "$br")
    git -C "$WORK" fetch -q "$repo" "$br"
    git -C "$WORK" checkout -q -B "$br" FETCH_HEAD
}

ver_now() { tr -d ' \r\n' < "$WORK/VERSION" 2>/dev/null; }

do_merge() {  # $1=incoming-ref-msg label ; merges FETCH_HEAD into current branch
    if ! git -C "$WORK" merge --no-edit -m "$1" FETCH_HEAD; then
        echo ""
        echo "!!! КОНФЛИКТ. Не запушено. Разрули вручную:"
        echo "    cd $WORK && git status   # правь файлы, git add, git commit"
        echo "    затем git push <repo> <branch>"
        exit 1
    fi
}

case "${1:-status}" in

  status)
    init_work
    echo "== Версии каналов =="
    for br in main beta dev; do
        co_branch "$br" >/dev/null 2>&1 || { printf "  %-7s (нет)\n" "$br"; continue; }
        printf "  %-7s %s  (%s)\n" "$br" "$(ver_now)" "$(git -C "$WORK" rev-parse --short HEAD)"
    done
    echo "Поток: dev -> beta -> stable. После хотфикса в stable: ./promote.sh forward"
    ;;

  dev2beta)
    init_work
    echo "== Промоут dev -> beta =="
    co_branch beta
    git -C "$WORK" fetch -q "$PRIV" dev
    DEVVER=$(git -C "$WORK" show FETCH_HEAD:VERSION | tr -d ' \r\n')
    do_merge "promote: merge dev into beta"
    BETAVER="${DEVVER%-dev}-beta"
    echo "$BETAVER" > "$WORK/VERSION"
    git -C "$WORK" commit -q -am "promote: beta VERSION -> $BETAVER" || true
    git -C "$WORK" push -q "$PRIV" beta:beta
    git -C "$WORK" tag -f "v$BETAVER" >/dev/null; git -C "$WORK" push -fq "$PRIV" "v$BETAVER"
    echo "OK -> beta = $BETAVER (тег v$BETAVER)"
    ;;

  beta2stable)
    STABLEVER="${2:-}"
    [ -n "$STABLEVER" ] || { echo "Укажи версию: ./promote.sh beta2stable 1.3.0"; exit 1; }
    init_work
    echo "== Релиз beta -> stable (v$STABLEVER) =="
    co_branch main
    git -C "$WORK" fetch -q "$PRIV" beta
    do_merge "release: merge beta into stable v$STABLEVER"
    echo "$STABLEVER" > "$WORK/VERSION"
    git -C "$WORK" commit -q -am "release: stable VERSION -> $STABLEVER" || true
    git -C "$WORK" push -q "$PUB" main:main
    git -C "$WORK" tag -f "v$STABLEVER" >/dev/null; git -C "$WORK" push -fq "$PUB" "v$STABLEVER"
    echo "OK -> stable = $STABLEVER (тег v$STABLEVER). Дальше: ./promote.sh forward"
    ;;

  forward)
    init_work
    echo "== Forward-port stable -> beta -> dev =="
    # main -> beta
    co_branch beta
    BETAVER=$(ver_now)
    git -C "$WORK" fetch -q "$PUB" main
    do_merge "forward: merge stable into beta"
    echo "$BETAVER" > "$WORK/VERSION"; git -C "$WORK" commit -q -am "forward: keep beta VERSION $BETAVER" || true
    git -C "$WORK" push -q "$PRIV" beta:beta
    echo "  beta <- stable OK"
    # beta -> dev
    co_branch dev
    DEVVER=$(ver_now)
    git -C "$WORK" fetch -q "$PRIV" beta
    do_merge "forward: merge beta into dev"
    echo "$DEVVER" > "$WORK/VERSION"; git -C "$WORK" commit -q -am "forward: keep dev VERSION $DEVVER" || true
    git -C "$WORK" push -q "$PRIV" dev:dev
    echo "  dev <- beta OK. Forward-port завершён."
    ;;

  *)
    echo "promote.sh — продвижение каналов PCA Phobos"
    echo "  status                  версии всех каналов"
    echo "  dev2beta                dev -> beta (кандидат)"
    echo "  beta2stable <version>   beta -> stable (релиз + тег)"
    echo "  forward                 stable -> beta -> dev (после хотфикса)"
    ;;
esac
