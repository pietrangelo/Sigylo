#!/usr/bin/env bash
#
# cc: keep a repository's Claude Code configuration encrypted on GitHub and
# decrypt it automatically when a Claude Code session starts.
#
# Copyright (C) 2026 Pietrangelo Masala
# Licensed under the GNU Affero General Public License v3 or later.
#
# The files are encrypted with sec (https://github.com/pietrangelo/sec) through
# a git clean/smudge filter. `cc init` copies this script into the target
# repository as .claude/cc/cc, where it serves as the SessionStart hook, the
# pre-commit check and the CI check.

set -euo pipefail

CC_SCRIPT_VERSION=0.1.0
MAGIC_HEX=53454302 # "SEC\x02", the sec v2 header
STUB_MARKER="<!-- cc:stub -->"
CONTEXT_LIMIT=9000 # SessionStart context is capped at 10,000 characters

die() {
	echo "cc: $*" >&2
	exit 1
}
info() { echo "cc: $*" >&2; }

usage() {
	cat >&2 <<'EOF'
usage: cc <command> [repo]

  init [repo]          protect a repository: key, .gitattributes, hook, checks
  unlock [repo]        configure the git filter and decrypt the working tree
  lock [repo]          remove the git filter and put ciphertext back on disk
  status [repo]        list protected files and whether they are encrypted
  check [repo]         fail if a staged file that must be encrypted is not
  scan-history [repo]  list every past commit that stored such a file in clear
  session-start        SessionStart hook: unlock and hand Claude the config

The key is read from SEC_TOOL_KEY or from ~/.config/cc/keys/<key id>.key.
EOF
	exit 2
}

repo_root() {
	git -C "${1:-.}" rev-parse --show-toplevel 2>/dev/null || die "not a git repository: ${1:-.}"
}

# Reads .claude/cc/config as data (KEY=value lines), never as shell code.
load_config() {
	local root=$1 line
	CC_KEY_ID=$(basename "$root")
	SEC_VERSION=v2.0.0
	if [ -f "$root/.claude/cc/config" ]; then
		while IFS= read -r line || [ -n "$line" ]; do
			case $line in
			CC_KEY_ID=*) CC_KEY_ID=${line#CC_KEY_ID=} ;;
			SEC_VERSION=*) SEC_VERSION=${line#SEC_VERSION=} ;;
			esac
		done <"$root/.claude/cc/config"
	fi
	case $CC_KEY_ID in *[!A-Za-z0-9._-]* | "") die "invalid CC_KEY_ID in .claude/cc/config" ;; esac
	KEY_DIR=${CC_KEY_DIR:-$HOME/.config/cc/keys}
	KEY_FILE=$KEY_DIR/$CC_KEY_ID.key
}

# Uses SEC_TOOL_KEY when set (cloud sessions), otherwise the local key file.
ensure_key() {
	if [ -n "${SEC_TOOL_KEY:-}" ]; then
		mkdir -p "$KEY_DIR"
		chmod 700 "$KEY_DIR"
		(
			umask 077
			printf '%s\n' "$SEC_TOOL_KEY" >"$KEY_FILE"
		)
	fi
	[ -s "$KEY_FILE" ]
}

sha256_check() {
	if command -v sha256sum >/dev/null; then sha256sum -c - >/dev/null; else shasum -a 256 -c - >/dev/null; fi
}

# A v2 sec binary accepts -mode=genkey; v1 exits with a usage error.
sec_ok() { [ -x "$1" ] && "$1" -mode=genkey >/dev/null 2>&1; }

find_sec() {
	if [ -n "${SEC_BIN:-}" ]; then
		sec_ok "$SEC_BIN" || die "SEC_BIN=$SEC_BIN is not sec v2"
		echo "$SEC_BIN"
		return
	fi
	local cached=${CC_CACHE:-$HOME/.cache/cc}/sec-$SEC_VERSION c
	for c in "$(command -v sec || true)" "$cached"; do
		if [ -n "$c" ] && sec_ok "$c"; then
			echo "$c"
			return
		fi
	done
	install_sec "$cached"
	echo "$cached"
}

# Downloads the pinned release and checks it against the release's SHA256SUMS;
# without a release binary for this platform, builds the pinned tag with Go.
install_sec() {
	local dest=$1 os arch asset tmp base
	os=$(uname -s | tr '[:upper:]' '[:lower:]')
	arch=$(uname -m)
	case $os in linux | freebsd) ;; darwin) os=mac ;; *) die "unsupported OS: $os" ;; esac
	case $arch in x86_64 | amd64) arch=amd64 ;; arm64 | aarch64) arch=arm64 ;; *) die "unsupported architecture: $arch" ;; esac
	asset=sec-$os-$arch
	base=https://github.com/pietrangelo/sec/releases/download/$SEC_VERSION
	tmp=$(mktemp -d)
	info "installing sec $SEC_VERSION"
	if curl -fsSL "$base/$asset" -o "$tmp/$asset" 2>/dev/null &&
		curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS" 2>/dev/null; then
		(cd "$tmp" && grep " $asset\$" SHA256SUMS | sha256_check) || {
			rm -rf "$tmp"
			die "checksum mismatch for $asset $SEC_VERSION"
		}
	elif command -v go >/dev/null; then
		if ! git clone -q --depth 1 --branch "$SEC_VERSION" https://github.com/pietrangelo/sec "$tmp/src" ||
			! (cd "$tmp/src" && go build -o "$tmp/$asset" .); then
			rm -rf "$tmp"
			die "could not build sec $SEC_VERSION"
		fi
	else
		rm -rf "$tmp"
		die "cannot install sec $SEC_VERSION: no release binary for $os/$arch and no Go toolchain"
	fi
	mkdir -p "$(dirname "$dest")"
	cp "$tmp/$asset" "$dest"
	chmod 755 "$dest"
	rm -rf "$tmp"
	sec_ok "$dest" || die "installed sec $SEC_VERSION is not a v2 sec"
}

hex4() { head -c4 | od -An -tx1 | tr -d ' \n'; }

# Prints, NUL separated, the paths among the NUL separated input that must be
# stored encrypted: those with filter=sec, anything under .claude/ apart from
# settings.json and cc's own files, and every CLAUDE.md or CLAUDE.local.md
# other than the root stub.
must_encrypt() {
	local root=$1 path _attr val
	git -C "$root" check-attr -z --stdin filter |
		while IFS= read -r -d '' path && IFS= read -r -d '' _attr && IFS= read -r -d '' val; do
			case $path in
			.claude/settings.json | .claude/cc/*) ;;
			.claude/*) printf '%s\0' "$path" ;;
			CLAUDE.md) ;;
			*/CLAUDE.md | CLAUDE.local.md | */CLAUDE.local.md) printf '%s\0' "$path" ;;
			*) [ "$val" = sec ] && printf '%s\0' "$path" ;;
			esac
		done
	return 0
}

protected_files() {
	git -C "$1" ls-files -z | must_encrypt "$1"
}

blob_encrypted() { [ "$(git -C "$1" cat-file blob "$2" | hex4)" = "$MAGIC_HEX" ]; }
file_encrypted() { [ -f "$1" ] && [ "$(hex4 <"$1")" = "$MAGIC_HEX" ]; }

configure_git() {
	local root=$1 sec=$2
	git -C "$root" config filter.sec.clean "\"$sec\" -mode=encrypt -deterministic -keyfile=\"$KEY_FILE\""
	git -C "$root" config filter.sec.smudge "\"$root/.claude/cc/cc\" smudge \"$sec\" \"$KEY_FILE\""
	git -C "$root" config filter.sec.required true
	# Git smudges blobs before handing them to textconv, so diffs only need
	# to be told that the decrypted content is text.
	git -C "$root" config diff.sec.textconv cat
}

# Smudge filter: decrypts sec v2 blobs and passes anything else through, so
# commits made before the repository was protected can still be checked out.
cmd_smudge() {
	local sec=$1 key=$2 tmp
	tmp=$(mktemp)
	cat >"$tmp"
	if [ "$(hex4 <"$tmp")" = "$MAGIC_HEX" ]; then
		"$sec" -mode=decrypt -keyfile="$key" <"$tmp" || {
			rm -f "$tmp"
			return 1
		}
	else
		cat "$tmp"
	fi
	rm -f "$tmp"
}

cmd_unlock() {
	local root sec f locked=()
	root=$(repo_root "${1:-.}")
	load_config "$root"
	ensure_key || die "no key: set SEC_TOOL_KEY or create $KEY_FILE"
	sec=$(find_sec)

	while IFS= read -r -d '' f; do
		file_encrypted "$root/$f" && locked+=("$f")
	done < <(protected_files "$root")

	# Prove the key before touching the working tree.
	if [ ${#locked[@]} -gt 0 ]; then
		"$sec" -mode=decrypt -keyfile="$KEY_FILE" <"$root/${locked[0]}" >/dev/null 2>&1 ||
			die "the key in $KEY_FILE does not decrypt ${locked[0]}"
	fi

	configure_git "$root" "$sec"

	# Files checked out before the filter existed hold ciphertext: check
	# them out again so the smudge filter decrypts them.
	if [ ${#locked[@]} -gt 0 ]; then
		(cd "$root" && rm -f -- "${locked[@]}" && git checkout -- "${locked[@]}")
	fi
	info "unlocked ${#locked[@]} file(s) in $root"
}

cmd_lock() {
	local root f files=()
	root=$(repo_root "${1:-.}")
	[ -z "$(git -C "$root" status --porcelain)" ] || die "commit or stash your changes first"
	while IFS= read -r -d '' f; do files+=("$f"); done < <(protected_files "$root")
	git -C "$root" config --remove-section filter.sec 2>/dev/null || true
	git -C "$root" config --remove-section diff.sec 2>/dev/null || true
	if [ ${#files[@]} -gt 0 ]; then
		(cd "$root" && rm -f -- "${files[@]}" && git checkout -- "${files[@]}")
	fi
	info "locked ${#files[@]} file(s) in $root"
}

cmd_status() {
	local root f state
	root=$(repo_root "${1:-.}")
	while IFS= read -r -d '' f; do
		if blob_encrypted "$root" ":$f"; then state=encrypted; else state=PLAINTEXT; fi
		if file_encrypted "$root/$f"; then
			printf '%-10s %-6s %s\n' "$state" locked "$f"
		else
			printf '%-10s %-6s %s\n' "$state" clear "$f"
		fi
	done < <(protected_files "$root")
	if git -C "$root" config filter.sec.clean >/dev/null; then echo "filter: configured"; else echo "filter: not configured (locked clone)"; fi
}

# Checks what is staged in the index (what the next commit will contain).
cmd_check() {
	local root f bad=0
	root=$(repo_root "${1:-.}")
	while IFS= read -r -d '' f; do
		if ! blob_encrypted "$root" ":$f"; then
			echo "cc: NOT ENCRYPTED: $f" >&2
			bad=1
		fi
	done < <(protected_files "$root")
	if git -C "$root" cat-file -e :CLAUDE.md 2>/dev/null &&
		! git -C "$root" cat-file blob :CLAUDE.md | grep -qF "$STUB_MARKER"; then
		echo "cc: NOT ENCRYPTED: CLAUDE.md is not the cc stub (move its content to .claude/private/CLAUDE.md)" >&2
		bad=1
	fi
	if [ $bad -ne 0 ]; then
		echo "cc: refusing: the files above would be published in clear. Run 'cc unlock' and 'git add --renormalize .'" >&2
		return 1
	fi
	echo "cc: all protected files are encrypted" >&2
}

cmd_scan_history() {
	local root obj path n=0 blobs must
	root=$(repo_root "${1:-.}")
	blobs=$(mktemp)
	must=$(mktemp)
	# Every blob reachable from any ref, with a path it was stored under.
	git -C "$root" rev-list --all --objects |
		git -C "$root" cat-file --batch-check='%(objecttype) %(objectname) %(rest)' |
		awk '$1 == "blob" && NF >= 3 { sub(/^blob /, ""); print }' >"$blobs"
	cut -d' ' -f2- "$blobs" | sort -u | tr '\n' '\0' | must_encrypt "$root" | tr '\0' '\n' >"$must"
	while IFS=' ' read -r obj path; do
		if [ "$path" = CLAUDE.md ]; then
			git -C "$root" cat-file blob "$obj" | grep -qF "$STUB_MARKER" && continue
		else
			grep -qxF -- "$path" "$must" || continue
			blob_encrypted "$root" "$obj" && continue
		fi
		echo "$obj $path"
		n=$((n + 1))
	done <"$blobs"
	rm -f "$blobs" "$must"
	if [ $n -gt 0 ]; then
		cat >&2 <<EOF
cc: $n blob(s) above were committed in clear. If they were ever pushed to a
public repository, treat their content as published: rewrite the history
(for example with git filter-repo) and rotate anything secret in them.
EOF
		return 1
	fi
	echo "cc: no protected file was ever committed in clear" >&2
}

json_string() {
	local tab cr
	tab=$(printf '\t')
	cr=$(printf '\r')
	LC_ALL=C tr -d '\000-\010\013\014\016-\037' |
		LC_ALL=C sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e "s/$tab/\\\\t/g" -e "s/$cr/\\\\r/g" |
		LC_ALL=C awk 'BEGIN { ORS = ""; printf "\"" }
			{ if (NR > 1) printf "%s", "\\n"; print }
			END { printf "\"" }'
}

emit_context() {
	local ctx
	ctx=$(printf '%s' "$1" | json_string)
	printf '{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":%s,"reloadSkills":true}}\n' "$ctx"
}

cmd_session_start() {
	local root out ctx files=() f size=0 body
	cat >/dev/null || true # hook input, not needed
	root=$(repo_root "${CLAUDE_PROJECT_DIR:-.}")
	load_config "$root"

	if ! ensure_key; then
		emit_context "The Claude configuration of this repository is encrypted and could not be unlocked: no key was found (SEC_TOOL_KEY is not set and $KEY_FILE does not exist). Tell the user. Do not try to decrypt or work around it."
		return 0
	fi
	if ! out=$(cmd_unlock "$root" 2>&1); then
		emit_context "The Claude configuration of this repository is encrypted and unlocking it failed: $out. Tell the user."
		return 0
	fi
	# Keep the key out of the environment of the commands Claude runs; the
	# git filter reads it from the key file.
	if [ -n "${CLAUDE_ENV_FILE:-}" ]; then echo 'unset SEC_TOOL_KEY' >>"$CLAUDE_ENV_FILE"; fi

	if [ -f "$root/.claude/private/CLAUDE.md" ]; then files+=(.claude/private/CLAUDE.md); fi
	while IFS= read -r -d '' f; do files+=("$f"); done < <(
		cd "$root" && find .claude/private -type f -name '*.md' ! -path .claude/private/CLAUDE.md -print0 2>/dev/null | sort -z
	)
	for f in "${files[@]+"${files[@]}"}"; do size=$((size + $(wc -c <"$root/$f"))); done

	ctx="The encrypted Claude configuration of this repository has been decrypted (skills, agents and commands under .claude/ are now readable)."
	if [ ${#files[@]} -eq 0 ]; then
		:
	elif [ $size -le $CONTEXT_LIMIT ]; then
		ctx+=" These are the project instructions, with the same authority as CLAUDE.md:"
		for f in "${files[@]}"; do
			body=$(cat "$root/${f}")
			ctx+=$'\n\n'"<project-instructions path=\"$f\">"$'\n'"$body"$'\n'"</project-instructions>"
		done
	else
		ctx+=" The project instructions, with the same authority as CLAUDE.md, are too long to include here. Read each of these files in full now, before doing anything else:"
		for f in "${files[@]}"; do ctx+=$'\n'"- $f"; done
	fi
	emit_context "$ctx"
}

cmd_init() {
	local root sec self settings hook_cmd tmp
	root=$(repo_root "${1:-.}")
	self=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")
	command -v jq >/dev/null || die "init needs jq"

	mkdir -p "$root/.claude/cc"
	if [ "$self" != "$root/.claude/cc/cc" ]; then cp "$self" "$root/.claude/cc/cc"; fi
	chmod 755 "$root/.claude/cc/cc"
	if [ ! -f "$root/.claude/cc/config" ]; then
		printf 'CC_KEY_ID=%s-%s\nSEC_VERSION=%s\n' "$(basename "$root" | tr -c 'A-Za-z0-9._\n-' _)" \
			"$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')" v2.0.0 >"$root/.claude/cc/config"
	fi
	load_config "$root"
	sec=$(find_sec)

	if [ -z "${SEC_TOOL_KEY:-}" ] && [ ! -s "$KEY_FILE" ]; then
		mkdir -p "$KEY_DIR"
		chmod 700 "$KEY_DIR"
		(
			umask 077
			"$sec" -mode=genkey >"$KEY_FILE"
		)
		info "new key in $KEY_FILE: back it up, it is the only way to read the files"
	fi

	if ! grep -qF '# cc: begin' "$root/.gitattributes" 2>/dev/null; then
		cat >>"$root/.gitattributes" <<'EOF'
# cc: begin (Claude Code configuration, encrypted with sec)
.claude/** filter=sec diff=sec
.claude/settings.json !filter !diff
.claude/cc/** !filter !diff
CLAUDE.md filter=sec diff=sec
CLAUDE.local.md filter=sec diff=sec
/CLAUDE.md !filter !diff
# cc: end
EOF
	fi

	# CLAUDE.md is read when Claude Code launches, before any hook could
	# decrypt it, so its content moves to an encrypted file that the
	# SessionStart hook hands to Claude, and a plaintext stub takes its place.
	mkdir -p "$root/.claude/private"
	if [ -f "$root/CLAUDE.md" ] && ! grep -qF "$STUB_MARKER" "$root/CLAUDE.md"; then
		[ ! -e "$root/.claude/private/CLAUDE.md" ] || die ".claude/private/CLAUDE.md already exists"
		if git -C "$root" ls-files --error-unmatch CLAUDE.md >/dev/null 2>&1; then
			git -C "$root" mv CLAUDE.md .claude/private/CLAUDE.md
		else
			mv "$root/CLAUDE.md" "$root/.claude/private/CLAUDE.md"
		fi
	fi
	# Rules also load at launch: move them next to the instructions.
	if [ -d "$root/.claude/rules" ]; then
		[ ! -e "$root/.claude/private/rules" ] || die ".claude/private/rules already exists"
		if [ -n "$(git -C "$root" ls-files .claude/rules)" ]; then
			git -C "$root" mv .claude/rules .claude/private/rules
		else
			mv "$root/.claude/rules" "$root/.claude/private/rules"
		fi
	fi
	if [ ! -f "$root/CLAUDE.md" ]; then
		cat >"$root/CLAUDE.md" <<EOF
$STUB_MARKER
# Claude configuration

The instructions, skills and agents for this repository are encrypted in git.
A SessionStart hook decrypts them when a Claude Code session starts, if the key
is available (SEC_TOOL_KEY, or the key file named in .claude/cc/config).

If you do not see the decrypted project instructions in your context, say so to
the user instead of guessing them.
EOF
	fi

	settings=$root/.claude/settings.json
	# shellcheck disable=SC2016 # expanded by Claude Code, not here
	hook_cmd='"$CLAUDE_PROJECT_DIR"/.claude/cc/cc session-start'
	[ -f "$settings" ] || echo '{}' >"$settings"
	if ! jq -e --arg c "$hook_cmd" '[.hooks.SessionStart[]?.hooks[]?.command] | index($c)' "$settings" >/dev/null; then
		tmp=$(mktemp)
		jq --arg c "$hook_cmd" '.hooks.SessionStart += [{"hooks": [{"type": "command", "command": $c, "timeout": 300}]}]' \
			"$settings" >"$tmp" && mv "$tmp" "$settings"
	fi

	local hooks_dir
	hooks_dir=$(git -C "$root" rev-parse --git-path hooks)
	case $hooks_dir in /*) ;; *) hooks_dir=$root/$hooks_dir ;; esac
	mkdir -p "$hooks_dir"
	if [ ! -e "$hooks_dir/pre-commit" ]; then
		# shellcheck disable=SC2016 # expanded by the hook, not here
		printf '#!/bin/sh\nexec "$(git rev-parse --show-toplevel)/.claude/cc/cc" check\n' >"$hooks_dir/pre-commit"
		chmod 755 "$hooks_dir/pre-commit"
	elif ! grep -q 'cc/cc" check' "$hooks_dir/pre-commit"; then
		info "a pre-commit hook already exists: add '.claude/cc/cc check' to it"
	fi

	mkdir -p "$root/.github/workflows"
	if [ ! -f "$root/.github/workflows/cc-check.yml" ]; then
		cat >"$root/.github/workflows/cc-check.yml" <<'EOF'
name: Encrypted Claude configuration

on: [push, pull_request]

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Check that the Claude configuration is encrypted
        run: .claude/cc/cc check
EOF
	fi

	cmd_unlock "$root"
	# Stage the protected files again so that the filter encrypts them.
	(cd "$root" && git add .gitattributes CLAUDE.md .claude/cc .claude/settings.json .claude/private \
		.github/workflows/cc-check.yml && git add --renormalize .)
	cmd_check "$root"

	cat >&2 <<EOF

cc: done. Next steps:
  1. Review and commit:   git -C "$root" commit -m "Encrypt Claude configuration"
  2. Look for past leaks: .claude/cc/cc scan-history
  3. Back up the key:     $KEY_FILE
  4. Cloud sessions: add SEC_TOOL_KEY=<contents of the key file> to the
     cloud environment's environment variables.
EOF
}

main() {
	local cmd=${1:-}
	[ $# -gt 0 ] && shift
	case $cmd in
	init) cmd_init "$@" ;;
	unlock) cmd_unlock "$@" ;;
	lock) cmd_lock "$@" ;;
	status) cmd_status "$@" ;;
	check) cmd_check "$@" ;;
	scan-history) cmd_scan_history "$@" ;;
	session-start) cmd_session_start ;;
	smudge) cmd_smudge "$@" ;;
	version) echo "cc $CC_SCRIPT_VERSION" ;;
	*) usage ;;
	esac
}

main "$@"
