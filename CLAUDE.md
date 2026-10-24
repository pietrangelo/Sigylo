<!-- cc:stub -->
# Claude configuration

The instructions, skills and agents for this repository are encrypted in git.
A SessionStart hook decrypts them when a Claude Code session starts, if the key
is available (SEC_TOOL_KEY, or the key file named in .claude/cc/config).

If you do not see the decrypted project instructions in your context, say so to
the user instead of guessing them.
