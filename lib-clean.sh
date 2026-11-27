#!/bin/bash
# lib-clean.sh - sourced (never run) by config.sh, reg-diff.sh, home-diff.sh and summarize-run.sh.
# Only defines functions, so it is safe to source anywhere.

# wq_clean_text <text>: the text with everything that can fool a terminal or a reader made visible.
# File names, process names and registry keys come from the game, so before one goes into a log or onto a
# screen: control characters (C0, DEL, and the C1 range, which xterm-style terminals still obey when they
# arrive as UTF-8) become "?", and Unicode direction overrides/isolates and zero-width characters become
# <bidi>/<hidden> markers, so "photo_<U+202E>gpj.exe" cannot pass for a picture. Byte-based (LC_ALL=C), so it
# gives the same result in every locale. Always print the result with printf '%s' or printf '%b%s%b',
# never `echo -e`: that would turn a file named like  x\033[2J  (literal backslashes) into a real escape.
wq_clean_text() {
  printf '%s' "${1-}" | tr '\001-\037\177' '?' | wq__mark_invisible
}

# wq_clean_stream: the same for several lines on stdin. Newline and tab survive, every other control becomes "?".
# Use it on anything read back from a log the game could write to (launch log, alert log) before it is shown.
wq_clean_stream() {
  tr '\001-\010\013-\037\177' '?' | wq__mark_invisible
}

# the shared byte-level part: C1 controls, direction controls, zero-width / invisible characters, and the
# Unicode "tag" block U+E0000..E007F (invisible text that a reader or an AI assistant would still read)
wq__mark_invisible() {
  LC_ALL=C sed -E \
    -e 's/\xc2[\x80-\x9f]/?/g' \
    -e 's/\xe2\x80[\xaa-\xae]|\xe2\x81[\xa6-\xa9]|\xd8\x9c/<bidi>/g' \
    -e 's/\xe2\x80[\x8b-\x8f\xa8\xa9]|\xe2\x81[\xa0-\xa4\xaa-\xaf]|\xef\xbb\xbf|\xc2\xad|\xe1\xa0\x8e|\xe2\xa0\x80|\xef\xbf[\xb9-\xbb]|\xf3\xa0[\x80-\x81][\x80-\xbf]/<hidden>/g'
}
