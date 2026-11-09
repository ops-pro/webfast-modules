# The filter's corpus

Lists of values, one per line, UTF-8, in the format of SecLists, ffuf, wfuzz and Burp Intruder:
every line is a value (there are no comments: `#hashtag` is a value), empty lines are skipped.
A value a line cannot hold (a newline in it) goes percent-encoded into the list's `-urlencoded.txt`.

| List | What it holds | Expected of the built-in sets together |
| --- | --- | --- |
| `sqli.txt` | SQL injection written after the well-known lists: numeric and quoted contexts, tautologies, comment and case obfuscation, encodings the rules' transformations undo | refused |
| `xss.txt` | cross-site scripting: tags and handlers, `javascript:` URLs, entities and escapes, encoded and nested tags | refused |
| `bypass.txt`, `bypass-urlencoded.txt` | known WAF evasions: comments and encodings inside keywords, spaces swapped or left out, other tautologies, entities and escapes, contexts closed first (`</title>`), split and unclosed tags. A regression set: an evasion added here comes with the rule that catches it | refused |
| `benign.txt` | what honest clients send: names with apostrophes, prose with SQL and script words, URLs, JSON, e-mail addresses, dates, numbers, browsers' User-Agents | no rule hits |

Not in `benign.txt`: `he said 'no' -- then left`, the known false positive of wf-942-140 (a
`high` rule, under the threshold alone: it refuses only with another hit, as its doc says).

Who reads them:

- the Rust tests (`src/detect/corpus.rs`): the detectors' and the prefilters' measurements, and
  `the_whole_filter_refuses_the_corpus_and_hits_no_benign_value`, which sends each value as a
  query parameter (a space as `%20` and as `+`) and as a cookie and checks the score (payloads at
  the threshold or over, benign values without any hit);
- `src/ftw.rs`, which writes them as go-ftw files (`tests/ftw/corpus/*.yaml`, the same three
  places, 403 or 200) for `tests/ftw.rs` and CI's blackbox run.

After editing a list, regenerate the go-ftw files: `UPDATE_FTW_TESTS=1 cargo test -p webfast-ngfw --lib ftw`.
