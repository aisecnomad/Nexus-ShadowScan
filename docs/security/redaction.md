# Redaction

What ShadowScan withholds from findings, reports and record exports, and what
can still remain. Treat every report as sensitive: redaction reduces accidental
disclosure, it does not make a report public. This detail moved here from
[SECURITY.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SECURITY.md);
[controls and limits](controls.md) covers the other controls.

## In brief

* Known credential formats, sensitive configuration fields, and credential-bearing URLs are **redacted** before findings or sanitized record exports are persisted. Redaction cannot identify every arbitrary secret; reports still contain security-sensitive inventory data.
* Secret stores (Secrets Manager, Key Vault, Secret Manager, OCI Vault) are read for **names only**.
* JWTs are never persisted; findings reference a truncated hash.

## What is redacted

- **By token shape:** Source excerpts and the provider text connectors shorten for a report
  (descriptions, instructions and prompts, welcome messages, trigger conditions, matching rules
  and policy statements) are redacted before they are shortened; lists of names (scopes,
  permissions, variable names) are cut first. Redaction withholds
  recognized token formats (provider prefixes such as `sk-`, `ghp_`, `glpat-`,
  `glrt-`, `xoxb-`, `xapp-`, `AIza`, `ya29.`, `npm_`, `pypi-`, `dop_v1_`,
  `ABSK` and `bedrock-api-key-`),
  JWTs, private key blocks (PEM, PGP, SSH2 and PuTTY, an unterminated one to the
  end of the text), URL userinfo (including schemes whose name contains an
  underscore, such as SQLAlchemy dialect URLs), credential query keys (including
  `auth`, `pwd` and `pat`) and webhook or MCP-server path segments (Slack,
  Discord, Teams, Zapier hooks and Zapier MCP server URLs), every cookie in a `Cookie`
  header, and compact `name:value` headers and passwords (`x-api-key:value`).
  A token or JWT is withheld behind a JSON-escaped line break or tab
  (`\n`, `\t`), a percent escape (`%3D`) or an underscore, and the prefixes no
  ordinary word contains (`sk-proj-`, `ghp_`, `AKIA`, `eyJ` and similar) also
  behind a digit; a word that merely ends in a prefix's text (`risk-`, `disk-`)
  stays. URL userinfo is withheld whole when the password holds a raw `/`, `?`
  or `#` (`postgres://u:example#pw@host`). A URL inside another URL's text
  (`redis://:pw@a,redis://:pw@b`, `?next=https://u:secret@b`) is read as a URL
  as well.
- **By naming context:** It also withholds values that their context names as credentials:
  assignments, including annotated, multiline and R (`<-`) expressions and
  every operator that joins a name to a value, with the operator kept (`=>`,
  `:=`, `||=`, `+=`, `.=`, `?=`); a quoted word or an opaque value compared with a
  sensitive name (`if token == "..."`, `!=`, `===`, `=~`);
  names such as `passphrase`, `db_pass`, `smtp_pwd`, `SECRET_KEY_BASE`, `creds` and
  npm's `_auth`, and an ODBC connection string's `Pwd=` (a braced value whole,
  `Pwd={a;b}`); the value after `password`, `passwd` and `account` in a netrc
  entry (`machine h login u password v`, on one line or one token per line,
  with keywords in any case as curl reads them, `default` anywhere on a line,
  vertical tabs and form feeds as blanks, also in a string with `\n`, `\t`,
  `\v` or `\f` escapes or PowerShell's `` `n ``, or written by `echo`),
  whatever it looks like, including a value that is itself a keyword
  (`login account password v` withholds both words after `account`), one
  after a Windows domain login (`login CORP\fred`, also `CORP\\fred` in a
  string, where an escape is read only on a line that holds a quote or an
  escape next to a keyword, or before one with blanks between), one after a
  token the format does not define once the entry's `machine`, `default`,
  `login` or `user` is read, on the line of the entry's last token
  (`machine h force yes password v`, `default force yes password v`) or on
  a later line before a `password`, `passwd` or `account` in the entry's
  region, which spans the eight lines from that of the entry's last token
  and ends before at a blank line or the next entry's `machine`, `default`
  or `macdef` (`machine h`, then `force yes`, then `password v` on the next
  lines), one in an entry spread over adjacent string literals, which a
  closing quote, then blanks, line breaks, a `+` or a line continuation,
  then an opening quote join (`("machine h\n"`, then `"login u\n"` and
  `"password v\n")` on the next lines), one after a keyword glued to a
  closing quote, which Python's `netrc` reads as the next token
  (`login "u"password v`, also after a quoted word glued to the name, as in
  `login "u""v"password v`), an entry in a comment, also right after its
  `#` (a `#` after a blank or a line-break escape starts a comment, which
  runs to the end of its line or, in escaped text, to the next line-break
  escape: where escapes are read and its line holds an escape next to a
  keyword or before one with blanks between (`machine h # c\n  login u`), a
  line-break escape before the `#`, or the same quote both before and after
  it, so the password of `"machine h\n  # bot\npassword v"` is withheld,
  while a netrc file's own `# Bob's share is C:\new\data` runs to the end
  of its line; a keyword that is a directory of a Windows path, right after
  a backslash or right before one that starts no escape, is no escape next
  to a keyword, so `# home \\nas\user\fred` and `# C:\Users\bob\default\new`
  run to the end of theirs too), and the lines of a netrc `macdef` macro up to the empty
  line that ends it (a word after `default password` in prose is withheld
  as well, and so is a word after `password` or `account` that follows
  `machine`, `default` or `login` on its line or in its region, as in
  `the machine needs an account and a key`, `the default service account
  of the instance`, or `machine learning tools` with
  `create an account for each user` on the next line); Yarn 1's `.yarnrc`
  registry credentials written `name value`
  (`"//registry.yarnpkg.com/:_authToken" "v"`, `_auth v`);
  mappings, YAML block scalars, properties and INI entries; `getenv`-style
  calls; name/value records such as Kubernetes `env` lists; XML elements and
  `key`/`value` attributes; Dockerfile `ENV NAME value`, `setx`, `setenv` and
  C `#define`; command-line options such as `--api-key`, `--token`,
  `--password`, `--passphrase`, `--pat`, `--auth`, `curl -u user:secret`,
  `-H "X-Api-Key:value"` (and any header whose name ends in a
  credential word, such as `X-Token: value` or `X-Functions-Key: value`), `-p` after
  `docker login` and other registry or cloud logins (`az`, `az acr`, `oc`,
  `cf`), `sshpass -p`, MySQL's `-pVALUE` and a literal echoed into
  `--password-stdin`; literal defaults of credentials read from the
  environment (`process.env.OPENAI_API_KEY || "..."`, `?? "..."`,
  `or "..."`, `?: "..."`, `${OPENAI_API_KEY:-...}`), also after a subscript
  or call read assigned to a credential name (`azure_api_key:
  os.environ['K'] if PROD else '...'`, `or '...'`, and an opaque one under
  `azureKey: process.env['K'] ?? '...'`); and string literals,
  including Python f-strings without replacement fields and backtick
  strings, passed to credential constructors and helpers such as
  `AzureKeyCredential("...")`, Rust's `AzureKeyCredential::new("...")`, C#'s
  target-typed `AzureKeyCredential credential = new("...")`,
  `HTTPBasicAuth("user", "...")`, `Credentials.basic("user", "...")`,
  `auth=("user", "...")` and `setBearerToken("...")`, including methods down a
  builder chain (`builder().apiKey("...")`). XML key/name attributes, element
  names and name/value records are read as settings: a hierarchical .NET name
  counts by its last `:`, `__` or `.` segment as well as whole
  (`<add key="OpenAI:Secret" value="..."/>`, `- name: AzureOpenAI__Token`,
  `<entry key="openai.token">`). A key/name attribute names the element's
  value attributes, `<value>` child and content, and the element's own name
  decides its content as well (`<token key="openai.token" value="">...</token>`).
  A literal that looks like an opaque key is also withheld from a name whose
  last word, ignoring trailing digits, names a credential: in assignments
  (`openaiKey = "..."`, `key = "..."`, `KEY1=...`, YAML `openaiKey: ...`),
  settings (`<add key="AzureOpenAI:Key" value="..."/>`,
  `<OpenAIKey>...</OpenAIKey>`, `{name: OpenAIKey, value: ...}`), options
  (`--key ...`, also in an argv list) and `dotnet user-secrets set NAME
  VALUE`; ordinary values under such names (`<add key="CacheKey"
  value="users"/>`, `cacheKey: users-by-id`) stay. It is also withheld from a
  lone unindented line after a sensitive key such as `token:`. Variable
  references (`$VAR`, `${{ secrets.X }}`), environment variable names and
  placeholders stay visible, and so does a value that is exactly one read of
  an environment variable by an upper-case name (`apiKey =
  process.env.OPENAI_API_KEY`, `api_key = os.getenv("OPENAI_API_KEY")`). Only
  blanks and then the end of the line, `;`, `,` or a closing bracket may follow
  the read: with a default argument, a fallback literal, any other operand or a
  comment after it the value is withheld up to where the value lexer ends it
  (a quote, bracket, `,` or `;` of the expression). On a line that joins a
  credential name to a value (by `:`, `=` or a PHP or Ruby `=>`), or that
  gives a callee whose last word names a credential its arguments
  (`sgMail.setApiKey(...)`, a builder's `.apiKey(...)`), every string literal
  after that name and the comment (`//`, `#`, `/* */` or an XML or HTML
  `<!-- -->`, read to its end when it runs past the line) keep their words,
  references and model names, but each token in them
  that looks like an opaque key is withheld, wherever the value ended: a
  fallback after a cut read (`azureApiKey: process.env.K?.trim() || "..."`,
  `os.environ[ 'K' ] if PROD else '...'`, `cfg("a", "b") || "..."`), a default
  argument (`os.getenv("K", "...")`) and a comment after the `,` or `;` that
  ends the value (`apiKey: process.env.KEY, // old: ...`, `api_key =
  os.environ["KEY"]; # ...`). A later line goes on with that value when it
  starts with a fallback operator (Black's `    or "...",`) or the line before
  ends with one, with comment lines between. Under each
  password's or secret's name on the line (`password`, `passwd`, `pwd`,
  `passphrase`, `pass` or `secret` as the last word, or a last word that runs
  words together and ends in one of them but `pass` and `pwd`, such as
  `dbpassword` or `CLIENTSECRET`), not only under its first credential name (`{
  apiKey: ..., password: ... }`, `client.setApiKey(k); ... { password: ...
  }`), every string literal of the value up to the next entry of its own
  mapping, object or argument list is withheld whole, whatever its shape
  (`dbPassword: process.env.DB_PASSWORD?.trim() || "..."`, `db_password:
  os.getenv("K", "...")`, `clientSecret: process.env.S?.trim() || "..."`, a
  passphrase with spaces too), as the assignment form withholds it: after an
  environment read the matcher reports such a fallback whatever its shape. A keyword argument of the read is part of the value
  (`cfg.get("db", "password", fallback="...")`, `env("P",
  default_value="...")`, `{ fallback: "..." }`), and a closer that closes
  no opener on the line (an earlier pass withheld it with the start of the
  value, or a line before opened it) counts as one opened in the value, so
  the value goes on past the entries before it. Spans
  withheld for one value merge, so a literal whose start looks like a token
  is withheld to its end, not only that token. An upper-case variable name,
  a path, a URL, a placeholder and a literal of fewer than six characters
  stay. A template that assembles its text from
  expressions (`${prefix}...`) stays, as in assignments. A read is withheld
  as well when its variable name looks like a key pasted in place of the
  name: letters and digits
  alternate in a long run of it, or it has 16 characters or more and no `_`
  (an upper-case key or a base32 secret, with or without digits; a name such
  as `HUGGINGFACEHUBAPITOKEN` is withheld with them).
- **Structured records:** Structured name/value records that connectors
  pass to the sanitizer read their name as a setting too, in either field
  order (`{"name": "OpenAI:Secret", "value": "..."}`, and an opaque value under
  `OpenAIKey`); an environment-style name there (`PAGE_TOKEN`) withholds only
  an opaque value. The fields of structured records (including every record
  of `--dump-records`) are withheld by name and by the words of the name: the
  last word, ignoring digits, is `secret`, `token`, `password`, `passwd`,
  `pwd`, `passphrase`, `pass`, `credential(s)`, `cookie` or `bearer`
  (`webhook_secret`, `bot_token`, `jwtSecret`, `db_pass`), or is `key` after
  `api`, `access`, `secret`, `private`, `signing`, `client`, `license`,
  `encryption`, `master`, `auth`, a provider such as `openai` or similar
  (`client_key`, `openai_key`). Cursors (`next_token`, `page_token`,
  `skipToken`), tokenizer tokens (`eos_token`), switches (`requires_auth`,
  `has_secret`), the bare `key` of tags and S3 objects, `sort_key`,
  `partition_key` and `cache_key` stay. A value that is not JSON-like (bytes,
  a set, an exception, a plugin's object) is converted to text before it is
  redacted, so `default=str` never prints it raw. The rules added for settings, options,
  numbered names and YAML values run after the earlier rules, on their
  output, so they only withhold more.
  Credential constructor calls also accept whitespace and
  comments before the parenthesis, redundant parentheses, static C# `$`
  strings, verbatim multiline C# strings with doubled quotes, and multiline
  triple-quoted literals. Recognized unterminated quoted flow-record values
  and credential-call literals are withheld through their bounded text tail.
  Supported Go SDK imports bind credential-call receivers, including aliases
  and dot imports, before evidence truncation. This lexical recognition shares
  the sanitization work and binding limits; exhausting either withholds the
  evidence and marks coverage incomplete. Local shadowing can over-redact.
  Dynamic function reassignment is outside this bounded direct-call recognition.
  Known environment lookup
  fallback literals inherit the credential constructor's context even when
  their environment variable name is ordinary. Textual flow records support
  either name/value field order, braces and escaped quotes inside quoted
  values; preceding YAML sibling values are read within sixteen lines without
  crossing a list-item or mapping boundary. A quoted assignment value, a
  double-quoted option value and an `auth=` password close at their first
  quote that no backslash escapes, so `{"log": "password: \"S\""}` and
  `--password "a\"S"` withhold all of `S`. Explicit signature and credential
  query fields are withheld in scheme-less URLs and copied query strings too.
  Command-specific `llm -k` and credential options glued after another option
  value are recognized; unrelated `-k` flags stay visible. Under key-like
  assignment names, an opaque identifier with at least three digit runs and
  only short letter fragments is also withheld; ordinary type names and
  `--key users` values remain visible.
  `aws configure set` also withholds positional `aws_access_key_id`,
  `aws_secret_access_key`, `aws_session_token` and legacy `aws_security_token`
  values in shell text and literal argv lists, in any letter case and for
  `aws`, `aws.exe` and `aws.cmd`, including `default.` and `profile.<name>.`
  settings, global options (an unlisted `--option` is read both as a flag and
  as taking a value), quoted words (including JSON-escaped quotes), POSIX,
  PowerShell backtick and cmd caret line continuations, `#` and `//` comments
  and string prefixes such as `r"..."` or `b"..."` between source argv
  elements, a bare `--` before the value, and an executable passed apart from
  its list (`spawn("aws", [...])`, `spawn("aws", args=[...])`,
  `["aws"] + [...]`, `Command::new("aws").args([...])`). Native argv exports remove
  copies of those values from
  sibling fields too. Variable references, placeholders and metavariables
  stay visible. Adjacent quoted shell fragments, escaped bare values and source
  argv expressions beginning
  with a literal are withheld as a whole; the reader does not evaluate them.
  Entirely computed argv values remain outside this command reader.
  Recognition is bounded to 32 arguments and 16 KiB per candidate: a candidate
  that exceeds either limit fails sanitization closed rather than publishing
  a later value.

## What can remain

- **Credentials in a file over `max_file_size` are not read.** The credential
  pass reads every analyzable file up to `max_file_size` (1,000,000 bytes by
  default), and no further: a key in an oversize cassette, fixture or data
  export is not reported. The scan records the file as a coverage gap of a
  whole entry wherever it lies (it is never declared by `profile: ci` or
  weighed down as test code), so a few such files are tolerated within the
  coverage budget, listed in `stats[].coverage.details` and counted in
  `summary.tolerated_gaps`, and more of them exit 3. An oversize dotenv file
  (`.env`, `.env.production`) always exits 3 while credentials are scanned; an
  oversize tool credential file (`.npmrc`, `.netrc`) is one such entry. Raise
  `max_file_size`, or set `--max-coverage-gap 0`, where such a key must not be
  missed.
- **Limitations:** Redaction cannot withhold a credential that nothing names or shapes as one,
  so treat reports as confidential. In evidence snippets only, a last-resort
  pass also withholds a quoted literal that looks generated: at least 20
  token characters mixing upper case, lower case and digits, switching between
  them often, with high per-character entropy. Hex digests, UUIDs and ordinary
  identifiers keep their text; a short or low-entropy secret can still pass,
  and descriptions, titles and metadata do not get this pass. Outside
  snippets, these forms can remain: an unprefixed
  literal passed to an ordinary function, or nested in another call inside a
  credential constructor (`AzureKeyCredential(str("..."))`) when it does not
  look like an opaque key (one that does is withheld, as after any credential
  name on its line); a value assembled by a computed expression; after a read
  the value lexer cuts, in `name: value` form or a callee's arguments, a
  literal under a name that is no password's or secret's that does not look
  like an opaque key, punctuated or not (`apiKey: cfg("a", "b") ||
  "correct-horse-battery-staple"`), and under a password's or secret's name a literal of fewer than six characters or one that
  reads as an upper-case variable name (`|| "HUNTERPASS"`); a literal on a later
  line that the value lexer does not reach when that line does not start with
  a fallback operator and the line before does not end with one; a key in a
  block comment opened on a line that names no credential. Recognized credential calls with mixed interpolation
  withhold opaque static material; pure variable references remain visible. A few LLM SDK
  calls take a key positionally under a name that names no credential; the
  literal at the key's position in these is withheld: Semantic Kernel's .NET
  Azure OpenAI and OpenAI connectors
  (`AddAzureOpenAIChatCompletion("deployment", endpoint, "...")`,
  `AddOpenAIChatCompletion("model", "...")`, including the overloads that
  take an endpoint `Uri` before the key, and their chat client, embedding,
  text-to-image and audio siblings and the matching services), go-openai's
  `openai.DefaultConfig("...")`, `openai.NewClient("...")` and
  `openai.DefaultAzureConfig("...", url)`, `new OpenAiService("...")`
  (com.theokanning.openai) and `new GoogleGenerativeAI("...")`. Where a
  variable stands at the key's position, a later literal such as an
  organization ID may be withheld instead. Any other SDK call is an ordinary
  function, as is a key at a position no listed overload uses. The three
  go-openai helpers also recognize literal imports of
  `github.com/sashabaranov/go-openai`, including aliases and dot imports;
  import references must be present in the full source passed to redaction.
  These forms can also remain: a word-like or short value under
  a name that is not itself sensitive and that lacks recognized opaque
  structure; a lowercase word
  after a space-separated option or as a fallback default; an option this
  list does not name, including command-specific one-letter options other
  than the recognized forms above; a positional
  argument of any other command besides the supported AWS credential settings;
  the part of an unquoted option value after a
  bracket, brace or comma; a literal fallback outside recognized credential
  contexts;
  URL userinfo that cannot be delimited: a password holding raw whitespace,
  quotes or angle brackets, one holding both a raw `@` and a raw `/`, `?` or
  `#`, a token without a colon that holds one of those
  (`https://tok?en@host`), a numeric password followed by one
  (`https://user:00000000?x@host`, which reads as a port), or a
  percent-encoded URL inside a query value
  (`?u=https%3A%2F%2Fu%3Apw%40h`); a token glued to a
  letter (`apisk-proj-...`) or, for a shorter prefix, a digit; a value named
  only by a comment (`x = "..."  # openai key`); a bare value that is not an
  opaque key compared with a sensitive name (`token == hunter2`), a literal written before the
  operator (`"..." == token`) or compared with a subscript
  (`headers["token"] == "..."`); a readable value glued to the colon of a
  sensitive name (`password:hunter2`) or under a bare `pwd` (the shell's
  working directory has that name); a field of a structured record whose
  name does not end in a credential word as above (`OpenAIKey`, `key1`, a
  bare `auth` or `pass`) and holds a value that looks like no credential; a
  record outside the bounded sibling/flow rules above; a
  value split across concatenated strings; a netrc entry spread over
  prefixed string literals or JavaScript template literals (Python's
  `b"machine h\n"`, `f"..."` or `r"..."` on the next lines, `` `machine h\n`
  + `` and so on), whose prefix or backtick the join of adjacent literals
  does not read, so the entry ends after `machine`; a netrc value after a token the
  format does not define on a later line than the entry's last token, which
  ends the entry there as prose after `machine learning` does, when a blank
  line, the next entry's `machine`, `default` or `macdef`, or the end of the
  eight-line region comes before the value's `password`, `passwd` or
  `account` (`force yes` and an empty line between `machine h` and
  `password v`), or in an entry whose `machine` is glued to other text; a
  commented-out netrc token that is not part of an entry in its comment, on
  a comment line of its own that holds no `machine` or `default`
  (`# password v` under a commented `# machine h`) or after an entry's own
  tokens (`login u # was password v`); the escaped lines after a netrc
  comment that those rules run to the end of its line, in escaped text
  where no escape sits next to a keyword or before one with blanks
  between, none breaks a line before the `#` and no quote comes both
  before and after it (`machine h # it's\nforce password v`); a netrc
  keyword written in quotes, which Python's `netrc` reads as the keyword,
  and the value after it (`login u "password" v`,
  `"machine" h login u password v`); and sensitive business data.
- **Plural collection names are not sensitive names.** `credentials` names a
  credential, but the list or mapping under a plural `secrets` or `tokens`
  key keeps its values unless each one has a recognized shape or a sensitive
  name of its own: `secrets: [prod-db-password]` lists the names a secret
  store holds, which the Secrets Manager, Key Vault, Secret Manager and OCI
  Vault collectors read and report as inventory, and `tokens: 12` is a count.
  A raw credential placed under one of those keys without a recognized shape
  therefore remains (the structural pass still removes it wherever a
  sensitive-named field holds the same value). Keep that in mind for a
  GitHub Actions `secrets:` block or a Kubernetes manifest an operator pastes
  into an issue.
