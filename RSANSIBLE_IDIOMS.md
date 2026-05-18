# rsansible idioms — canonical spellings preferred over Ansible's

This file tracks places where rsansible offers a **canonical spelling**
that we prefer for fresh playbooks, alongside a **compat shim** that
keeps the original Ansible spelling working. Behavior is identical via
the shim — these are not divergences. They are naming/ergonomics
preferences for new code.

**Scope:** if behavior matches Ansible's (because a shim forwards), it
belongs here. If behavior differs in a way an author would observe
given identical input, it belongs in `ANSIBLE_COMPAT.md` instead.

When authoring fresh rsansible playbooks, prefer the canonical
spelling. When porting an existing Ansible playbook, the compat shim
means you don't have to rewrite — but new tasks added to that
playbook should use the canonical form.

---

## 1. Lookups: `controller_*` over `lookup('<plugin>', ...)`

| Canonical | Compat shim |
|---|---|
| `{{ controller_read_file("/etc/foo") }}` | `{{ lookup('file', '/etc/foo') }}` |
| `{{ controller_shell_stdout("uuidgen") }}` | `{{ lookup('pipe', 'uuidgen') }}` |
| `{{ controller_env("HOME") }}` | `{{ lookup('env', 'HOME') }}` |

**Why prefer the canonical:** the *location of execution* (controller
vs target) is in the function name, not buried in plugin docs. The
entire class of "I thought `lookup('file', ...)` read the target's
filesystem" footguns evaporates when the side is spelled at the call
site. See `CLAUDE.md` ("Naming: `controller_` / `target_` prefix") for
the full rationale.

When/if we add `target_*` equivalents, they'll land here too with the
same pair-structure.

---

## 2. Package repositories: `repository` over `apt_repository` / friends

| Canonical | Compat shim |
|---|---|
| `repository:` with `manager:` selector | `apt_repository:` (forwards with `manager: apt`) |

Canonical shape:

```yaml
- repository:
    manager: apt        # optional; auto-detected on the agent when omitted.
                        # Today only `apt` is implemented; other managers
                        # error with BAD_REQUEST.
    repo: "deb [signed-by=/etc/apt/keyrings/pg.asc] https://apt.postgresql.org/pub/repos/apt focal-pgdg main"
    filename: pgdg      # optional; derived from `repo` if omitted (Ansible-compat)
    state: present
    update_cache: true  # default true (matches Ansible's apt_repository)
```

Compat shim (existing Ansible playbooks port unchanged):

```yaml
- apt_repository:
    repo: "deb [signed-by=...] https://apt.postgresql.org/pub/repos/apt focal-pgdg main"
    filename: pgdg
    state: present
    update_cache: true
# → forwards to repository: { manager: apt, ... }
# A body field `manager:` that contradicts the YAML key (e.g.
# `apt_repository: { manager: auto }`) is rejected at parse time.
```

**Why prefer the canonical:** mirrors `package:` vs `apt:`/`yum:`/etc.
in Ansible itself — the unprefixed form is the cross-manager one, and
playbooks that target mixed fleets stop reaching for `when:
ansible_os_family == "Debian"` guards. The shim keeps existing
playbooks working unmodified.

When other repository managers land (`dnf`, `zypper`, …), they slot in
under `manager:` without new top-level task names. The `manager:` byte
allocation in the wire schema mirrors `package:` 1:1 so a single
auto-detect step on the agent serves both ops.

---

## 3. Python packages: `package: manager: pip` over `pip:`

| Canonical | Compat shim |
|---|---|
| `package:` with `manager: pip` | `pip:` (forwards with `manager: pip`) |

Canonical shape:

```yaml
- package:
    manager: pip
    name:
      - "requests==2.31.0"
      - "ruff"
    state: present
    virtualenv: /opt/myapp/venv          # optional; absent → system pip
    virtualenv_command: python3.11 -m venv  # optional; default `python3 -m venv`
```

Compat shim (existing Ansible playbooks port unchanged):

```yaml
- pip:
    name:
      - "requests==2.31.0"
      - "ruff"
    state: present
    virtualenv: /opt/myapp/venv
# → forwards to package: { manager: pip, ... }
# A body field `manager:` that contradicts the YAML key (e.g.
# `pip: { manager: apt }`) is rejected at parse time.
```

**Why prefer the canonical:** same rationale as `repository:` vs
`apt_repository:` — `package:` is the cross-manager spelling that
already covers apt today and will cover dnf/zypper/etc. as backends
land. Python-via-pip is just one more `manager:` value; making it a
peer of system packages keeps multi-manager playbooks readable
(`package: { manager: pip, ... }` next to `package: { manager: apt,
... }`) and stops the awkward shape where every backend has its own
top-level task name. The shim keeps existing Ansible `pip:` tasks
working unmodified.

**Supported fields under `manager: pip`:** `name`, `state` (present /
absent / latest), `virtualenv`, `virtualenv_command`. Other pip
knobs that Ansible exposes (`virtualenv_site_packages`,
`virtualenv_python`, `executable`, `chdir`, `editable`, `extra_args`,
`umask`) are rejected at parse time with BAD_REQUEST — they aren't
implemented yet, and silently ignoring them would let playbooks
think they got the behavior they asked for.

---

## When you add an entry here

Two-column "canonical vs compat" table at minimum, plus one paragraph
on *why* the canonical is preferred. If the canonical isn't shipped
yet, mark **Status: not yet implemented** so readers know not to reach
for it.

Cross-reference from `CLAUDE.md` if there's a deeper architectural
rule behind the naming choice (as with `controller_*`).
