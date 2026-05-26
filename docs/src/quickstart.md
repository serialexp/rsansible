# Quickstart

Once you have `rsansible` and `rsansible-agent` built (see
[Installation](./install.md)), a run looks exactly like an
`ansible-playbook` invocation, with the agent path threaded through.

## A minimal playbook

`inventory.yml`:

```yaml
all:
  hosts:
    web-1:
      ansible_host: 10.0.0.11
    web-2:
      ansible_host: 10.0.0.12
  vars:
    ansible_user: bart
```

`site.yml`:

```yaml
- hosts: all
  gather_facts: true
  tasks:
    - name: Install nginx
      apt:
        name: nginx
        state: present
      become: true

    - name: Ensure nginx is running
      service:
        name: nginx
        state: started
        enabled: true
      become: true
```

## Running

```
rsansible run \
  -i inventory.yml \
  -a target/x86_64-unknown-linux-musl/release/rsansible-agent \
  site.yml
```

That'll connect to every host in `all` via SSH (using your
`ssh-agent`), push the agent binary into a fresh per-run temp dir,
gather facts in parallel, dispatch the two tasks per-host in
lockstep, and print a PLAY RECAP at the end that matches
Ansible's shape exactly.

## Useful flags

- `--limit web-1` / `--limit 'web*'` / `--limit '~^web\d$'` — filter
  the target set the same way Ansible does.
- `--tags deploy` / `--skip-tags slow` — tag selectors, including
  the magic `always` / `all` / `untagged`.
- `-e key=value` / `-e @vars.yml` / `-e '{json}'` — extra vars at
  highest precedence.
- `--check` — dry run. Modules report what they would change,
  mutating ops are skipped, per-task `check_mode: false` opts back
  in.
- `--forward` (optionally with `--forward-host <name>`) — push the
  controller next to the targets and drive the run from there.
  Collapses per-op SSH RTT on long-haul links. See the forward-mode
  guide.
- `--timing` — print a phase-by-phase orchestrator breakdown
  alongside the per-host `agent=` / `rtt=` summary.

## What to read next

- [Compatibility with Ansible](./reference/compat.md) — when a ported
  playbook misbehaves, this is where the deliberate differences live.
- [rsansible idioms](./reference/idioms.md) — preferred spellings for
  fresh playbooks.
