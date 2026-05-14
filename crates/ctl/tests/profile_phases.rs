//! Phase-by-phase wallclock profile of an end-to-end run.
//!
//! Bypasses the orchestrator so each step can be timed independently. We
//! still exercise the real `ssh::connect_and_push` + framed-protocol code
//! paths — the connect/push/exec/Hello loop is the same one
//! `orchestrator::run` uses internally.
//!
//! Run:
//!   cargo test -p rsansible-ctl --test profile_phases \
//!     -- --ignored --nocapture --test-threads=1

mod common;

use std::collections::BTreeMap;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use rsansible_ctl::ssh::{self, AgentConn, ConnectOptions};
use rsansible_wire::{
    generated::Message,
    msg::{op_shell, op_write_file, task_dispatch},
    read_frame, write_frame,
};
use tokio::task::JoinSet;

use common::{locate_agent_binary, should_skip_docker_tests, sshd::SshdContainer};

const NUM_HOSTS: usize = 3;

#[tokio::test]
#[ignore]
async fn profile_three_host_run() -> Result<()> {
    if should_skip_docker_tests() {
        eprintln!("skipping: RSANSIBLE_SKIP_DOCKER_TESTS=1 or docker missing");
        return Ok(());
    }

    let total_t0 = Instant::now();
    let mut log: Vec<(&'static str, std::time::Duration)> = Vec::new();
    macro_rules! phase {
        ($name:expr, $body:expr) => {{
            let t = Instant::now();
            let v = $body;
            let d = t.elapsed();
            log.push(($name, d));
            v
        }};
    }

    // 1. Locate (and possibly build) the agent binary.
    let agent_path = phase!("locate-agent-binary", locate_agent_binary()?);

    // 2. Read its bytes — should be near-instant; tracked for completeness.
    let agent_bytes = phase!("read-agent-bytes", std::fs::read(&agent_path)?);
    let agent_size = agent_bytes.len();

    // 3. Spawn NUM_HOSTS sshd containers in parallel.
    let containers: Vec<SshdContainer> = phase!("docker-containers-up", {
        let mut set: JoinSet<Result<SshdContainer>> = JoinSet::new();
        for _ in 0..NUM_HOSTS {
            set.spawn(async { SshdContainer::start().await });
        }
        let mut out = Vec::new();
        while let Some(joined) = set.join_next().await {
            out.push(joined.map_err(|e| anyhow!("panic: {e}"))??);
        }
        out
    });

    // 4. SSH connect + auth + arch probe + upload agent + exec + Hello.
    //    Per-host timing: we time the whole barrel-roll for each host
    //    individually, then report (min, mean, max) since they run in
    //    parallel and the wallclock for the *set* is dominated by the
    //    slowest.
    let mut per_host_connect: Vec<std::time::Duration> = Vec::new();
    let (mut conns, connect_wall) = {
        let t_phase = Instant::now();
        let mut set: JoinSet<(String, std::time::Duration, Result<AgentConn>)> = JoinSet::new();
        for (i, c) in containers.iter().enumerate() {
            let opts = ConnectOptions {
                host: "127.0.0.1".into(),
                port: c.host_port,
                user: c.user.clone(),
                key_path: Some(c.key_path.clone()),
                strict_host_key: false,
            };
            let bin = agent_bytes.clone();
            let name = format!("host{}", i + 1);
            set.spawn(async move {
                let t = Instant::now();
                let r = ssh::connect_and_push(&opts, &bin).await;
                (name, t.elapsed(), r)
            });
        }
        let mut conns: BTreeMap<String, AgentConn> = BTreeMap::new();
        while let Some(joined) = set.join_next().await {
            let (name, d, r) = joined.map_err(|e| anyhow!("panic: {e}"))?;
            per_host_connect.push(d);
            conns.insert(name, r.context("connect_and_push")?);
        }
        (conns, t_phase.elapsed())
    };
    log.push(("ssh-connect+push+hello (wall, all hosts in parallel)", connect_wall));

    // 5. Three barrier tasks: shell echo, write_file, exec cat. Each
    //    timed as a whole barrier (slowest host wins).
    let task_wall_shell = run_barrier(
        &mut conns,
        1,
        rsansible_wire::msg::task_dispatch(
            1,
            op_shell("printf 'hi from %s\\n' \"$(hostname)\"".into(), 5_000),
        ),
    )
    .await?;
    log.push(("task barrier 1: shell echo", task_wall_shell));

    let task_wall_write = run_barrier(
        &mut conns,
        2,
        task_dispatch(
            2,
            op_write_file(
                "/tmp/rsansible-hello".into(),
                0o644,
                b"hello from rsansible\n".to_vec(),
            ),
        ),
    )
    .await?;
    log.push(("task barrier 2: write_file", task_wall_write));

    let task_wall_exec = run_barrier(
        &mut conns,
        3,
        task_dispatch(
            3,
            rsansible_wire::msg::op_exec(
                vec!["/bin/cat".into(), "/tmp/rsansible-hello".into()],
                vec!["LC_ALL".into()],
                vec!["C".into()],
                String::new(),
                Vec::new(),
                5_000,
            ),
        ),
    )
    .await?;
    log.push(("task barrier 3: exec cat", task_wall_exec));

    // 6. Bye + close.
    let bye_wall = {
        let t = Instant::now();
        for (_, mut conn) in std::mem::take(&mut conns) {
            let _ = write_frame(&mut conn.stream, &rsansible_wire::msg::bye()).await;
            // dropping the conn closes the underlying channel
        }
        t.elapsed()
    };
    log.push(("bye + close", bye_wall));

    // 7. Container teardown via Drop.
    let teardown_wall = {
        let t = Instant::now();
        drop(containers);
        t.elapsed()
    };
    log.push(("docker rm -f (Drop)", teardown_wall));

    let total = total_t0.elapsed();

    // Report.
    eprintln!();
    eprintln!("================== rsansible phase profile ==================");
    eprintln!("agent size: {} KiB", agent_size / 1024);
    eprintln!("num hosts:  {NUM_HOSTS}");
    eprintln!();
    eprintln!("{:>50}  {:>10}", "phase", "wallclock");
    eprintln!("{:>50}  {:>10}", "─".repeat(50), "─".repeat(10));
    for (name, d) in &log {
        eprintln!("{:>50}  {:>9.2?}", name, d);
    }
    eprintln!("{:>50}  {:>10}", "─".repeat(50), "─".repeat(10));
    eprintln!("{:>50}  {:>9.2?}", "TOTAL", total);
    eprintln!();
    if !per_host_connect.is_empty() {
        per_host_connect.sort();
        let min = per_host_connect.first().copied().unwrap();
        let max = per_host_connect.last().copied().unwrap();
        let mean = per_host_connect.iter().sum::<std::time::Duration>() / per_host_connect.len() as u32;
        eprintln!(
            "  per-host connect+push+Hello: min {:.2?}  mean {:.2?}  max {:.2?}  (count={})",
            min,
            mean,
            max,
            per_host_connect.len()
        );
    }
    eprintln!("=============================================================");
    eprintln!();

    Ok(())
}

/// Send one TaskDispatch to every host in parallel and wait for TaskDone
/// from each — returns the slowest's elapsed time (i.e. the barrier
/// wallclock).
async fn run_barrier(
    conns: &mut BTreeMap<String, AgentConn>,
    seq: u32,
    dispatch: rsansible_wire::Message,
) -> Result<std::time::Duration> {
    let t = Instant::now();
    let take: Vec<(String, AgentConn)> = std::mem::take(conns).into_iter().collect();
    let mut set: JoinSet<(String, AgentConn, Result<()>)> = JoinSet::new();
    for (name, mut conn) in take {
        let d = dispatch.clone();
        set.spawn(async move {
            let r = drive_one_task(&mut conn, seq, d).await;
            (name, conn, r)
        });
    }
    while let Some(joined) = set.join_next().await {
        let (name, conn, r) = joined.map_err(|e| anyhow!("panic: {e}"))?;
        r.with_context(|| format!("task on {name}"))?;
        conns.insert(name, conn);
    }
    Ok(t.elapsed())
}

async fn drive_one_task(
    conn: &mut AgentConn,
    seq: u32,
    dispatch: rsansible_wire::Message,
) -> Result<()> {
    write_frame(&mut conn.stream, &dispatch).await?;
    loop {
        let frame = read_frame(&mut conn.stream)
            .await?
            .ok_or_else(|| anyhow!("agent closed mid-task"))?;
        match frame {
            Message::TaskProgress(p) => {
                if p.seq != seq {
                    return Err(anyhow!("progress seq mismatch"));
                }
            }
            Message::TaskDone(d) => {
                if d.seq != seq {
                    return Err(anyhow!("done seq mismatch"));
                }
                if d.exit_code != 0 {
                    return Err(anyhow!("task exit {}", d.exit_code));
                }
                return Ok(());
            }
            Message::TaskError(e) => return Err(anyhow!("agent error: {}: {}", e.code, e.message)),
            _ => return Err(anyhow!("unexpected frame")),
        }
    }
}
