//! Basic per-host example: package + templated config + service that
//! reloads when the config changes. The "hello world" of declarative
//! infra — exercises every primitive without cross-host coordination.

use rsansible_declarative_spike::*;

/// A typed nginx config template. Real version would be:
///
/// ```ignore
/// #[derive(Template)]
/// #[template(source = "templates/nginx.conf.tmpl")]
/// struct NginxConf { server_name: String, worker_count: u32 }
/// ```
///
/// For the spike, we implement [`Template`] by hand and inline the
/// rendering. The point is to show the typed-fields-instead-of-Jinja
/// shape.
struct NginxConf {
    server_name: String,
    worker_count: u32,
}

impl Template for NginxConf {
    fn render(&self) -> Output<String> {
        Output::ready(format!(
            "worker_processes {};\n\
             events {{ worker_connections 1024; }}\n\
             http {{\n\
             \x20 server {{\n\
             \x20   listen 80;\n\
             \x20   server_name {};\n\
             \x20   root /var/www/html;\n\
             \x20 }}\n\
             }}\n",
            self.worker_count, self.server_name,
        ))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Spike inventory — real version would be Inventory::load("hosts.toml").
    let mut inv = Inventory::default();
    inv.add_host("web-1.example.com", "10.0.0.1");
    inv.add_host("web-2.example.com", "10.0.0.2");
    inv.add_to_group("web", "web-1.example.com");
    inv.add_to_group("web", "web-2.example.com");

    let plan = Plan::new();

    for host in inv.group("web") {
        let node = plan.node(host);

        let pkg = node.package(Package {
            name: "nginx".into(),
            state: PackageState::Present,
            become_: Some(BecomeUser::Root),
            ..Default::default()
        });

        let cfg = node.file(File {
            path: "/etc/nginx/nginx.conf".into(),
            content: NginxConf {
                server_name: host.name().to_string(),
                worker_count: 4,
            }
            .render(),
            owner: Some("root".into()),
            mode: Some(0o644),
            become_: Some(BecomeUser::Root),
            // Explicit edge: nginx package owns the default file at this
            // path, so we must come after the install. Future: module
            // footprint declarations would infer this.
            after: deps![pkg],
            ..Default::default()
        });

        node.service(Service {
            name: "nginx".into(),
            running: true,
            enabled: true,
            // The whole "handler / notify / flush_handlers" machinery
            // collapses into this one field.
            reload_on: deps![cfg],
            after: deps![pkg],
            become_: Some(BecomeUser::Root),
            ..Default::default()
        });
    }

    println!(
        "nginx plan: {} resources declared across 2 hosts",
        plan.resource_count()
    );
    Ok(())
}
