/*
 * Copyright 2025 Oxide Computer Company
 */

use std::time::Duration;
use std::{sync::Arc, time::Instant};

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use hiercmd::prelude::*;
use russh::*;
use russh_keys::*;

mod config;
mod parse;
mod template;
mod terminal;
mod vlan;

#[derive(Default)]
struct Stuff {
    config: Option<config::ConfigFile>,
}

impl Stuff {
    fn config(&self) -> &config::ConfigFile {
        self.config.as_ref().unwrap()
    }
}

struct SwitchClient {
    tx: tokio::sync::mpsc::Sender<(
        String,
        tokio::sync::oneshot::Sender<std::result::Result<String, String>>,
    )>,
}

impl SwitchClient {
    async fn new(s: &Stuff, name: &str) -> Result<SwitchClient> {
        let cfs = s.config().switch(name)?;

        let config = Arc::new(russh::client::Config {
            preferred: Preferred {
                kex: &[kex::DH_G14_SHA1],
                key: &[key::SSH_RSA],
                ..Default::default()
            },
            ..Default::default()
        });

        let sh = SwitchClientInner {};

        let mut session =
            russh::client::connect(config, (cfs.ip(), 22), sh).await?;

        if session.authenticate_password(cfs.username(), cfs.password()).await?
        {
            println!("INFO: authenticated");
        } else {
            bail!("INFO: not authenticated?");
        }

        let mut channel = session.channel_open_session().await?;

        /*
         * Unfortunately the CLI requires a PTY, and has no way to avoid drawing
         * console characters.
         */
        println!("requesting pty...");
        channel.request_pty(true, "dumb", 80, 25, 8 * 80, 12 * 25, &[]).await?;

        if let Some(msg) = channel.wait().await {
            println!("INFO: from channel: {:?}", msg)
        } else {
            bail!("EOC?");
        }

        println!("requesting shell...");
        channel.request_shell(true).await?;

        if let Some(msg) = channel.wait().await {
            println!("INFO: from channel: {:?}", msg)
        } else {
            bail!("EOC?");
        }

        /*
         * Create the channel that async callers will use to request execution
         * of a command.
         */
        let (tx, rx) = tokio::sync::mpsc::channel(16);

        let swc = SwitchClient { tx };

        tokio::spawn(async {
            switch_client_task(rx, channel).await;
        });

        /*
         * Execute these commands at the start of each session with the switch
         * in an attempt to get any terminal handling out of the way:
         */
        for cmd in
            ["terminal no prompt", "terminal width 0", "terminal datadump"]
        {
            swc.exec(cmd).await?;
        }

        Ok(swc)
    }

    async fn exec(&self, cmd: &str) -> Result<String> {
        let (tx, rx) = tokio::sync::oneshot::channel::<
            std::result::Result<String, String>,
        >();

        self.tx.send((cmd.into(), tx)).await.unwrap();

        Ok(rx.await.unwrap().map_err(|e| anyhow!("exec error: {e}"))?)
    }
}

async fn switch_client_task_turn(
    cmd: &str,
    t: &mut terminal::Terminal,
    channel: &mut Channel<russh::client::Msg>,
    exit_ready: &mut bool,
) -> Result<String> {
    let timeo = Duration::from_millis(50);
    let mut last_activity = Instant::now();

    let mut sent = false;

    loop {
        let idle =
            Instant::now().saturating_duration_since(last_activity).as_millis();

        match tokio::time::timeout(timeo, channel.wait()).await {
            Ok(Some(msg)) => {
                match msg {
                    ChannelMsg::Data { data } => {
                        last_activity = Instant::now();

                        t.ingest(&data);
                        loop {
                            if !t.process()? {
                                break;
                            }
                        }
                    }
                    other => {
                        println!("INFO: other from channel: {:?}", other);
                    }
                }
                continue;
            }
            Ok(None) => {
                if *exit_ready {
                    return Ok("".into());
                }

                bail!("early EOC!");
            }
            Err(_) => {
                if !t.at_prompt() {
                    if idle > 5 * 1000 {
                        println!(
                            " * waiting for prompt [have: {:?}]...",
                            t.peek_prompt()
                        );
                    }
                    continue;
                }

                if !sent {
                    println!(" * sending command: {cmd:?}");
                    t.start_command(&cmd)?;
                    channel.data(&cmd.as_bytes()[..]).await?;
                    channel.data(&b"\n"[..]).await?;
                    sent = true;
                }

                if t.has_output() {
                    return Ok(format!("{}\n", t.take_output()?.join("\n")));
                }
            }
        }
    }
}

async fn switch_client_task(
    mut rx: tokio::sync::mpsc::Receiver<(
        String,
        tokio::sync::oneshot::Sender<std::result::Result<String, String>>,
    )>,
    mut channel: Channel<russh::client::Msg>,
) {
    let mut t = terminal::Terminal::new();

    let mut exit_ready = false;
    loop {
        /*
         * Wait until we are told what to do.
         */
        let Some((cmd, reply)) = rx.recv().await else {
            /*
             * A receive failure here generally means the switch client was
             * dropped.
             */
            return;
        };

        match switch_client_task_turn(
            &cmd,
            &mut t,
            &mut channel,
            &mut exit_ready,
        )
        .await
        {
            Ok(out) => reply.send(Ok(out)).ok(),
            Err(e) => reply.send(Err(e.to_string())).ok(),
        };
    }
}

struct SwitchClientInner {}

#[async_trait]
impl client::Handler for SwitchClientInner {
    type Error = anyhow::Error;

    async fn check_server_key(
        self,
        _server_public_key: &key::PublicKey,
    ) -> Result<(Self, bool), Self::Error> {
        Ok((self, true))
    }
}

async fn dump_config(s: &Stuff, name: &str) -> Result<String> {
    let swc = SwitchClient::new(s, name).await?;

    Ok(swc.exec("show running-config").await?)
}

async fn do_macs(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("SWITCH..."));

    let a = args!(l);
    if a.args().is_empty() {
        bad_args!(l, "specify a switch to dump");
    }

    for name in a.args() {
        let swc = SwitchClient::new(l.context(), name).await?;

        println!("{}", swc.exec("show mac address-table").await?);
        println!();
    }

    Ok(())
}

async fn do_dump(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("SWITCH..."));
    l.optopt("o", "", "output config to file", "FILE");

    let a = args!(l);
    if a.args().is_empty() {
        bad_args!(l, "specify a switch to dump");
    }

    if a.opts().opt_present("o") && a.args().len() > 1 {
        bad_args!(l, "-o only works with one switch");
    }

    for name in a.args() {
        let cfg = dump_config(l.context(), &name).await?;

        if let Some(o) = a.opts().opt_str("o") {
            std::fs::write(&o, &cfg)?;
            return Ok(());
        }

        println!("{name:?} CONFIG:");
        println!("{cfg}");
        println!("-------------");
        println!();
    }

    Ok(())
}

async fn do_apply(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("SWITCH..."));

    l.reqopt("A", "", "apply a template file", "TEMPLATE");
    l.optopt("V", "", "use VLAN database file", "VLAN_DB");
    l.optflag("n", "", "dry run only");
    l.optflag("v", "", "verbose output");
    l.optflag("p", "", "make configuration persistent");

    let a = args!(l);
    if a.args().is_empty() {
        bad_args!(l, "specify a switch for template application");
    }

    let dryrun = a.opts().opt_present("n");
    let persist = a.opts().opt_present("p");
    let verbose = a.opts().opt_present("v");

    let vldb = if let Some(vlp) = a.opts().opt_str("V") {
        vlan::VlanDatabase::load(&vlp)?
    } else {
        vlan::VlanDatabase::default()
    };

    let tpl = template::load(&a.opts().opt_str("A").unwrap(), &vldb)?;

    for name in a.args() {
        let swc = SwitchClient::new(l.context(), name).await?;

        let raw = swc.exec("show running-config").await?;
        let cfg = parse::Config::parse(
            raw.split('\n').collect::<Vec<_>>().as_slice(),
        )?;

        if verbose {
            println!("{name:?} CONFIG:");
            println!("{cfg:#?}");
        }
        println!();

        let cmds = tpl.apply(&cfg, &vldb)?;
        if !cmds.is_empty() {
            if dryrun {
                print!("would run these ");
            }
            println!("update commands:");
            for cmd in &cmds {
                println!("    {cmd}");
            }
        } else {
            println!("no update commands needed");
        }

        if !cmds.is_empty() && !dryrun {
            swc.exec("config terminal").await?;

            for cmd in &cmds {
                let out = swc.exec(&cmd).await?;
                if !out.trim().is_empty() {
                    bail!("unexpected command output: {out:?}");
                }
            }

            swc.exec("exit").await?;
        }

        if persist && !dryrun {
            let out = swc.exec("write").await?;
            if out.trim() != "Copy succeeded" {
                bail!("unexpected command output: {out:?}");
            }
        }

        println!("-------------");
        println!();
    }

    Ok(())
}

async fn do_parse(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("FILE..."));

    l.optopt(
        "A",
        "",
        "apply a template file and generate commands",
        "TEMPLATE",
    );
    l.optopt("V", "", "use VLAN database file", "VLAN_DB");

    let a = args!(l);
    if a.args().is_empty() {
        bad_args!(l, "specify a file to parse");
    }

    let vldb = if let Some(vlp) = a.opts().opt_str("V") {
        vlan::VlanDatabase::load(&vlp)?
    } else {
        vlan::VlanDatabase::default()
    };

    let tpl = if let Some(tp) = a.opts().opt_str("A") {
        Some(template::load(&tp, &vldb)?)
    } else {
        None
    };

    for name in a.args() {
        let f = std::fs::read_to_string(&name)?;

        let cfg =
            parse::Config::parse(f.lines().collect::<Vec<_>>().as_slice())?;

        println!("{name:?} CONFIG:");
        println!("{cfg:#?}");
        println!();

        if let Some(tpl) = &tpl {
            let cmds = tpl.apply(&cfg, &vldb)?;
            if !cmds.is_empty() {
                println!("update commands:");
                for cmd in &cmds {
                    println!("    {cmd}");
                }
            } else {
                println!("no update commands needed");
            }
        }

        println!("-------------");
        println!();
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut l = Level::new("switchconf", Stuff::default());

    l.cmd("dump", "dump configuration files from switches", cmd!(do_dump))?;
    l.cmd("parse", "parse a config file", cmd!(do_parse))?;
    l.cmd("apply", "apply a template to a switch", cmd!(do_apply))?;
    l.cmd("macs", "dump MAC address table", cmd!(do_macs))?;

    l.context_mut().config = Some(config::load()?);

    env_logger::init();

    sel!(l).run().await
}
