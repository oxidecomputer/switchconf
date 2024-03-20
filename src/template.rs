/*
 * Copyright 2024 Oxide Computer Company
 */

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::parse::*;

use anyhow::{anyhow, bail, Result};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateFile {
    cdp: Option<TemplateCdp>,
    lldp: Option<TemplateLldp>,
    bonjour: Option<TemplateBonjour>,
    snmp_server: Option<TemplateSnmpServer>,
    ssh_server: Option<TemplateSshServer>,
    logging: Option<TemplateLogging>,
    user: Option<BTreeMap<String, TemplateUser>>,
    interface: Option<TemplateInterface>,
    vlan: Option<BTreeMap<String, TemplateVlan>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateInterface {
    gigabit: Option<BTreeMap<String, TemplateGigabit>>,
    tengigabit: Option<BTreeMap<String, TemplateGigabit>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateInterfaceLldp {
    transmit: Option<bool>,
}

impl TemplateInterfaceLldp {
    fn transmit(&self) -> bool {
        self.transmit.unwrap_or(true)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateGigabit {
    enable: Option<bool>,
    desc: Option<String>,
    vlan: Option<String>,
    mode: Option<String>,
    power: Option<bool>,
    lldp: Option<TemplateInterfaceLldp>,
    stp: Option<bool>,
}

impl TemplateGigabit {
    fn enable(&self) -> bool {
        self.enable.unwrap_or(true)
    }

    fn mode(&self) -> Result<SwitchPortMode> {
        Ok(match self.mode.as_deref() {
            Some("access") | None => SwitchPortMode::Access,
            Some("trunk") => SwitchPortMode::Trunk,
            Some(other) => bail!("{other:?} is not a valid switchport mode"),
        })
    }

    fn vlan_name(&self) -> &str {
        self.vlan.as_deref().unwrap_or("default")
    }

    fn power(&self) -> bool {
        self.power.unwrap_or(true)
    }

    fn spanning_tree(&self) -> bool {
        self.stp.unwrap_or(true)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateVlan {
    enable: Option<bool>,
    id: u16,
    #[serde(default)]
    dhcp: bool,
}

impl TemplateVlan {
    fn enable(&self) -> bool {
        self.enable.unwrap_or(true)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateCdp {
    enable: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateLldp {
    enable: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateBonjour {
    enable: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateSnmpServer {
    enable: bool,
    community: Option<HashMap<String, TemplateSnmpCommunity>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateSnmpCommunity {
    readonly: bool,
    view: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateSshServer {
    enable: bool,
    auth: Option<TemplateSshServerAuth>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateSshServerAuth {
    pubkey: Option<TemplateSshServerPubkey>,
    password: Option<TemplateSshServerPassword>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateSshServerPassword {
    enable: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateSshServerPubkey {
    enable: bool,
    auto_login: Option<bool>,
}

impl TemplateSshServerPubkey {
    fn auto_login(&self) -> bool {
        /*
         * Auto-login is the behaviour people expect, so make it the default
         * once pubkey authentication is enabled.
         */
        self.auto_login.unwrap_or(self.enable)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateUser {
    privilege: u16,
    password: String,
    sshrsa: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateLogging {
    console: bool,
    syslog: Option<TemplateLoggingSyslog>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateLoggingSyslog {
    host: String,
    port: Option<u16>,
    facility: Option<String>,
    severity: Option<String>,
}

impl TemplateFile {
    pub fn apply(&self, config: &Config) -> Result<Vec<String>> {
        let mut out: Vec<String> = Vec::new();

        /*
         * If we don't deal with console logging first, the switch client may be
         * interrupted by bullshit log messages spraying all over the console
         * while we make configuration changes later.
         */
        if let Some(logging) = &self.logging {
            if logging.console != config.logging_console {
                let mut cmd = Vec::new();
                if !logging.console {
                    cmd.push("no");
                }
                cmd.push("logging console");

                out.push(cmd.join(" "));
            }

            if let Some(syslog) = &logging.syslog {
                let mut update = false;

                if Some(&syslog.host) != config.logging_syslog.host.as_ref()
                    && config.logging_syslog.host.is_some()
                {
                    out.push(format!("no logging host {}", syslog.host));
                    update = true;
                }

                let sport = syslog.port.unwrap_or(514).to_string();
                let sfac = syslog.facility.as_deref().unwrap_or("local7");
                let ssev = syslog.severity.as_deref().unwrap_or("debugging");

                if sport != config.logging_syslog.port
                    || sfac != config.logging_syslog.facility.as_str()
                    || ssev != config.logging_syslog.severity.as_str()
                {
                    update = true;
                }

                if update {
                    let mut cmd = Vec::new();
                    cmd.push("logging host");
                    cmd.push(syslog.host.as_str());
                    cmd.push("port");
                    cmd.push(&sport);
                    cmd.push("facility");
                    cmd.push(sfac);
                    cmd.push("severity");
                    cmd.push(ssev);

                    out.push(cmd.join(" "));
                }
            } else {
                if let Some(host) = &config.logging_syslog.host {
                    out.push(format!("no logging host {host}"));
                }
            }
        }

        /*
         * Always disable as much of the password complexity and aging
         * management as we can.  It only gets in the way.
         */
        if config.passwords.aging != 0 {
            out.push("passwords aging 0".into());
        }

        if let Some(cdp) = &self.cdp {
            if cdp.enable != config.cdp {
                if cdp.enable {
                    out.push("cdp run".into());
                } else {
                    out.push("no cdp run".into());
                }
            }
        }

        if let Some(lldp) = &self.lldp {
            if lldp.enable != config.lldp {
                if lldp.enable {
                    out.push("lldp run".into());
                } else {
                    out.push("no lldp run".into());
                }
            }
        }

        if let Some(bonjour) = &self.bonjour {
            if bonjour.enable != config.bonjour.enable {
                if bonjour.enable {
                    out.push("bonjour enable".into());
                } else {
                    out.push("no bonjour enable".into());
                }
            }
        }

        if let Some(snmp) = &self.snmp_server {
            if config.snmp_server.enable != snmp.enable && !snmp.enable {
                out.push("no snmp-server server".into());
            }

            /*
             * Eliminate any communities that do not appear in the template now.
             */
            for k in config.snmp_server.community.keys() {
                if let Some(sc) = &snmp.community {
                    if !sc.contains_key(k) {
                        out.push(format!("no snmp-server community {k}"));
                    }
                }
            }

            if let Some(sc) = &snmp.community {
                for (k, v) in sc.iter() {
                    let flush = if let Some(ext) =
                        config.snmp_server.community.get(k)
                    {
                        let view = v.view.as_deref().unwrap_or("Default");

                        /*
                         * This community already exists.  Check the
                         * configuration now.
                         */
                        ext.view.as_deref() != Some(view)
                            || ext.readonly != v.readonly
                    } else {
                        /*
                         * The community does not exist so just create it.
                         */
                        true
                    };

                    if flush {
                        let mut cmd = format!("snmp-server community {k}");

                        if v.readonly {
                            cmd.push_str(" ro");
                        } else {
                            bail!("only readonly SNMP communities right now");
                        }

                        if let Some(view) = &v.view {
                            cmd.push_str(&format!(" view {view}"));
                        }

                        out.push(cmd);
                    }
                }
            }

            if config.snmp_server.enable != snmp.enable && snmp.enable {
                out.push("snmp-server server".into());
            }
        }

        if let Some(user) = &self.user {
            /*
             * Create or update any users from the template:
             */
            for (n, u) in user.iter() {
                let update = if let Some(ex) = config.users.get(n) {
                    /*
                     * This user already exists in the configuration.
                     */
                    ex.privilege != u.privilege
                        || ex.password_encrypted != u.password
                } else {
                    /*
                     * This user does not exist at all yet.
                     */
                    true
                };

                if update {
                    out.push(format!(
                        "username {n} password encrypted {} privilege {}",
                        u.password, u.privilege,
                    ));
                }
            }

            let mut in_key_mode = false;

            /*
             * Remove any SSH keys that should not be present on the system.
             */
            for n in config.user_ssh_keys.keys() {
                if let Some(user) = user.get(n) {
                    if user.sshrsa.is_some() {
                        /*
                         * This user is present, and has _some_ SSH key.  We'll
                         * fix it up in the subsequent pass if it is wrong.
                         */
                        continue;
                    }
                }

                if !in_key_mode {
                    out.push("crypto key pubkey-chain ssh".into());
                    in_key_mode = true;
                }

                out.push(format!("no user-key {n}"));
            }

            /*
             * Add or update any SSH keys that do not match our expectations.
             */
            for (n, u) in user.iter() {
                let Some(rsa) = u.sshrsa.as_deref() else {
                    continue;
                };

                let update = if let Some(ka) = config.user_ssh_keys.get(n) {
                    let ex = ka.iter().map(String::as_str).collect::<String>();
                    rsa != ex
                } else {
                    true
                };

                if update {
                    if !in_key_mode {
                        out.push("crypto key pubkey-chain ssh".into());
                        in_key_mode = true;
                    }

                    out.push(format!("user-key {n} rsa"));
                    for ch in rsa.chars().collect::<Vec<char>>().chunks(80) {
                        let row = ch.iter().collect::<String>();
                        out.push(format!("key-string row {row}"));
                    }
                    out.push("exit".into());
                }
            }

            if in_key_mode {
                out.push("exit".into());
            }

            /*
             * Remove any users that exist on the system but are not expected:
             */
            for n in config.users.keys() {
                if user.contains_key(n) {
                    continue;
                }

                out.push(format!("no username {n}"));
            }
        }

        if let Some(ssh) = &self.ssh_server {
            if ssh.enable && !config.ssh_server.enable {
                out.push("ip ssh server".into());
            }

            if let Some(auth) = &ssh.auth {
                if let Some(pubkey) = &auth.pubkey {
                    if pubkey.enable != config.ssh_server.pubkey_auth
                        || pubkey.auto_login()
                            != config.ssh_server.pubkey_auto_login
                    {
                        let mut cmd = Vec::new();
                        if !pubkey.enable {
                            cmd.push("no");
                        }
                        cmd.push("ip ssh pubkey-auth");
                        if pubkey.enable && pubkey.auto_login() {
                            cmd.push("auto-login");
                        }

                        out.push(cmd.join(" "));
                    }
                }

                if let Some(password) = &auth.password {
                    if password.enable != config.ssh_server.password_auth {
                        let mut cmd = Vec::new();
                        if !password.enable {
                            cmd.push("no");
                        }
                        cmd.push("ip ssh password-auth");

                        out.push(cmd.join(" "));
                    }
                }
            }

            if !ssh.enable && config.ssh_server.enable {
                if config.ssh_server.pubkey_auth {
                    out.push("no ip ssh pubkey-auth".into());
                }
                if config.ssh_server.password_auth {
                    out.push("no ip ssh password-auth".into());
                }
                out.push("no ip ssh server".into());
            }
        }

        /*
         * We don't ever want the voice VLAN stuff, so just turn it off.
         */
        if !matches!(config.voice_vlan.state, VoiceVlanState::Disabled) {
            out.push("voice vlan state disabled".into());
        }

        /*
         * We don't want the Smartport Macro stuff either.
         */
        if !matches!(config.smartports.state, SmartportsState::Disabled) {
            out.push("macro auto disabled".into());
        }

        if let Some(vlans) = &self.vlan {
            /*
             * First, determine if there are any VLANs that we need to tear
             * down.
             */
            let remove: BTreeSet<u16> = config
                .vlans
                .iter()
                .filter(|&&vext| !vlans.values().any(|vl| vl.id == vext))
                .cloned()
                .collect();

            /*
             * And any VLANs that are not yet in the database on the switch:
             */
            let add: BTreeSet<u16> = vlans
                .values()
                .map(|vl| vl.id)
                .filter(|vwant| !config.vlans.contains(vwant))
                .collect();

            if !remove.is_empty() || !add.is_empty() {
                out.push("vlan database".into());
                for r in remove {
                    /*
                     * In limited testing, this directive appears to be enough
                     * to drop at least some of the configuration directives
                     * from an "interface vlan N" section.  If that turns out
                     * not to be true we may have to do more work here.
                     */
                    out.push(format!("no vlan {r}"));
                }
                if !add.is_empty() {
                    out.push(format!("vlan {}", print_id_list(&add)));
                }
                out.push("exit".into());
            }

            /*
             * Now that the VLAN database has been populated, check the rest of
             * the per-VLAN configuration.
             */
            for (name, vlan) in vlans {
                let mut fix_name = false;
                let mut fix_dhcp = false;
                let mut fix_shutdown = false;

                if let Some(ext) =
                    config.interfaces.get(&Interface::Vlan(vlan.id))
                {
                    if vlan.id == 1 {
                        assert_eq!(name, "default");
                        /*
                         * Do not put a name on the default VLAN.
                         */
                        if ext.name.is_some() {
                            fix_name = true;
                        }
                    } else if ext.name.as_deref() != Some(name.as_str()) {
                        fix_name = true;
                    }

                    if ext.dhcp != vlan.dhcp {
                        fix_dhcp = true;
                    }

                    if vlan.enable() == ext.shutdown {
                        fix_shutdown = true;
                    }
                } else {
                    if vlan.id != 1 {
                        fix_name = true;
                    }
                    if !vlan.enable() {
                        fix_shutdown = true;
                    }
                    fix_dhcp = true;
                }

                if fix_name || fix_dhcp {
                    out.push(format!("interface vlan {}", vlan.id));
                    if fix_name {
                        if vlan.id == 1 {
                            out.push("no name".into());
                        } else {
                            out.push(format!("name {name}"));
                        }
                    }
                    if fix_dhcp {
                        let mut s =
                            if vlan.dhcp { "" } else { "no " }.to_string();
                        s.push_str("ip address dhcp");
                        out.push(s);
                    }
                    if fix_shutdown {
                        let mut s =
                            if vlan.enable() { "" } else { "no " }.to_string();
                        s.push_str("shutdown");
                        out.push(s);
                    }
                    out.push("exit".into());
                }
            }
        }

        if let Some(gi) =
            self.interface.as_ref().and_then(|ifs| ifs.gigabit.as_ref())
        {
            out.extend(
                self.configure_interfaces(config, "gi", gi, false)?.into_iter(),
            );
        }

        if let Some(te) =
            self.interface.as_ref().and_then(|ifs| ifs.tengigabit.as_ref())
        {
            out.extend(
                self.configure_interfaces(config, "te", te, true)?.into_iter(),
            );
        }

        Ok(out)
    }

    pub fn configure_interfaces(
        &self,
        config: &Config,
        pfx: &str,
        ifaces: &BTreeMap<String, TemplateGigabit>,
        tengig: bool,
    ) -> Result<Vec<String>> {
        let mut out = Vec::new();

        /*
         * For now, we just configure interfaces specified in the template.  If
         * there are interfaces on the switch that are not covered by the
         * template, we ignore them.
         */
        for (n, gi) in ifaces {
            let mut sout = Vec::new();
            let n: u16 = n.parse().unwrap();

            let def;
            let ext = if let Some(ext) = if tengig {
                config.interfaces.get(&Interface::TenGigabit(n))
            } else {
                config.interfaces.get(&Interface::Gigabit(n))
            } {
                ext
            } else {
                def = Default::default();
                &def
            };

            let tv = self.vlan.as_ref().unwrap().get(gi.vlan_name()).unwrap();
            let gimode = gi.mode()?;

            if !gi.enable() && !ext.shutdown {
                sout.push("shutdown".into());
            }

            if gi.desc != ext.description {
                if let Some(desc) = gi.desc.as_deref() {
                    sout.push(format!("description {desc:?}"));
                } else {
                    sout.push("no description".into());
                }
            }

            /*
             * Prepare for the mode switch.  It is particularly critical
             * that we keep the same native VLAN across the change.
             */
            match gimode {
                SwitchPortMode::Access => {
                    if ext.access_vlan != tv.id {
                        sout.push(format!("switchport access vlan {}", tv.id,));
                    }
                }
                SwitchPortMode::Trunk => {
                    if ext.trunk_native_vlan != tv.id {
                        sout.push(format!(
                            "switchport trunk native vlan {}",
                            tv.id,
                        ));
                    }

                    /*
                     * XXX Right now we want to allow all VLANs throughout
                     * the entire fabric, but in future we will want to be
                     * able to configure the trunk allow list.
                     */
                    let all_vlans = self
                        .vlan
                        .as_ref()
                        .map(|vl| {
                            vl.values().map(|tv| tv.id).collect::<BTreeSet<_>>()
                        })
                        .unwrap_or_default();

                    let set = if let Some(tav) = &ext.trunk_allowed_vlans {
                        tav != &all_vlans
                    } else {
                        true
                    };

                    if set {
                        sout.push(format!(
                            "switchport trunk allowed vlan {}",
                            print_id_list(&all_vlans),
                        ));
                    }
                }
            }

            /*
             * Change the mode now.  This may impact connectivity.
             */
            if gimode != ext.mode {
                sout.push(format!("switchport mode {}", gimode));
            }

            /*
             * After the mode switch, we can clean up detritus from the mode
             * that is now no longer configured.
             */
            match gimode {
                SwitchPortMode::Access => {
                    if ext.trunk_native_vlan != 1 {
                        sout.push("no switchport trunk native vlan".into());
                    }

                    if ext.trunk_allowed_vlans.is_some() {
                        sout.push("no switchport trunk allowed vlan".into());
                    }
                }
                SwitchPortMode::Trunk => {
                    if ext.access_vlan != 1 {
                        sout.push("no switchport access vlan".into());
                    }
                }
            }

            let want_lldp_transmit =
                gi.lldp.as_ref().map(|lldp| lldp.transmit()).unwrap_or(true);

            if want_lldp_transmit != ext.lldp.transmit {
                sout.push(format!(
                    "{}lldp transmit",
                    if !want_lldp_transmit { "no " } else { "" }
                ));
            }

            if gi.spanning_tree() != ext.spanning_tree.enable {
                sout.push(format!(
                    "{}spanning-tree disable",
                    if gi.spanning_tree() { "no " } else { "" },
                ));
            }

            /*
             * We do not presently configure IP addresses directly on any
             * (ten)gigabit interfaces.
             */
            if ext.dhcp {
                sout.push("no ip address dhcp".into());
            }

            if gi.enable() && ext.shutdown {
                sout.push("no shutdown".into());
            }

            /*
             * Enable or disable power-over-ethernet for this port.
             */
            if gi.power() {
                if ext.power.inline != PowerInline::Auto {
                    sout.push("power inline auto".into());
                }
            } else {
                if ext.power.inline != PowerInline::Never {
                    sout.push("power inline never".into());
                }
            }

            if !sout.is_empty() {
                out.push(format!("interface {pfx}{n}"));
                for s in sout {
                    out.push(s);
                }
                out.push("exit".into());
            }
        }

        Ok(out)
    }
}

pub fn check_interfaces(
    pfx: &str,
    ifaces: &BTreeMap<String, TemplateGigabit>,
    max: u16,
    t: &TemplateFile,
) -> Result<()> {
    for (n, gi) in ifaces {
        /*
         * Because TOML sucks, keys in tables must be strings.  In the case of
         * gigabit and ten gigabit interfaces, they must really be numbers.
         * Confirm now that each specified instance is a number of appropriate
         * size.
         */
        let nn: u16 = n
            .parse()
            .map_err(|e| anyhow!("{n:?} is not a valid {pfx} number: {e}"))?;
        if nn > max {
            bail!("{pfx}{nn} is too high an interface number");
        }

        gi.mode()?;

        if let Some(vlan) = gi.vlan.as_deref() {
            if !t
                .vlan
                .as_ref()
                .map(|vlans| vlans.contains_key(vlan))
                .unwrap_or(false)
            {
                bail!("{pfx}{n}: template does not include VLAN {vlan:?}");
            }
        }
    }

    Ok(())
}

pub fn load(name: &str) -> Result<TemplateFile> {
    let f = std::fs::read_to_string(name)?;
    let t: TemplateFile = toml::from_str(&f)?;

    /*
     * Perform some consistency checks on interfaces and VLANs.
     */
    if let Some(vlans) = &t.vlan {
        let mut vids = HashSet::new();

        if !vlans.contains_key("default") {
            bail!("default VLAN must be specified");
        }

        for (n, vlan) in vlans.iter() {
            if !vids.insert(vlan.id) {
                bail!("VLAN id {} appears to be a duplicate", vlan.id);
            }

            if (n == "default" && vlan.id != 1)
                || (n != "default" && vlan.id == 1)
            {
                bail!("one may only use the name \"default\" for VLAN 1");
            }
        }
    }

    if let Some(iface) = &t.interface {
        if let Some(gi) = &iface.gigabit {
            /*
             * Different switches have different numbers of gigabit
             * ports, but none of the ones we care about have more than
             * 64.
             */
            check_interfaces("gi", gi, 64, &t)?;
        }
        if let Some(te) = &iface.tengigabit {
            /*
             * Different switches have different numbers of gigabit
             * ports, but none of the ones we care about have more than
             * 64.
             */
            check_interfaces("te", te, 4, &t)?;
        }
    }

    Ok(t)
}
