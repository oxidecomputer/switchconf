/*
 * Copyright 2023 Oxide Computer Company
 */

use std::{collections::HashMap, ops::RangeBounds};
#[allow(unused_imports)]
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    ops::RangeInclusive,
};

use anyhow::{anyhow, bail, Result};

#[derive(Debug)]
enum State {
    Rest,
    Header,
    SsdControl,
    UnitTypeControl,
    General,
    VlanDatabase,
    CryptoKeys,
    UserKey(String),
    Interface(Interface),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Interface {
    Vlan(u16),
    Gigabit(u16),
    TenGigabit(u16),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SwitchPortMode {
    Access,
    Trunk,
}

impl std::fmt::Display for SwitchPortMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                SwitchPortMode::Access => "access",
                SwitchPortMode::Trunk => "trunk",
            }
        )
    }
}

#[derive(Debug, Clone)]
pub struct InterfaceConfig {
    pub shutdown: bool,
    pub mode: SwitchPortMode,
    pub access_vlan: u16,
    pub trunk_native_vlan: u16,
    pub trunk_allowed_vlans: Option<BTreeSet<u16>>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub dhcp: bool,
}

impl Default for InterfaceConfig {
    fn default() -> Self {
        InterfaceConfig {
            shutdown: false,
            mode: SwitchPortMode::Access,
            access_vlan: 1,
            trunk_native_vlan: 1,
            trunk_allowed_vlans: None,
            name: None,
            description: None,
            dhcp: false,
        }
    }
}

#[allow(unused)]
#[derive(Debug)]
pub struct UserConfig {
    pub privilege: u16,
    pub password_encrypted: String,
}

impl From<Parser> for Config {
    fn from(p: Parser) -> Self {
        let Parser {
            state: _,
            iface: _,
            keyrows: _,

            header,
            ssd_control,
            unit_type_control,
            user_ssh_keys,
            interfaces,
            vlans,
            pnp,
            cdp,
            lldp,
            hostname,
            logging_console,
            users,
            bonjour,
            snmp_server,
            ssh_server,
            voice_vlan,
            passwords,
            smartports,
        } = p;

        Config {
            header,
            ssd_control,
            unit_type_control,
            user_ssh_keys,
            interfaces,
            vlans,
            pnp,
            cdp,
            lldp,
            hostname,
            logging_console,
            users,
            bonjour,
            snmp_server,
            ssh_server,
            voice_vlan,
            passwords,
            smartports,
        }
    }
}

#[allow(unused)]
#[derive(Debug)]
pub struct SnmpServer {
    pub enable: bool,
    pub community: HashMap<String, SnmpCommunity>,
}

#[allow(unused)]
#[derive(Debug)]
pub struct SnmpCommunity {
    pub readonly: bool,
    pub view: Option<String>,
}

#[allow(unused)]
#[derive(Debug)]
pub struct SshServer {
    pub enable: bool,
    pub password_auth: bool,
    pub pubkey_auth: bool,
    pub pubkey_auto_login: bool,
}

#[allow(unused)]
#[derive(Debug)]
pub struct Bonjour {
    pub enable: bool,
    pub vlans: BTreeSet<u16>,
}

#[derive(Debug)]
pub struct Passwords {
    pub aging: u16,
}

#[derive(Debug)]
pub enum SmartportsState {
    Disabled,
    Enabled,
    Controlled,
}

#[allow(unused)]
#[derive(Debug)]
pub struct Smartports {
    pub state: SmartportsState,
}

#[derive(Debug)]
pub enum VoiceVlanState {
    Disabled,
    OuiEnabled,
    AutoTriggered,
    AutoEnabled,
}

#[allow(unused)]
#[derive(Debug)]
pub struct VoiceVlan {
    pub state: VoiceVlanState,
    pub oui_table: BTreeMap<String, String>,
}

struct Parser {
    state: State,
    header: Vec<String>,
    ssd_control: Vec<String>,
    unit_type_control: Vec<String>,
    iface: Option<InterfaceConfig>,
    keyrows: Option<Vec<String>>,
    user_ssh_keys: BTreeMap<String, Vec<String>>,
    vlans: BTreeSet<u16>,
    interfaces: BTreeMap<Interface, InterfaceConfig>,
    pnp: bool,
    cdp: bool,
    lldp: bool,
    hostname: String,
    logging_console: bool,
    users: BTreeMap<String, UserConfig>,
    snmp_server: SnmpServer,
    ssh_server: SshServer,
    bonjour: Bonjour,
    voice_vlan: VoiceVlan,
    passwords: Passwords,
    smartports: Smartports,
}

impl Default for Parser {
    fn default() -> Self {
        Parser {
            state: State::Rest,
            header: Default::default(),
            ssd_control: Default::default(),
            unit_type_control: Default::default(),
            iface: None,
            keyrows: None,
            user_ssh_keys: Default::default(),
            interfaces: Default::default(),
            vlans: [1].into_iter().collect(),
            pnp: true,
            cdp: true,
            lldp: true,
            hostname: "".into(),
            logging_console: true,
            users: Default::default(),
            bonjour: Bonjour { enable: true, vlans: [1].into_iter().collect() },
            snmp_server: SnmpServer {
                enable: false,
                community: Default::default(),
            },
            ssh_server: SshServer {
                enable: false,
                password_auth: false,
                pubkey_auth: false,
                pubkey_auto_login: false,
            },
            voice_vlan: VoiceVlan {
                state: VoiceVlanState::Disabled,
                oui_table: Default::default(),
            },
            /*
             * The manual says that the default is passwords aging enabled for
             * 180 days, but it does not seem like this is universally true.
             * Experimentally, using "no passwords aging" disables passwords
             * aging, and then nothing appears in the file; the same with
             * "passwords aging 0" which is what the manual says to do.
             *
             * Hopefuly we will not need to probe "show passwords configuration"
             * to find out the real story.
             */
            passwords: Passwords { aging: 0 },
            smartports: Smartports { state: SmartportsState::Disabled },
        }
    }
}

fn parse_id_list(list: &str) -> Result<Vec<RangeInclusive<u16>>> {
    Ok(list
        .split(',')
        .map(|t| {
            if let Some((first, last)) = t.split_once('-') {
                Ok((first.parse::<u16>()?, last.parse::<u16>()?))
            } else {
                let n = t.parse::<u16>()?;
                Ok((n, n))
            }
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .map(|(f, l)| (f..=l))
        .collect())
}

fn explode_id_list(list: &[RangeInclusive<u16>]) -> BTreeSet<u16> {
    let mut out: BTreeSet<u16> = Default::default();

    for range in list {
        for n in range.clone().into_iter() {
            out.insert(n);
        }
    }

    out
}

fn compact_id_list(list: &BTreeSet<u16>) -> Vec<RangeInclusive<u16>> {
    let mut hi = None;
    let mut lo = None;
    let mut ids = list.iter();
    let mut out = Vec::new();

    loop {
        let id = ids.next();

        if let Some(&id) = id {
            if let Some(curhi) = hi {
                assert!(id > curhi);
                if id == curhi + 1 {
                    hi = Some(id);
                } else {
                    out.push(lo.take().unwrap()..=hi.take().unwrap());
                    lo = Some(id);
                    hi = Some(id);
                }
                continue;
            }

            hi = Some(id);
            lo = Some(id);
            continue;
        }

        if hi.is_some() {
            out.push(lo.take().unwrap()..=hi.take().unwrap());
        }
        break;
    }

    out
}

pub fn print_id_list(list: &BTreeSet<u16>) -> String {
    compact_id_list(list)
        .into_iter()
        .map(|r| {
            let lo = match r.start_bound() {
                std::ops::Bound::Included(&i) => i.to_string(),
                std::ops::Bound::Excluded(&e) => {
                    (e as u32).checked_add(1).unwrap().to_string()
                }
                std::ops::Bound::Unbounded => {
                    panic!("no unbounded ranges allowed")
                }
            };

            let hi = match r.end_bound() {
                std::ops::Bound::Included(&i) => i.to_string(),
                std::ops::Bound::Excluded(&e) => {
                    (e as u32).checked_sub(1).unwrap().to_string()
                }
                std::ops::Bound::Unbounded => {
                    panic!("no unbounded ranges allowed")
                }
            };

            if lo == hi {
                lo
            } else {
                format!("{lo}-{hi}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

impl Parser {
    fn commit_interface(&mut self) -> Result<()> {
        if let State::Interface(oldiface) = self.state {
            if let Some(cfg) = self.iface.take() {
                self.interfaces.insert(oldiface, cfg);
            } else {
                /*
                 * This should probably not happen.
                 */
                self.interfaces.remove(&oldiface);
            }
        }

        Ok(())
    }

    fn new_interface(&mut self, iface: Interface) -> Result<()> {
        /*
         * If we are already configuring an interface, persist the configuration
         * for that now:
         */
        self.commit_interface()?;

        /*
         * Set up the new interface.
         */
        self.iface = Some(Default::default());
        if let Interface::Vlan(1) = iface {
            /*
             * The management VLAN appears to have DHCP enabled by default.
             */
            self.iface.as_mut().unwrap().dhcp = true;
        }
        self.state = State::Interface(iface);
        Ok(())
    }

    fn line_username(&mut self, no: bool, ww: &Vec<String>) -> Result<()> {
        if no || ww.len() < 2 {
            bail!("username: {no:?} {ww:?}");
        }

        let username = ww[1].to_string();
        let mut privilege = None;
        let mut password_encrypted = None;

        let mut wi = ww.iter().skip(2);
        loop {
            match wi.next().map(String::as_str) {
                Some("password") => match wi.next().map(String::as_str) {
                    Some("encrypted") => {
                        if let Some(pe) = wi.next() {
                            password_encrypted = Some(pe.to_string());
                        } else {
                            bail!("username: {no:?} {ww:?}");
                        }
                    }
                    _ => {
                        bail!("username: {no:?} {ww:?}");
                    }
                },
                Some("privilege") => {
                    if let Some(pri) = wi.next() {
                        privilege = Some(pri.to_string());
                    } else {
                        bail!("username: {no:?} {ww:?}");
                    }
                }
                Some(_) => bail!("username: {no:?} {ww:?}"),
                None => break,
            }
        }

        let Some(password_encrypted) = password_encrypted else {
            bail!("username: {no:?} {ww:?}");
        };

        let privilege: u16 = if let Some(p) = privilege {
            p.parse().map_err(|e| anyhow!("invalid privilege: {ww:?}: {e}"))?
        } else {
            1
        };

        self.users
            .insert(username, UserConfig { privilege, password_encrypted });

        Ok(())
    }

    fn line_snmp_server(&mut self, no: bool, ww: &Vec<String>) -> Result<()> {
        if ww.len() == 2 && ww[1] == "server" {
            self.snmp_server.enable = !no;
            return Ok(());
        }

        if no {
            bail!("snmp-server: unexpected no");
        }

        if ww.len() >= 3 && ww[1] == "community" {
            let community = ww[2].to_string();
            let readonly = true;
            let mut view = Some("Default".to_string());

            let mut wi = ww.iter().skip(3);
            loop {
                match wi.next().map(String::as_str) {
                    Some("ro") => {
                        /*
                         * Read-only access is the default when one is not
                         * specified, so just ignore it for now.
                         */
                        continue;
                    }
                    Some("view") => {
                        if let Some(name) = wi.next() {
                            view = Some(name.to_string());
                        } else {
                            bail!("snmp-server: expected a view name");
                        }
                    }
                    Some(other) => {
                        bail!("snmp-server: unexpected {other:?}");
                    }
                    None => {
                        self.snmp_server.community.insert(
                            community.to_string(),
                            SnmpCommunity { readonly, view },
                        );
                        return Ok(());
                    }
                }
            }
        }

        bail!("snmp-server: {no:?} {ww:?}");
    }

    fn line_interface(&mut self, ww: &Vec<String>) -> Result<()> {
        if ww.len() < 2 {
            bail!("unexpected interface line: {ww:?}");
        }

        if ww[1] == "vlan" {
            if ww.len() != 3 {
                bail!("unexpected interface vlan line: {ww:?}");
            }

            let vid: u16 = ww[2]
                .parse()
                .map_err(|e| anyhow!("invalid vlan ID: {ww:?}: {e}"))?;

            return self.new_interface(Interface::Vlan(vid));
        }

        if let Some(gi) = ww[1].strip_prefix("GigabitEthernet") {
            if ww.len() != 2 {
                bail!("unexpected interface gi line: {ww:?}");
            }

            let gi: u16 = gi
                .parse()
                .map_err(|e| anyhow!("invalid gi ID: {ww:?}: {e}"))?;

            return self.new_interface(Interface::Gigabit(gi));
        }

        if let Some(te) = ww[1].strip_prefix("TenGigabitEthernet") {
            if ww.len() != 2 {
                bail!("unexpected interface te line: {ww:?}");
            }

            let te: u16 = te
                .parse()
                .map_err(|e| anyhow!("invalid te ID: {ww:?}: {e}"))?;

            return self.new_interface(Interface::TenGigabit(te));
        }

        bail!("unexpected interface line: {ww:?}");
    }

    fn line(&mut self, s: &str) -> Result<()> {
        /*
         * Split a line into words.  Strings with spaces can be quoted.
         */
        #[derive(Debug)]
        enum LineState {
            Rest,
            Word,
            Whitespace,
            QuotedString,
        }

        let mut ls = LineState::Rest;

        let mut cc = s.chars();
        let mut w = String::new();
        let mut ww = Vec::new();

        loop {
            match ls {
                LineState::Rest => {
                    match cc.next() {
                        None => {
                            /*
                             * We don't really expect blank lines, but whatever.
                             */
                            return Ok(());
                        }
                        Some(c) if c == ' ' => {
                            ls = LineState::Whitespace;
                        }
                        Some(c) if c == '"' => {
                            w.clear();
                            ls = LineState::QuotedString;
                        }
                        Some(c) if c == '!' => {
                            /*
                             * Lines with a bare ! are inserted by the config
                             * engine on the switch to visually separate
                             * sections.
                             */
                            return Ok(());
                        }
                        Some(c) if c.is_ascii_alphabetic() => {
                            w.push(c);
                            ls = LineState::Word;
                        }
                        Some(c) => bail!("unexpected start of line {c:?}"),
                    }
                }
                LineState::Whitespace => match cc.next() {
                    Some(c) if c == ' ' => (),
                    Some(c) if c == '"' => {
                        w.clear();
                        ls = LineState::QuotedString;
                    }
                    Some(c) if c.is_ascii_graphic() => {
                        w.clear();
                        w.push(c);
                        ls = LineState::Word;
                    }
                    Some(c) => bail!("unexpected {c:?} after whitespace"),
                    None => break,
                },
                LineState::Word => match cc.next() {
                    Some(c) if c == ' ' => {
                        if !w.is_empty() {
                            ww.push(w.clone());
                            w.clear();
                        }
                        ls = LineState::Whitespace;
                    }
                    Some(c) if c.is_ascii_graphic() => {
                        w.push(c);
                    }
                    Some(c) => bail!("unexpected {c:?} in word"),
                    None => {
                        if !w.is_empty() {
                            ww.push(w.clone());
                            w.clear();
                        }
                        break;
                    }
                },
                LineState::QuotedString => match cc.next() {
                    Some(c) if c == '"' => {
                        ww.push(w.clone());
                        w.clear();
                        ls = LineState::Whitespace;
                    }
                    Some(c) if c.is_ascii_graphic() || c == ' ' => {
                        w.push(c);
                    }
                    Some(c) => bail!("unexpected {c:?} in quoted string"),
                    None => {
                        bail!("unexpected end of line inside qouted string");
                    }
                },
            }
        }

        /*
         * Now process the words for this line.
         */
        if ww.is_empty() {
            return Ok(());
        }

        let no = if ww[0] == "no" {
            ww.remove(0);
            true
        } else {
            false
        };

        match self.state {
            State::Rest
            | State::Header
            | State::SsdControl
            | State::UnitTypeControl => panic!("unexpected"),
            State::General => {
                match ww.get(0).map(|s| s.as_str()) {
                    Some("cdp") => {
                        if !no || ww.len() != 2 || ww[1] != "run" {
                            bail!("unexpected cdp directive: {ww:?}");
                        }

                        self.cdp = false;
                    }
                    Some("pnp") => {
                        if !no || ww.len() != 2 || ww[1] != "enable" {
                            bail!("unexpected pnp directive: {ww:?}");
                        }

                        self.pnp = false;
                    }
                    Some("vlan") => {
                        if no || ww.len() != 2 || ww[1] != "database" {
                            bail!("unexpected vlan directive: {ww:?}");
                        }

                        /*
                         * Enter the VLAN database mode:
                         */
                        self.state = State::VlanDatabase;
                    }
                    Some("voice") => {
                        if no {
                            bail!("unexpected voice directive: {ww:?}");
                        }

                        if ww.len() == 4 && ww[1] == "vlan" && ww[2] == "state"
                        {
                            self.voice_vlan.state = match ww[3].as_str() {
                                "auto-triggered" => {
                                    VoiceVlanState::AutoTriggered
                                }
                                "auto-enabled" => VoiceVlanState::AutoEnabled,
                                "oui-enabled" => VoiceVlanState::OuiEnabled,
                                "disabled" => VoiceVlanState::Disabled,
                                _ => bail!("voice: {ww:?}"),
                            };
                        } else if ww.len() == 6
                            && ww[1] == "vlan"
                            && ww[2] == "oui-table"
                            && ww[3] == "add"
                        {
                            self.voice_vlan
                                .oui_table
                                .insert(ww[4].to_string(), ww[5].to_string());
                        } else {
                            bail!("voice: {ww:?}");
                        }
                    }
                    Some("bonjour") => {
                        if ww.len() == 5
                            && ww[1] == "interface"
                            && ww[2] == "range"
                            && ww[3] == "vlan"
                        {
                            for r in parse_id_list(&ww[4])? {
                                for id in r {
                                    if no {
                                        self.bonjour.vlans.remove(&id);
                                    } else {
                                        self.bonjour.vlans.insert(id);
                                    }
                                }
                            }
                        } else if ww.len() == 2 && ww[1] == "enable" {
                            self.bonjour.enable = !no;
                        } else {
                            bail!("bonjour: {no:?} {ww:?}");
                        }
                    }
                    Some("hostname") => {
                        if no || ww.len() != 2 {
                            bail!("unexpected hostname directive: {ww:?}");
                        }

                        self.hostname = ww[1].to_string();
                    }
                    Some("logging") => {
                        if ww.len() != 2 || ww[1] != "console" {
                            bail!("logging: {no:?} {ww:?}");
                        }

                        self.logging_console = !no;
                    }
                    Some("username") => {
                        return self.line_username(no, &ww);
                    }
                    Some("ip") => match ww.get(1).map(|s| s.as_str()) {
                        Some("ssh") => {
                            if ww.len() == 3 && ww[2] == "server" {
                                self.ssh_server.enable = !no;
                            } else if ww.len() == 3 && ww[2] == "password-auth"
                            {
                                self.ssh_server.password_auth = !no;
                            } else if (3..=4).contains(&ww.len())
                                && ww[2] == "pubkey-auth"
                            {
                                let auto = if ww.len() == 4 {
                                    if ww[3] == "auto-login" {
                                        true
                                    } else {
                                        bail!("{no:?} {ww:?}");
                                    }
                                } else {
                                    false
                                };

                                if no {
                                    self.ssh_server.pubkey_auth = false;
                                    self.ssh_server.pubkey_auto_login = false;
                                } else {
                                    self.ssh_server.pubkey_auth = true;
                                    self.ssh_server.pubkey_auto_login = auto;
                                }
                            } else {
                                bail!("{no:?} {ww:?}");
                            }
                        }
                        _ => {
                            bail!("{no:?} {ww:?}");
                        }
                    },
                    Some("snmp-server") => {
                        return self.line_snmp_server(no, &ww);
                    }
                    Some("interface") => {
                        if no {
                            bail!("unexpected interface directive: {ww:?}");
                        }

                        return self.line_interface(&ww);
                    }
                    Some("crypto") => {
                        if no
                            || ww.len() != 4
                            || ww[1] != "key"
                            || ww[2] != "pubkey-chain"
                            || ww[3] != "ssh"
                        {
                            bail!("unexpected crypto directive: {ww:?}");
                        }
                        self.state = State::CryptoKeys;
                    }
                    Some("lldp") => {
                        if ww.len() != 2 || ww[1] != "run" {
                            bail!("unexpected lldp directive: {ww:?}");
                        }

                        self.lldp = !no;
                    }
                    Some("passwords") => {
                        if !no && ww.len() == 3 && ww[1] == "aging" {
                            self.passwords.aging = ww[2].parse()?;
                            return Ok(());
                        }

                        bail!("passwords: {no:?} {ww:?}");
                    }
                    Some("macro") => {
                        if !no && ww.len() == 3 && ww[1] == "auto" {
                            self.smartports.state = match ww[2].as_str() {
                                "disabled" => SmartportsState::Disabled,
                                "enabled" => SmartportsState::Enabled,
                                "controlled" => SmartportsState::Controlled,
                                _ => bail!("macro: {no:?} {ww:?}"),
                            };
                            return Ok(());
                        }

                        bail!("macro: {no:?} {ww:?}");
                    }
                    Some(other) => {
                        bail!("what is a {other:?} directive?");
                    }
                    None => bail!("unexpected line structure {no:?} {ww:#?}"),
                }
            }
            State::CryptoKeys => match ww.get(0).map(|s| s.as_str()) {
                Some("user-key") => {
                    if no || ww.len() != 3 || ww[2] != "rsa" {
                        bail!("unexpected user-key directive: {ww:?}");
                    }

                    self.state = State::UserKey(ww[1].to_string());
                }
                Some("exit") => {
                    self.state = State::General;
                }
                Some(_) | None => {
                    bail!("unexpected line structure {no:?} {ww:#?}")
                }
            },
            State::UserKey(ref u) => match ww.get(0).map(|s| s.as_str()) {
                Some("key-string") => {
                    if no || ww.len() != 3 || ww[1] != "row" {
                        bail!("unexpected key-string structure {no:?} {ww:?}");
                    }

                    if self.keyrows.is_none() {
                        self.keyrows = Some(Vec::new());
                    }
                    self.keyrows.as_mut().unwrap().push(ww[2].to_string());
                }
                Some("exit") => {
                    if let Some(keyrows) = self.keyrows.take() {
                        self.user_ssh_keys.insert(u.to_string(), keyrows);
                    }

                    self.state = State::CryptoKeys;
                }
                Some(_) | None => {
                    bail!("unexpected line structure {no:?} {ww:#?}")
                }
            },
            State::VlanDatabase => match ww.get(0).map(|s| s.as_str()) {
                Some("vlan") => {
                    if no || ww.len() != 2 {
                        bail!("unexpected vlan directive: {ww:?}");
                    }

                    let ranges = parse_id_list(&ww[1])?;

                    /*
                     * Explode the ranges into a set of defined VLANs.  There
                     * may be more than one "vlan" line in the database section,
                     * so we extend rather than replace the database here.
                     */
                    self.vlans.extend(explode_id_list(&ranges));
                }
                Some("exit") => {
                    self.state = State::General;
                }
                Some(_) | None => {
                    bail!("unexpected line structure {no:?} {ww:#?}")
                }
            },
            State::Interface(_) => {
                let ifc = self.iface.as_mut().unwrap();

                match ww.get(0).map(|s| s.as_str()) {
                    Some("interface") => {
                        if no {
                            bail!("unexpected interface directive: {ww:?}");
                        }

                        return self.line_interface(&ww);
                    }
                    Some("switchport") => match ww.get(1).map(|s| s.as_str()) {
                        Some("mode") => match ww.get(2).map(|s| s.as_str()) {
                            Some("access") => {
                                ifc.mode = SwitchPortMode::Access;
                            }
                            Some("trunk") => {
                                ifc.mode = SwitchPortMode::Trunk;
                            }
                            Some(_) | None => {
                                bail!(
                                    "unexpected interface \
                                        directive: {ww:?}"
                                );
                            }
                        },
                        Some("access") => match ww.get(2).map(|s| s.as_str()) {
                            Some("vlan") => {
                                if ww.len() != 4 {
                                    bail!(
                                        "unexpected interface \
                                        directive: {ww:?}"
                                    );
                                }

                                ifc.access_vlan =
                                    ww[3].parse().map_err(|e| {
                                        anyhow!("invalid vlan ID: {ww:?}: {e}")
                                    })?;
                            }
                            Some(_) | None => {
                                bail!(
                                    "unexpected interface \
                                        directive: {ww:?}"
                                );
                            }
                        },
                        Some("trunk") => match ww.get(2).map(|s| s.as_str()) {
                            Some("native") => {
                                if ww.len() != 5 || ww[3] != "vlan" {
                                    bail!(
                                        "unexpected interface \
                                        directive: {ww:?}"
                                    );
                                }

                                ifc.trunk_native_vlan =
                                    ww[4].parse().map_err(|e| {
                                        anyhow!("invalid vlan ID: {ww:?}: {e}")
                                    })?;
                            }
                            Some("allowed") => {
                                if ww.len() != 5 || ww[3] != "vlan" {
                                    bail!(
                                        "unexpected interface \
                                        directive: {ww:?}"
                                    );
                                }

                                ifc.trunk_allowed_vlans = Some(
                                    explode_id_list(&parse_id_list(&ww[4])?),
                                );
                            }
                            Some(_) | None => {
                                bail!(
                                    "unexpected interface \
                                        directive: {ww:?}"
                                );
                            }
                        },
                        Some(_) | None => {
                            bail!("unexpected interface directive: {ww:?}");
                        }
                    },
                    Some("shutdown") => {
                        if ww.len() != 1 {
                            bail!("unexpected shutdown directive: {ww:?}");
                        }

                        ifc.shutdown = !no;
                    }
                    Some("description") => {
                        if ww.len() != 2 {
                            bail!("description: {ww:?}");
                        }

                        ifc.description = Some(ww[1].to_string());
                    }
                    Some("name") => {
                        if ww.len() != 2 {
                            bail!("name: {ww:?}");
                        }

                        ifc.name = Some(ww[1].to_string());
                    }
                    Some("ip") => {
                        if ww.len() == 3
                            && ww[1] == "address"
                            && ww[2] == "dhcp"
                        {
                            ifc.dhcp = !no;
                        } else {
                            bail!("ip: {no:?} {ww:?}");
                        }
                    }
                    Some("exit") => {
                        /*
                         * Commit the last interface that we were editing:
                         */
                        self.commit_interface()?;
                        self.state = State::General;
                    }
                    Some(_) | None => {
                        bail!("unexpected line structure {no:?} {ww:#?}")
                    }
                }
            }
        }

        Ok(())
    }
}

#[allow(unused)]
#[derive(Debug)]
pub struct Config {
    pub header: Vec<String>,
    pub ssd_control: Vec<String>,
    pub unit_type_control: Vec<String>,
    pub user_ssh_keys: BTreeMap<String, Vec<String>>,
    pub interfaces: BTreeMap<Interface, InterfaceConfig>,
    pub vlans: BTreeSet<u16>,
    pub pnp: bool,
    pub cdp: bool,
    pub lldp: bool,
    pub hostname: String,
    pub logging_console: bool,
    pub users: BTreeMap<String, UserConfig>,
    pub bonjour: Bonjour,
    pub snmp_server: SnmpServer,
    pub ssh_server: SshServer,
    pub voice_vlan: VoiceVlan,
    pub passwords: Passwords,
    pub smartports: Smartports,
}

impl Config {
    pub fn parse(s: &[&str]) -> Result<Config> {
        let mut p = Parser::default();

        let mut s = s.to_vec().into_iter();

        loop {
            match p.state {
                State::Rest => match s.next() {
                    Some("config-file-header") => {
                        p.state = State::Header;
                        continue;
                    }
                    Some(other) => {
                        bail!("wanted config header, got {other:?}");
                    }
                    None => {
                        bail!("file ended before config file header");
                    }
                },
                State::Header => match s.next() {
                    Some("@") => {
                        p.state = State::General;
                        continue;
                    }
                    Some(other) => {
                        p.header.push(other.to_string());
                        continue;
                    }
                    None => {
                        bail!("file ended during config file header");
                    }
                },
                State::SsdControl => match s.next() {
                    Some(other) if other.starts_with("ssd-control-end ") => {
                        p.ssd_control.push(other.to_string());
                        p.state = State::General;
                        continue;
                    }
                    Some(other) => {
                        p.ssd_control.push(other.to_string());
                        continue;
                    }
                    None => {
                        bail!("file ended during ssd control");
                    }
                },
                State::UnitTypeControl => match s.next() {
                    Some(s @ "unit-type-control-end") => {
                        p.unit_type_control.push(s.to_string());
                        p.state = State::General;
                        continue;
                    }
                    Some(other) => {
                        p.unit_type_control.push(other.to_string());
                        continue;
                    }
                    None => {
                        bail!("file ended during unit type control");
                    }
                },
                State::UserKey(_) | State::CryptoKeys => match s.next() {
                    Some(other) => {
                        p.line(other)?;
                        continue;
                    }
                    None => {
                        bail!("file ended during crypto keys");
                    }
                },
                State::Interface(_) => match s.next() {
                    Some(other) => {
                        p.line(other)?;
                        continue;
                    }
                    None => {
                        bail!("file ended during interface");
                    }
                },
                State::VlanDatabase => match s.next() {
                    Some(other) => {
                        p.line(other)?;
                        continue;
                    }
                    None => {
                        bail!("file ended during VLAN database");
                    }
                },
                State::General => match s.next() {
                    Some(s @ "ssd-control-start") => {
                        p.ssd_control.push(s.to_string());
                        p.state = State::SsdControl;
                        continue;
                    }
                    Some(s @ "unit-type-control-start") => {
                        p.unit_type_control.push(s.to_string());
                        p.state = State::UnitTypeControl;
                        continue;
                    }
                    Some("!") => {
                        continue;
                    }
                    Some(other) => {
                        /*
                         * Parse this line as a general directive.
                         */
                        p.line(other)?;
                        continue;
                    }
                    None => {
                        break;
                    }
                },
            }
        }

        Ok(Config::from(p))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const FILE: &[&str] = &[
        "config-file-header",
        "periwinkle",
        "v3.2.1.1 / RCBS3.2hotfix_950_377_136",
        "CLI v1.0",
        "file SSD indicator encrypted",
        "@",
        "ssd-control-start",
        "ssd config",
        "ssd file passphrase control unrestricted",
        "no ssd file integrity control",
        "ssd-control-end cb0a3fdb1f3a1af4e4430033719968c0",
        "!",
        "!",
        "unit-type-control-start",
        "unit-type unit 1 network gi uplink none",
        "unit-type-control-end",
        "!",
        "no cdp run",
        "vlan database",
        "vlan 1500-1503,1600-1603,1700-1712,2000,2002-2004",
        "exit",
        "voice vlan state auto-triggered",
        "voice vlan oui-table add 0001e3 Siemens_AG_phone",
        "voice vlan oui-table add 00036b Cisco_phone",
        "voice vlan oui-table add 00096e Avaya",
        "voice vlan oui-table add 000fe2 H3C_Aolynk",
        "voice vlan oui-table add 0060b9 Philips_and_NEC_AG_phone",
        "voice vlan oui-table add 00d01e Pingtel_phone",
        "voice vlan oui-table add 00e075 Polycom/Veritel_phone",
        "voice vlan oui-table add 00e0bb 3Com_phone",
        "no lldp run",
        "bonjour interface range vlan 1",
        "hostname periwinkle",
        "no logging console",
        "username root password encrypted \
            $99$RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR\
            RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR \
            privilege 15",
        "ip ssh server",
        "ip ssh password-auth",
        "ip ssh pubkey-auth auto-login",
        "crypto key pubkey-chain ssh",
        "user-key root rsa",
        "key-string row AAAAB3NzaC1yc2EAAAADAQABAAABAQDsPMGqmkcc",
        "key-string row K/Jr33aq7ZxKNVo/yiFal507mlFT/8irKotBWSCQ",
        "key-string row u1dEKriCMgoaiGCYG6O0+6Mp5UAqVJ2WfbsktPl1",
        "key-string row MrYoOCWPAShgtd7xGEDCNgvuEKtivZ0DErbF675e",
        "key-string row b7opKO35eNrKFQNzRwzRYyBji2Su3lEQ09XjtJYB",
        "key-string row 1r/aaQNHBSOpPblPY6z+BH+t/jnChGaCRkqYXtIU",
        "key-string row QlrdfHSfbsUSpsIwvFBwJXONoDZDqTNgXVs9bkn/",
        "exit",
        "exit",
        "snmp-server server",
        "snmp-server community moonbase ro view Default",
        "no pnp enable",
        "!",
        "interface vlan 1",
        " no ip address dhcp",
        "!",
        "interface vlan 1500",
        " name flexlm",
        "!",
        "interface vlan 1501",
        " name rack2rt",
        "!",
        "interface vlan 1502",
        " name london0rt",
        "!",
        "interface vlan 1503",
        " name madrid0rt",
        "!",
        "interface vlan 1600",
        " name buildomat0",
        "!",
        "interface vlan 1601",
        " name buildomat1",
        "!",
        "interface vlan 1602",
        " name buildomat2",
        "!",
        "interface vlan 1603",
        " name buildomat3",
        "!",
        "interface vlan 1700",
        " name \"R1 SW0 TP0 (rack2)\"",
        "!",
        "interface vlan 1701",
        " name \"R1 SW1 TP0 (rack2)\"",
        "!",
        "interface vlan 1702",
        " name \"R2 SW0 TP0 (london)\"",
        "!",
        "interface vlan 1703",
        " name \"R3 SW0 TP0 (madrid)\"",
        "!",
        "interface vlan 1704",
        " name \"madrid K.2\"",
        "!",
        "interface vlan 1705",
        " name \"london K.2\"",
        "!",
        "interface vlan 1706",
        " name \"R1 SW0 TP1\"",
        "!",
        "interface vlan 1707",
        " name \"R1 SW1 TP1\"",
        "!",
        "interface vlan 1708",
        " name \"R4 SW0 TP0\"",
        "!",
        "interface vlan 1709",
        " name \"R4 SW0 TP1\"",
        "!",
        "interface vlan 1710",
        " name \"R4 SW1 TP0\"",
        "!",
        "interface vlan 1711",
        " name \"R4 SW1 TP1\"",
        "!",
        "interface vlan 2000",
        " name desktops",
        "!",
        "interface vlan 2002",
        " name table-hosts",
        " ip address dhcp",
        "!",
        "interface vlan 2003",
        " name emy01-hosts",
        "!",
        "interface vlan 2004",
        " name emy01-mgmt",
        "!",
        "interface GigabitEthernet1",
        " description \"rack2 sw0 tp0\"",
        " switchport access vlan 1700",
        "!",
        "interface GigabitEthernet2",
        " description \"rack2 sw0 tp1\"",
        " switchport access vlan 1706",
        "!",
        "interface GigabitEthernet3",
        " description \"rack2 sw1 tp0\"",
        " switchport access vlan 1701",
        "!",
        "interface GigabitEthernet4",
        " description \"rack2 sw1 tp1\"",
        " switchport access vlan 1707",
        "!",
        "interface GigabitEthernet5",
        " description \"london sw0 tp0\"",
        " switchport access vlan 1702",
        "!",
        "interface GigabitEthernet6",
        " description \"rack3 K.2\"",
        " switchport access vlan 2002",
        "!",
        "interface GigabitEthernet7",
        " shutdown",
        "!",
        "interface GigabitEthernet8",
        " description \"rack3 sw1 tp1\"",
        " switchport access vlan 1711",
        "!",
        "interface GigabitEthernet9",
        " description \"madrid sw0 tp0\"",
        " switchport access vlan 1703",
        "!",
        "interface GigabitEthernet10",
        " description \"rack3 sw1 tp0\"",
        " switchport access vlan 1710",
        "!",
        "interface GigabitEthernet11",
        " description \"london K.2\"",
        " switchport access vlan 1705",
        "!",
        "interface GigabitEthernet12",
        " description \"rack3 sw0 tp1\"",
        " switchport access vlan 1709",
        "!",
        "interface GigabitEthernet13",
        " description \"madrid K.2\"",
        " switchport access vlan 1704",
        "!",
        "interface GigabitEthernet14",
        " description \"rack3 sw0 tp0\"",
        " switchport access vlan 1708",
        "!",
        "interface GigabitEthernet15",
        " description jeeves",
        " switchport mode trunk",
        " switchport trunk native vlan 2002",
        " switchport trunk allowed vlan 1700-1711,2002",
        "!",
        "interface GigabitEthernet16",
        " description uplink",
        " switchport mode trunk",
        " switchport trunk native vlan 2002",
        " switchport trunk allowed vlan 1,1700-1711,2002",
        "!",
        "exit",
    ];

    #[test]
    fn basic() -> Result<()> {
        let c = Config::parse(FILE)?;
        println!("config = {c:#?}");
        Ok(())
    }

    #[test]
    fn basic_id_list_compaction_empty() {
        let list = [].into_iter().collect::<BTreeSet<u16>>();

        let out = compact_id_list(&list);

        let want: Vec<RangeInclusive<u16>> = Vec::new();
        assert_eq!(want, out);
    }

    #[test]
    fn basic_id_list_compaction_one_element() {
        let list = [3210].into_iter().collect::<BTreeSet<u16>>();

        let out = compact_id_list(&list);

        let want = vec![3210..=3210];
        assert_eq!(want, out);
    }

    #[test]
    fn basic_id_list_compaction() {
        let list =
            [1, 10, 11, 13, 15, 20, 21, 22, 999, 1000, 1001, 1002, 1005, 4093]
                .into_iter()
                .collect::<BTreeSet<u16>>();

        let out = compact_id_list(&list);

        let want = vec![
            1..=1,
            10..=11,
            13..=13,
            15..=15,
            20..=22,
            999..=1002,
            1005..=1005,
            4093..=4093,
        ];
        assert_eq!(want, out);
    }

    #[test]
    fn basic_id_list_print() {
        let list =
            [1, 10, 11, 13, 15, 20, 21, 22, 999, 1000, 1001, 1002, 1005, 4093]
                .into_iter()
                .collect::<BTreeSet<u16>>();

        let out = print_id_list(&list);

        assert_eq!(out, "1,10-11,13,15,20-22,999-1002,1005,4093");
    }
}
