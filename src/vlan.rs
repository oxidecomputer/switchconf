/*
 * Copyright 2025 Oxide Computer Company
 */

use std::{collections::BTreeMap, path::Path};

use anyhow::{anyhow, bail, Result};

use crate::template::TemplateVlan;

pub struct VlanDatabase {
    name_to_id: BTreeMap<String, u16>,
}

impl Default for VlanDatabase {
    fn default() -> Self {
        Self { name_to_id: [("default".into(), 1)].into() }
    }
}

#[derive(Clone)]
pub struct TemplateVlanAndId {
    pub id: u16,
    pub t: TemplateVlan,
}

impl VlanDatabase {
    pub fn load<P: AsRef<Path>>(p: P) -> Result<VlanDatabase> {
        let p = p.as_ref();
        let f = std::fs::read_to_string(&p)
            .map_err(|e| anyhow!("reading {p:?}: {e}"))?;

        let mut name_to_id: BTreeMap<String, u16> = Default::default();
        let mut id_to_name: BTreeMap<u16, String> = Default::default();

        for l in f.lines() {
            let mut cc = l.chars();
            let mut t = Vec::new();
            let mut acc = String::new();

            enum State {
                Rest,
                Comment,
                Value,
            }
            let mut st = State::Rest;

            loop {
                let c = cc.next();

                match st {
                    State::Rest => match c {
                        Some('#') => {
                            st = State::Comment;
                        }
                        Some(' ') | Some('\t') => (),
                        Some(c) if c.is_ascii_alphanumeric() || c == '-' => {
                            st = State::Value;
                            acc.push(c);
                        }
                        Some(other) => {
                            bail!("unexpected character {other:?}");
                        }
                        None => break,
                    },
                    State::Comment => {
                        match c {
                            /*
                             * Comments end at the end of the line.
                             */
                            None => break,
                            _ => (),
                        }
                    }
                    State::Value => match c {
                        Some('#') => {
                            if !acc.is_empty() {
                                t.push(acc);
                                acc = String::new();
                            }
                            st = State::Comment;
                        }
                        Some(' ') | Some('\t') => {
                            if !acc.is_empty() {
                                t.push(acc);
                                acc = String::new();
                            }
                            st = State::Rest;
                        }
                        Some(c) if c.is_ascii_alphanumeric() || c == '-' => {
                            acc.push(c);
                        }
                        Some(other) => {
                            bail!("unexpected character {other:?}");
                        }
                        None => {
                            if !acc.is_empty() {
                                t.push(acc);
                            }
                            break;
                        }
                    },
                }
            }

            if t.is_empty() {
                continue;
            }

            if t.len() != 2 {
                bail!("unusual line: {l:?} -> {t:?}");
            }

            let name = t[0].to_string();
            let id = u16::from_str_radix(&t[1], 10)?;

            if let Some(ex) = name_to_id.get(&name) {
                bail!("duplicate entries for name {name:?}: {ex} and {id}");
            }
            if let Some(ex) = id_to_name.get(&id) {
                bail!("duplicate entries for ID {id:?}: {ex:?} and {name:?}");
            }

            name_to_id.insert(name.clone(), id);
            id_to_name.insert(id, name.clone());
        }

        let Some(dfl) = name_to_id.get("default").copied() else {
            bail!("all VLAN databases must have a \"default\" entry");
        };
        if dfl != 1 {
            bail!("the \"default\" VLAN must have ID 1, not {dfl}");
        }

        Ok(Self { name_to_id })
    }

    pub fn reconcile(
        &self,
        vlans: &BTreeMap<String, TemplateVlan>,
    ) -> Result<BTreeMap<String, TemplateVlanAndId>> {
        let mut out: BTreeMap<String, TemplateVlanAndId> = Default::default();

        for (name, t) in vlans.clone().into_iter() {
            /*
             * Use the VLAN database to determine the ID number for this
             * VLAN:
             */
            let Some(id) = self.name_to_id.get(&name).copied() else {
                bail!("VLAN {name:?} does not appear in database");
            };

            assert!(out.insert(name, TemplateVlanAndId { id, t }).is_none());
        }

        /*
         * Include a default entry for any VLAN that appears in the database but
         * not in the configuration.
         */
        for (name, id) in self.name_to_id.iter() {
            if out.contains_key(name) {
                continue;
            }

            out.insert(
                name.to_string(),
                TemplateVlanAndId { id: *id, t: TemplateVlan::default() },
            );
        }

        /*
         * This should have been checked as a result of loading the database:
         */
        let dfl = out.get("default").expect("must have \"default\" VLAN");
        assert_eq!(dfl.id, 1);

        Ok(out)
    }
}
