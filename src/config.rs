/*
 * Copyright 2023 Oxide Computer Company
 */

use std::collections::HashMap;

use anyhow::{bail, Result};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct ConfigFile {
    switch: HashMap<String, ConfigFileSwitch>,
}

impl ConfigFile {
    pub fn switch(&self, name: &str) -> Result<&ConfigFileSwitch> {
        if let Some(cfs) = self.switch.get(name) {
            Ok(cfs)
        } else {
            bail!("could not find switch named {name:?}");
        }
    }
}

#[derive(Deserialize)]
pub struct ConfigFileSwitch {
    ip: String,
    username: String,
    password: String,
}

impl ConfigFileSwitch {
    pub fn ip(&self) -> &str {
        &self.ip
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}

pub fn load() -> Result<ConfigFile> {
    let f = std::fs::read_to_string("switch.toml")?;
    Ok(toml::from_str(&f)?)
}
