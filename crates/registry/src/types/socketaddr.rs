/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    jmap::{
        IntoValue, JmapValue, JsonPointerPatch, MaybeUnpatched, PatchResult, RegistryJsonPatch,
    },
    pickle::{Pickle, PickledStream},
    types::error::PatchError,
};
use std::{fmt::Display, str::FromStr};

const UNSET_SOCKET_ADDR: std::net::SocketAddr = std::net::SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::from_octets([255, 255, 255, 255])),
    u16::MAX,
);
const UNIX_PREFIX: &str = "unix:";
const UNIX_TAG: u8 = b'u';

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketAddr {
    Inet(std::net::SocketAddr),
    Unix { path: String, local_port: u16 },
}

impl SocketAddr {
    pub fn is_valid(&self) -> bool {
        match self {
            SocketAddr::Inet(addr) => *addr != UNSET_SOCKET_ADDR,
            SocketAddr::Unix { path, .. } => path.starts_with('/'),
        }
    }
}

impl FromStr for SocketAddr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some(path) = s.strip_prefix(UNIX_PREFIX) else {
            return s
                .parse::<std::net::SocketAddr>()
                .map(SocketAddr::Inet)
                .map_err(|err| err.to_string());
        };
        let (path, local_port) = match path.rsplit_once(':') {
            Some((path, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
                (path, port.parse::<u16>().map_err(|err| err.to_string())?)
            }
            _ => (path, 0),
        };
        if path.starts_with('/') {
            Ok(SocketAddr::Unix {
                path: path.to_string(),
                local_port,
            })
        } else {
            Err("Unix socket path must be absolute".to_string())
        }
    }
}

impl Display for SocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketAddr::Inet(addr) => write!(f, "{addr}"),
            SocketAddr::Unix {
                path,
                local_port: 0,
            } => write!(f, "{UNIX_PREFIX}{path}"),
            SocketAddr::Unix { path, local_port } => write!(f, "{UNIX_PREFIX}{path}:{local_port}"),
        }
    }
}

impl serde::Serialize for SocketAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SocketAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        SocketAddr::from_str(<&str>::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid SocketAddr"))
    }
}

impl Default for SocketAddr {
    fn default() -> Self {
        SocketAddr::Inet(UNSET_SOCKET_ADDR)
    }
}

impl Pickle for SocketAddr {
    fn pickle(&self, out: &mut Vec<u8>) {
        match self {
            SocketAddr::Inet(addr) => {
                addr.ip().pickle(out);
                addr.port().pickle(out);
            }
            SocketAddr::Unix { path, local_port } => {
                out.push(UNIX_TAG);
                path.pickle(out);
                local_port.pickle(out);
            }
        }
    }

    fn unpickle(data: &mut PickledStream<'_>) -> Option<Self> {
        let ip = match data.read()? {
            4 => std::net::IpAddr::V4(data.read_array::<4>()?.into()),
            6 => std::net::IpAddr::V6(data.read_array::<16>()?.into()),
            UNIX_TAG => {
                let path = String::unpickle(data)?;
                let local_port = u16::unpickle(data)?;
                return Some(SocketAddr::Unix { path, local_port });
            }
            _ => return None,
        };
        let port = u16::unpickle(data)?;
        Some(SocketAddr::Inet(std::net::SocketAddr::new(ip, port)))
    }
}

impl RegistryJsonPatch for SocketAddr {
    fn patch<'x>(
        &mut self,
        mut pointer: JsonPointerPatch<'_>,
        value: JmapValue<'x>,
    ) -> PatchResult<'x> {
        match (value, pointer.next()) {
            (jmap_tools::Value::Str(value), None) => {
                if let Ok(new_value) = SocketAddr::from_str(value.as_ref()) {
                    *self = new_value;
                    Ok(MaybeUnpatched::Patched)
                } else {
                    Err(PatchError::new(
                        pointer,
                        "Failed to parse SocketAddr from string",
                    ))
                }
            }
            _ => Err(PatchError::new(
                pointer,
                "Invalid path for SocketAddr, expected a string value",
            )),
        }
    }
}

impl IntoValue for SocketAddr {
    fn into_value(self) -> JmapValue<'static> {
        JmapValue::Str(self.to_string().into())
    }
}
