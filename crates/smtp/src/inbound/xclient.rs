/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::core::{Session, SessionData};
use common::network::SessionStream;
use compact_str::format_compact;
use std::net::IpAddr;
use trc::SmtpEvent;

impl<T: SessionStream> Session<T> {
    pub async fn handle_xclient(&mut self, attributes: &[impl AsRef<str>]) -> Result<(), ()> {
        if !self.instance.unix_socket
            || self.data.authenticated_as.is_some()
            || self.data.mail_from.is_some()
        {
            trc::event!(
                Smtp(SmtpEvent::CommandNotImplemented),
                SpanId = self.data.session_id,
                Details = "XCLIENT",
            );
            return self.write(b"550 5.7.0 XCLIENT is not permitted.\r\n").await;
        }

        let mut remote_ip = self.data.remote_ip;
        let mut remote_port = self.data.remote_port;
        for attribute in attributes {
            let Some((name, value)) = attribute.as_ref().split_once('=') else {
                continue;
            };
            if name.eq_ignore_ascii_case("ADDR") {
                let value = value
                    .get(..5)
                    .filter(|prefix| prefix.eq_ignore_ascii_case("IPV6:"))
                    .map_or(value, |_| &value[5..]);
                if let Ok(ip) = value.parse::<IpAddr>() {
                    remote_ip = ip;
                }
            } else if name.eq_ignore_ascii_case("PORT")
                && let Ok(port) = value.parse::<u16>()
            {
                remote_port = port;
            }
        }

        trc::event!(
            Smtp(SmtpEvent::ConnectionStart),
            SpanId = self.data.session_id,
            RemoteIp = remote_ip,
            RemotePort = remote_port,
            Details = format_compact!("XCLIENT {}", self.data.remote_ip),
        );

        self.data = SessionData::new(
            self.data.local_ip,
            self.data.local_port,
            remote_ip,
            remote_port,
            self.server.lookup_asn_country(remote_ip).await,
            self.data.session_id,
        );

        if self.init_conn().await { Ok(()) } else { Err(()) }
    }
}
