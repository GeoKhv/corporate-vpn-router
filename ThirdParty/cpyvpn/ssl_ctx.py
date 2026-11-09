# coding: utf-8
# Created on 28.05.2021
# Copyright © 2020-2021 Nick Krylov.
# SPDX-License-Identifier: GPL-3.0-or-later

# Modified for Corporate VPN Router: require the app's verified gateway policy.
# No unverified connection, system CA search, cached CA discovery or client identity.
def get_ssl_context():
    raise RuntimeError('GATEWAY_POLICY_NOT_INSTALLED')

def check_ssl_mode(host, port, nocert):
    raise RuntimeError('GATEWAY_POLICY_NOT_INSTALLED')

def set_ssl_strict_mode(state):
    if state is not True:
        raise RuntimeError('PERMISSIVE_TLS_FORBIDDEN')

def require_user_cert():
    raise RuntimeError('CLIENT_CERTIFICATE_AUTH_NOT_SUPPORTED')
