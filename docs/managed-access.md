# Managed access

This host works with the optional [Moonlight V+ backend and host agent](https://github.com/mikulicf/moonlight-vplus/tree/master/control). Supply deployment addresses and credentials at installation time. The repository includes none.

## Enabling the host policy

Build this repository or obtain the Windows ZIP artifact from its **Managed host build** workflow. Preserve the existing Apollo configuration, certificates, application list, and state when updating the host. The package requires the same GPU drivers and virtual-display driver as upstream Apollo.

Follow the backend's enrollment instructions and configure:

```ini
managed_policy_file = <absolute-path-to-protected-policy-file>
```

The agent and Apollo must use the same policy path. The agent authenticates outbound to the backend over HTTPS and writes current grants atomically. Only the agent, trusted host services, and administrators may modify this file or its parent directory. Interactive Windows users receiving remote desktop access should not be local administrators; full desktop access is not an operating-system sandbox. Apollo's supported Windows service runs as LocalSystem, which remains a trusted principal.

With a nonempty policy path, Apollo:

- Accepts only the exact client certificates in unexpired backend leases, including on reused HTTPS connections.
- Ignores legacy device pairings and disables PIN pairing, automatic port mapping, and discovery.
- Requires encrypted RTSP, video, audio, and input according to the GameStream protocol.
- Checks authorization before starting a stream and terminates revoked or expired streams.
- Binds its administrative web listener to IPv4 loopback, including first-run account setup.
- Exposes managed protocol version 1 in loopback server information for the agent.

There is no fallback to paired-device access while managed mode is enabled. A missing, malformed, stale, or expired policy denies access. The normal polling interval is one second, and Apollo reloads policy and checks active sessions every 500 ms. During a backend outage, authorization lasts at most the remaining 90-second lease. Synchronize clocks on the backend and host.

The policy grants streaming, application launch/stop, input, and clipboard permission. It does not grant host command execution or file-transfer extensions. Users authorized for the same host share its Windows desktop; this does not create separate Windows sessions or provide exclusive ownership of a workstation.

## Networking

The backend does not relay media or arrange NAT traversal. Provide client-reachable streaming addresses and ports for each deployment. Keep Apollo administration and OS management ports off public networks. The management backend needs its own HTTPS endpoint; configure certificate issuance, router rules, and firewall restrictions for the actual environment.

An empty `managed_policy_file` retains regular Apollo operation. Removing managed mode is a deliberate administrator action that restores the usual pairing and configuration rules. Stopping the agent or deleting its policy alone leaves managed mode enabled and access denied.

## Validation and upstream maintenance

Keep `third-party/build-deps` at the restored FFmpeg 8 revision `c38829d6` or a reviewed compatible successor. Apollo's encoder teardown drains FFmpeg before releasing the device; the earlier `a9a7f863` dependency pin supplies FFmpeg 7 and can hang indefinitely during AMD AMF probing. This fork restores the dependency revision used before the upstream merge regression described in [Apollo issue #1588](https://github.com/ClassicOldSong/Apollo/issues/1588). Validate hardware encoder startup and stream teardown when updating these dependencies.

CI builds the Windows host and runs production policy-parser tests covering exact certificate matching, derived and unknown certificates, revoked/expired grants, malformed policy, validity bounds, and permission restrictions.

This fork builds on Apollo master and includes fixes from the upstream security work: strict paired-certificate identity checks and serialized legacy certificate-store access, plus the [input bounds repair](https://github.com/LizardByte/Sunshine/commit/1583e7c4) and [control packet bounds repair](https://github.com/LizardByte/Sunshine/commit/82bccdf6). Review [Sunshine security advisories](https://github.com/LizardByte/Sunshine/security/advisories) when updating inherited protocol code. Automated tests and a successful build do not establish suitability for every public-network deployment.
