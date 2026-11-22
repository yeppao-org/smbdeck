# smbdeck Helm chart

Deploys [smbdeck](https://github.com/yeppao-org/smbdeck), a small web console for
Samba, on Kubernetes: one pod with the `agent` (smbd) and `web` (console)
containers, a small volume for the state, and optionally a discovery pod that
announces the server on the local network.

## Install

The chart pulls `ghcr.io/yeppao-org/smbdeck`, at the tag of the chart's
`appVersion` (`0.1.0`). To run an image you built yourself
(`docker build -t <registry>/smbdeck .` at the root of the repository), push it
to a registry the cluster can pull from, and set `image.repository` and
`image.tag`.

```bash
helm install smbdeck ./deploy/helm/smbdeck \
  --namespace smbdeck --create-namespace \
  --set 'roots[0].name=drive1' --set 'roots[0].hostPath=/mnt/drive1' \
  --set nodeSelector.kubernetes\.io/hostname=nas \
  --set smb.service.enabled=true
```

Without a seed, the console asks for a first administrator, once, with a setup
code printed in the web container's logs:

```bash
kubectl -n smbdeck logs deploy/smbdeck -c web | grep setupCode
kubectl -n smbdeck port-forward svc/smbdeck 8080:80   # then http://localhost:8080
```

## Privileges

| Container | User | Capabilities | Root file system | Mounts |
|---|---|---|---|---|
| `agent` | 0 | CHOWN, FOWNER, DAC_OVERRIDE, SETUID, SETGID, NET_BIND_SERVICE | read-only | state, share roots (hostPath), tmpfs |
| `web` | 10001 | none | read-only | state, tmpfs; never the roots |
| `discovery/mdns` | 86 (avahi) | none | read-only | tmpfs |
| `discovery/wsd` | 65534 (nobody) | none | read-only | none |

All containers run with `allowPrivilegeEscalation: false` and the
`RuntimeDefault` seccomp profile; no service account token is mounted. The
agent re-validates everything the console writes: a path that leads outside its
root, even through a symbolic link, is refused.

The discovery pod uses the host network (multicast does not cross networks) and
`shareProcessNamespace: true`: on the node's network, a process with PID 1
collides with systemd's netlink socket, and wsdd2 then fails with
`bind: Address in use`. avahi's runtime directory lives in an emptyDir, which
kubelet creates with mode 0777, so no root init container is needed.

## Main values

| Value | Default | Meaning |
|---|---|---|
| `roots` | `[]` | Share roots: `name`, `hostPath`, `type` (`Directory` waits for a missing disk) |
| `filesUid` / `filesGid` | `1000` | Owner of every file created through SMB |
| `samba.hostsAllow` | `[]` | Networks allowed to connect over SMB (empty: any) |
| `web.allowedNetworks` | `[]` | Networks allowed to reach the console (empty: private ranges and 100.64.0.0/10) |
| `web.trustedProxies` | `[]` | Proxies whose X-Forwarded-For / X-Forwarded-Proto are believed |
| `web.smbHosts` | `[]` | Names shown in `smb://` addresses (empty: the console's host name) |
| `web.cookieSecure` | `auto` | `auto`, `always` or `never` |
| `seed.enabled` | `false` | Initial accounts and shares, applied once on an empty state |
| `seed.passwordsSecret` | `""` | Existing Secret, one key per account (initial password) |
| `persistence.size` | `64Mi` | State volume (holds NT hashes: treat it as a secret) |
| `persistence.keep` | `true` | Keep the claim on uninstall |
| `service.type` | `ClusterIP` | Service of the console (port 80) |
| `smb.service.enabled` | `false` | SMB Service (LoadBalancer, `externalTrafficPolicy: Local`, no node port) |
| `ingress.enabled` | `false` | Ingress for the console |
| `discovery.enabled` | `false` | mDNS/Bonjour and WS-Discovery announcements |
| `discovery.hostName` | `""` | Name announced as `<hostName>.local` (required when enabled) |
| `discovery.address` | `""` | Address announced for that name (the SMB load balancer address) |
| `networkPolicy.enabled` | `false` | Restrict who reaches the web and SMB ports |

Every value is documented in [values.yaml](values.yaml).

## Example: MetalLB, console reserved to a tailnet

```yaml
roots:
  - name: drive1
    hostPath: /mnt/drive1
nodeSelector:
  kubernetes.io/hostname: nas
samba:
  hostsAllow: [192.168.1.0/24, 100.64.0.0/10]
web:
  allowedNetworks: [100.64.0.0/10]     # SMBDECK_ALLOWED_NETWORKS
  smbHosts: [nas.local, 192.168.1.50]
service:
  type: LoadBalancer
  externalTrafficPolicy: Local          # the console sees the real client
  annotations:
    metallb.io/loadBalancerIPs: 192.168.1.51
smb:
  service:
    enabled: true
    annotations:
      metallb.io/loadBalancerIPs: 192.168.1.50
discovery:
  enabled: true
  hostName: nas
  address: 192.168.1.50
  interface: eth0
  nodeSelector:
    kubernetes.io/hostname: nas
```

## Seed

```yaml
seed:
  enabled: true
  passwordsSecret: smbdeck-seed        # kubectl create secret generic smbdeck-seed --from-file=admin=./admin.txt
  config:
    users:
      - name: admin
        admin: true
    shares:
      - name: Media
        root: drive1
        path: media
        access:
          admin: rw
```

The seed is read once, when the state volume holds no desired state. Passwords
are hashed and never stored; the Secret can be deleted afterwards.

## Notes

- The agent's reports live in an `emptyDir` (`/status`), mounted read-only in
  the console: the console cannot forge what the agent reports.
- The console answers only to IP addresses, `localhost`, the names in
  `web.allowedHosts` and the ingress hosts (421 otherwise, against DNS
  rebinding).
- A `LoadBalancer` or `NodePort` web Service defaults to
  `externalTrafficPolicy: Local`, so the console sees the client's address.
  An ingress requires `web.trustedProxies` (rendering fails otherwise).
- Discovery requires `discovery.interface`: on the host network, avahi and
  wsdd2 would otherwise answer on every interface of the node.
- `kubectl port-forward` reaches the console from 127.0.0.1: it is refused if
  `web.allowedNetworks` leaves out 127.0.0.0/8.
