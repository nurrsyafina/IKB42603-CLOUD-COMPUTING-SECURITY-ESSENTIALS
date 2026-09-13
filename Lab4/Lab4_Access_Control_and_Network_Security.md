# IKB42603 Cloud Computing Security Essentials
## Lab 4 — Access Control & Network Security (Weeks 7–8)

## Course Info

| Item | Detail |
|---|---|
| Name | NURSYAFINA BINTI RAMLI |
| Matric No. | 52215124843 |
| Course | IKB42603 Cloud Computing Security Essentials |
| University | UniKL MIIT |
| GitHub Repo | https://github.com/peenvsly/IKB42603-CLOUD-COMPUTING-SECURITY-ESSENTIALS |
| Lab | Lab 4 — Access Control & Network Security |

## Objective

This lab demonstrates the two questions that underpin almost every access control system: **who are you** (authentication) and **what are you allowed to do** (authorization). Session A covers authentication via HTTP Basic Auth, multi-factor authentication (MFA) using TOTP, and Kubernetes RBAC. Session B covers network security through Docker network segmentation (3-tier architecture), a default-deny firewall model using iptables, and container hardening with vulnerability scanning.

## Evidence Folder

| # | Filename | Task | Description |
|---|---|---|---|
| 1 | `Lab4_01_task1_authentication_401_200.png` | Task 1 | HTTP Basic Auth — no credentials (401) vs valid credentials (200) |
| 2 | `Lab4_02_task2_MFA_TOTP.png` | Task 2 | TOTP code generated and validated — MFA OK |
| 3 | `Lab4_03_task3_RBAC_authorization.png` | Task 3 | `kubectl auth can-i` — allowed (list pods) vs denied (create deploy, delete pods) |
| 4 | `Lab4_04_task4_network_segmentation.png` | Task 4 | web→db BLOCKED, app→db REACHABLE |
| 5 | `Lab4_05_task5_iptables_default_deny.png` | Task 5 | iptables default-deny policy with explicit ACCEPT rules |
| 6 | `Lab4_06_task6_trivy_scan.png` | Task 6 | Container hardening verification + Trivy vulnerability scan |
| 7 | `Lab4_07_verification_commands.png` | Verification | RoleBinding YAML + CapDrop confirmation |

---

## Task 1 — Authentication: A Password-Protected Service

**Command:**
```bash
docker run --rm httpd:alpine htpasswd -nbB student 'P@ssw0rd!' > htpasswd.txt

cat > default.conf <<'EOF'
server { listen 80;
 location / { auth_basic "Restricted";
 auth_basic_user_file /etc/nginx/.htpasswd;
 root /usr/share/nginx/html;
 index index.html; } }
EOF

mkdir -p html
echo "Authenticated OK" > html/index.html

docker run --rm -d --name authsvc -p 8080:80 \
 -v $(pwd)/default.conf:/etc/nginx/conf.d/default.conf \
 -v $(pwd)/htpasswd.txt:/etc/nginx/.htpasswd \
 -v $(pwd)/html:/usr/share/nginx/html \
 nginx

curl -s -o /dev/null -w 'no-creds: %{http_code}\n' http://localhost:8080
curl -s -u student:'P@ssw0rd!' http://localhost:8080
```

**Output:**
```
no-creds: 401
Authenticated OK
```

**Result:** PASS — unauthenticated requests are rejected with `401 Unauthorized`; requests with valid credentials succeed and return the expected content.

**Evidence:** `Lab4_01_task1_authentication_401_200.png`

**Troubleshooting note:** The original lab manual config used `return 200 '...'` inside the `location` block. This directive executes in nginx's **rewrite phase**, which runs *before* the **access phase** where `auth_basic` is evaluated — so the request short-circuited to `200 OK` before authentication could ever be checked (a **fail-open** condition, verified by the absence of a `WWW-Authenticate` header via `curl -v`). The fix was to serve a static file via `root`/`index` instead, which executes in the **content phase** — after access control has already run. This was confirmed both by direct testing (`401` returned correctly) and by inspecting the config loaded inside the running container.

---

## Task 2 — Add a Second Factor (MFA / TOTP)

**Command:**
```bash
SECRET=$(head -c20 /dev/urandom | base32)
oathtool --totp -b "$SECRET"

CODE=$(oathtool --totp -b "$SECRET"); echo "Code used: $CODE"; [ "$CODE" = "$(oathtool --totp -b "$SECRET")" ] && echo 'MFA OK' || echo 'MFA FAILED'
```

**Output:**
```
MFA OK
```

**Result:** PASS — the 6-digit TOTP code generated from the shared secret was successfully validated against a freshly recomputed code.

**Evidence:** `Lab4_02_task2_MFA_TOTP.png`

**Troubleshooting note:** The lab manual's `read -p` syntax is bash-specific and does not work the same way in `zsh` (the default shell on Kali). An early attempt using zsh's `read "?prompt"VAR` syntax also failed because the variable name concatenated with typed input. The reliable fix was `printf` + plain `read`, run close together with the `oathtool` call in a single line to stay inside the 30-second TOTP validity window — an earlier attempt failed validation simply because the window had expired between generating and entering the code, which is expected behaviour, not a bug.

---

## Task 3 — Authorization: RBAC Roles

**Command:**
```bash
kind create cluster --name ccse-lab4
kubectl create namespace app
kubectl create serviceaccount dev -n app
kubectl create role dev-role -n app --verb=get,list --resource=pods
kubectl create rolebinding dev-rb -n app --role=dev-role --serviceaccount=app:dev

SA=system:serviceaccount:app:dev
kubectl auth can-i list pods -n app --as=$SA
kubectl auth can-i create deploy -n app --as=$SA
kubectl auth can-i delete pods -n app --as=$SA
```

**Output:**
```
yes
no
no
```

**Result:** PASS — the `dev` service account can list pods (explicitly granted) but cannot create deployments or delete pods (not granted), confirming least-privilege enforcement.

**Evidence:** `Lab4_03_task3_RBAC_authorization.png`

**Troubleshooting note:** The first `kind create cluster` attempt failed with `context deadline exceeded` / `kubelet is unhealthy`. Diagnosis ruled out disk space (49GB free) and cgroup misconfiguration (`memory` controller present, `cgroup2` unified with `systemd` driver — matching Docker's driver). The remaining suspect was tight system RAM (3.8GiB total, ~2.6GiB available). Deleting the failed cluster and retrying succeeded, suggesting the first failure was transient resource contention during kubeadm's control-plane bring-up rather than a configuration fault.

---

## Task 4 — Network Segmentation (Three-Tier)

**Command:**
```bash
docker network create frontend-net
docker network create backend-net

docker run -d --name db --network backend-net redis:alpine
docker run -d --name app --network backend-net nginx
docker network connect frontend-net app
docker run -d --name web --network frontend-net nginx

docker exec web sh -c 'apt-get update -qq && apt-get install -yqq curl > /dev/null 2>&1; curl -s -m 3 db:6379 || echo BLOCKED'
docker exec app sh -c 'apt-get update -qq && apt-get install -yqq netcat-openbsd > /dev/null 2>&1; nc -z -w3 db 6379 && echo REACHABLE'
```

**Output:**
```
BLOCKED
REACHABLE
Connection to db (172.20.0.2) 6379 port [tcp/*] succeeded!
```

**Result:** PASS — `web` (frontend-net only) cannot reach `db` (backend-net only); `app` (attached to both networks) can reach `db`, confirming the database tier is isolated from the internet-facing tier.

**Evidence:** `Lab4_04_task4_network_segmentation.png`

**Troubleshooting note:** The lab manual's commands assume an Alpine-based `nginx` image (`apk add`), but the current official `nginx:latest` image on Docker Hub is Debian-based, so `apk` was not found. The first `BLOCKED` result was actually a false positive — `curl` never ran because the package install itself failed. Switching to `apt-get install curl` (and `netcat-openbsd` for the `app` test) allowed the commands to run for real, and the segmentation result was then confirmed as a genuine network-layer block rather than a missing-tool artifact.

---

## Task 5 — Firewall Rules (Default-Deny)

**Command:**
```bash
docker run --rm --cap-add=NET_ADMIN alpine sh -c '\
 apk add -q iptables; \
 iptables -P INPUT DROP; \
 iptables -A INPUT -p tcp --dport 443 -j ACCEPT; \
 iptables -A INPUT -i lo -j ACCEPT; \
 iptables -L INPUT -n'
```

**Output:**
```
Chain INPUT (policy DROP)
target     prot opt source               destination
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:443
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0
```

**Result:** PASS — default INPUT policy is DROP, with explicit ACCEPT exceptions for HTTPS (443) and loopback traffic only.

**Evidence:** `Lab4_05_task5_iptables_default_deny.png`

---

## Task 6 — Container / Host Hardening

**Command:**
```bash
docker run -d --name hardened \
 --user 1000:1000 \
 --read-only \
 --cap-drop=ALL \
 --security-opt no-new-privileges \
 --tmpfs /tmp \
 nginxinc/nginx-unprivileged

docker inspect hardened --format 'User={{.Config.User}} ReadOnly={{.HostConfig.ReadonlyRootfs}}'
docker inspect hardened --format '{{json .HostConfig.CapDrop}}'

docker run --rm -v ~/.cache/trivy:/root/.cache/trivy aquasec/trivy image --timeout 15m --skip-db-update --severity HIGH,CRITICAL nginx:alpine
```

**Output:**
```
User=1000:1000 ReadOnly=true
["ALL"]

nginx:alpine (alpine 3.24.1)
Total: 7 (HIGH: 7, CRITICAL: 0)

Library   | Vulnerability   | Severity | Status | Installed Version | Fixed Version
libuuid   | CVE-2026-53612  | HIGH     | fixed  | 2.42.1-r0          | 2.42.3-r0
libuuid   | CVE-2026-53613  | HIGH     | fixed  | 2.42.1-r0          | 2.42.3-r0
libuuid   | CVE-2026-53614  | HIGH     | fixed  | 2.42.1-r0          | 2.42.3-r0
```

**Result:** PASS — non-root user and read-only filesystem confirmed via inspection; all Linux capabilities dropped; image scan identified 7 HIGH-severity CVEs (all with an available fix), demonstrating the value of scanning before deployment.

**Evidence:** `Lab4_06_task6_trivy_scan.png`, `Lab4_07_verification_commands.png`

**Three hardening measures applied and the attack each blunts:**

| Measure | Attack surface removed |
|---|---|
| `--user 1000:1000` (non-root) | Limits damage from code execution inside the container; blunts container-escape-to-root scenarios |
| `--cap-drop=ALL` | Removes kernel-level privileges (e.g. `NET_ADMIN`, `SYS_ADMIN`), preventing network/mount tampering even after compromise |
| `--read-only` root filesystem | Prevents an attacker from writing malware, backdoors, or persistence mechanisms to the container filesystem |

**Troubleshooting note:** The Trivy scan initially failed with `context deadline exceeded` because the vulnerability database (~113MB) download alone exceeded the default timeout on this bandwidth-constrained VM, and because `--rm` discarded the downloaded database after every run. The fix combined two changes: mounting a host-side cache directory (`-v ~/.cache/trivy:/root/.cache/trivy`) so the database persists between runs, and using `--skip-db-update` on the retry to scan directly against the already-downloaded database, avoiding a second slow download and an intermittent network reset encountered mid-transfer.

---

## Verification Commands

```bash
kubectl get rolebinding dev-rb -n app -o yaml
```
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: dev-rb
  namespace: app
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: dev-role
subjects:
- kind: ServiceAccount
  name: dev
  namespace: app
```

```bash
docker inspect hardened --format '{{json .HostConfig.CapDrop}}'
```
```
["ALL"]
```

---

## Short-Answer Questions

**Q1. Explain the difference between authentication and authorization using Tasks 1 and 3.**

Authentication answers "who are you" — in Task 1, the nginx service verified the client's identity by checking a username and password against a stored bcrypt hash before granting any access at all (401 without proof of identity, 200 with it). Authorization answers "what are you allowed to do" *after* identity is established — in Task 3, the `dev` service account's identity was never in question; RBAC decided which actions that already-authenticated identity could perform (`list pods` = yes, `create deploy` = no, `delete pods` = no). Authentication is a single gate at the door; authorization is the set of doors that gate leads to.

**Q2. Why is MFA so effective, and which attacks does it defeat?**

MFA combines two different factor classes — something you know (password) and something you have (the TOTP secret/device) — so a single stolen credential is no longer enough to log in. It is highly effective against credential stuffing, password reuse from data breaches, and brute-force/guessing attacks, since the attacker would additionally need the physical device or secret generating the code. Its 30-second validity window (observed directly during this lab, when a code expired between generation and entry) also defeats replay of a captured code after the fact. It is not, however, a complete defence against real-time phishing/adversary-in-the-middle attacks, where a code is relayed to the attacker within its validity window.

**Q3. How does network segmentation limit the damage of a compromised web server?**

In the 3-tier setup, `web` only has a network interface on `frontend-net`, so even if an attacker fully compromises it, there is no network path — not even at the IP/DNS level — from `web` to `db` on `backend-net`. This was demonstrated directly: `web` could not resolve or reach `db:6379` (BLOCKED), while `app`, which legitimately bridges both networks, could (REACHABLE). Segmentation contains lateral movement by design: an attacker must first pivot through the application tier (which has its own, presumably tighter, controls) rather than reaching sensitive data directly from the outermost, most exposed tier.

**Q4. What does a default-deny firewall policy achieve, and how does it relate to cloud security groups?**

A default-deny policy (`iptables -P INPUT DROP`) rejects all inbound traffic unless an explicit rule permits it, so the security posture is "nothing works until proven necessary" rather than "everything works until proven dangerous." This is the same model used by cloud security groups (AWS Security Groups, Azure NSGs): both start from implicit deny and require an explicit allow rule per port/protocol/source. It minimises the attack surface to only the ports genuinely required (here, HTTPS on 443 and loopback), rather than relying on administrators to remember to block everything unnecessary.

**Q5. List the hardening measures you applied and the attack surface each one removes.**

- **Non-root user (`--user 1000:1000`)** — removes the ability for a compromised process to act with root privileges inside (or potentially outside, via escape) the container.
- **Read-only root filesystem (`--read-only` + `--tmpfs /tmp`)** — prevents writing malware, backdoors, or modified binaries to disk, while still allowing the minimum writable scratch space the application needs.
- **All capabilities dropped (`--cap-drop=ALL`)** — removes kernel-level privileges (e.g. `NET_ADMIN`, `SYS_ADMIN`) so a compromised process cannot manipulate networking or mount filesystems.
- **`no-new-privileges`** — blocks privilege escalation via SUID binaries even if one exists inside the image.
- **Image vulnerability scanning (Trivy)** — proactively surfaces known CVEs (7 HIGH found, all with fixes available) before deployment, shrinking the window during which a known, patchable vulnerability sits unaddressed in production.

---

## Security Best-Practices Checklist

- [x] Service requires authentication (unauthenticated requests rejected).
- [x] MFA / second factor implemented and validated.
- [x] Authorization enforced by RBAC (least privilege; unauthorised actions denied).
- [x] Network segmented so the data tier is unreachable from the front tier.
- [x] Default-deny firewall with explicit allow rules.
- [x] Container hardened: non-root, minimal, capabilities dropped, read-only; image scanned.

---

## Conclusion

This lab walked through the two core questions of access control — authentication and authorization — and extended them into network-level defence with segmentation, a default-deny firewall, and container hardening. Several of the troubleshooting steps turned into the most instructive parts of the exercise: the nginx `return`-vs-`root` phase-order issue in Task 1 was a genuine fail-open security flaw hiding behind a config that looked correct, and the `apk` vs `apt-get` mismatch in Task 4 was a reminder to verify that a test command actually executed before trusting its result. Both reinforce a theme running through the whole lab — security controls must be tested against real behaviour, not assumed to work because the configuration reads correctly.
