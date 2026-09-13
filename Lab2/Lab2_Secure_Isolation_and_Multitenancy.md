# Lab 2 — Secure Isolation & Multi-Tenancy

## Course Info

| Item | Details |
|---|---|
| Course Code | IKB42603 |
| Course Name | Cloud Computing Security Essentials |
| Lab Title | Lab 2 — Secure Isolation & Multi-Tenancy (Weeks 3–4) |
| Institution | UniKL MIIT |
| Lecturer | Prof. Dr. Shahrulniza Musa |
| Student Name | NURSYAFINA BINTI RAMLI |
| Student ID | 52215124843 |
| Environment | Kali Linux (Rolling 2026.2) on VMware Workstation |
| Tools Used | Docker, kind v0.23.0, kubectl v1.33.4, Calico CNI v3.27.0 |
| GitHub Repo | [IKB42603-CLOUD-COMPUTING-SECURITY-ESSENTIALS](https://github.com/nurrsyafina/IKB42603-CLOUD-COMPUTING-SECURITY-ESSENTIALS) |

---

## Objective

This lab demonstrates the three core dimensions of multi-tenant cloud isolation — **compute**, **network**, and **storage** — through hands-on Kubernetes and Docker exercises. The lab is structured to first **expose** the default-open risk of shared infrastructure (Session A), and then **apply the controls** that properly separate tenants (Session B). By the end of this lab, the following Course Learning Outcome is addressed:

> **CLO2** — Construct secure cloud operations that safeguard data integrity.

Specifically, this lab covers:
1. Compute isolation via Kubernetes namespaces and resource quotas.
2. Observing and understanding the default-open behaviour of shared cluster networking.
3. Implementing network isolation using a default-deny `NetworkPolicy`, enforced by Calico CNI.
4. Enforcing storage/API isolation using RBAC (Role-Based Access Control) for per-tenant Secrets.
5. Understanding data remanence and demonstrating secure deletion techniques.

---

## Evidence Folder

| # | Filename | Task | Description |
|---|---|---|---|
| 1 | `Lab2_01_cluster_ready.png` | Setup | Cluster `ccse-lab2` with Calico CNI — node `Ready`, all system pods `Running` |
| 2 | `Lab2_02_task1_tenants_deployed.png` | Task 1 | Pods and services running in `tenant-a` and `tenant-b` |
| 3 | `Lab2_03_task2_before_HTTP200.png` | Task 2 | Cross-tenant probe — **before** NetworkPolicy — `HTTP 200` |
| 4 | `Lab2_04_task3_resourcequota.png` | Task 3 | ResourceQuota applied to `tenant-a` |
| 5 | `Lab2_05_task4_after_HTTP000.png` | Task 4 | Cross-tenant probe — **after** default-deny NetworkPolicy — `HTTP 000` |
| 6 | `Lab2_06_task5_rbac_isolation.png` | Task 5 | RBAC `auth can-i` test — same-namespace `yes`, cross-namespace `no` |
| 7 | `Lab2_07_task6_remanence_scan.png` | Task 6 | Data remanence scan after normal `rm` deletion |
| 8 | `Lab2_08_task6_secure_wipe.png` | Task 6 | Secure wipe using `dd` overwrite before deletion |
| 9 | `Lab2_09_verification.png` | Verification | Final `kubectl get networkpolicy -A` and `resourcequota` check |

*(Screenshots embedded below via GitHub web editor drag-and-drop — see placeholders in each task section.)*

---

## Setup — Cluster with Policy Enforcement

**Command:**
```bash
cat <<EOF | kind create cluster --name ccse-lab2 --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
EOF

kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
kubectl -n kube-system rollout status daemonset/calico-node --timeout=180s
```

**Output:**
Cluster `ccse-lab2` created successfully. Calico manifest applied (CRDs, ClusterRoles, DaemonSet). Initial rollout check timed out due to a host-level resource constraint (`too many open files`, from `fs.inotify` limits being too low for running a simulated multi-node cluster in Docker on the host VM). Root cause was diagnosed via `kubectl logs` on the crashing `kube-proxy` and `calico-node` pods, then resolved by raising the host's `inotify` limits:
```bash
sudo sysctl fs.inotify.max_user_watches=524288
sudo sysctl fs.inotify.max_user_instances=512
```
After the affected pods were deleted and recreated, all `kube-system` pods stabilised to `Running 1/1` and the node reached `Ready`.

**Result:** Cluster fully operational with Calico CNI, which is required for `NetworkPolicy` enforcement (the default `kind` network does not enforce policies).

**Evidence:** `![Cluster Ready](Lab2_01_cluster_ready.png)`

---

## Task 1 — Two Tenants on One Cluster

**Command:**
```bash
kubectl create namespace tenant-a
kubectl create namespace tenant-b

kubectl -n tenant-a create deployment web --image=nginx
kubectl -n tenant-b create deployment web --image=nginx
kubectl -n tenant-a expose deployment web --port=80
kubectl -n tenant-b expose deployment web --port=80
```

**Output:**
Both namespaces created. Each hosts an identical `web` deployment (nginx) and a `ClusterIP` service:
- `tenant-a` service `web` → `10.96.25.211:80`
- `tenant-b` service `web` → `10.96.255.22:80`

**Result:** Two tenants successfully modelled as separate namespaces on the same physical cluster infrastructure, each with their own workload and stable network endpoint.

**Evidence:** `![Task 1 - Tenants Deployed](Lab2_02_task1_tenants_deployed.png)`

---

## Task 2 — Observe the Default-Open Risk

**Command:**
```bash
kubectl -n tenant-a run probe --image=curlimages/curl --restart=Never \
  -- sh -c "curl -s -m 5 http://10.96.255.22 -o /dev/null -w 'HTTP %{http_code}\n'"
kubectl logs probe -n tenant-a
```

**Output:**
```
HTTP 200
```

**Result:** A pod launched in `tenant-a`'s namespace successfully reached `tenant-b`'s service and received a valid HTTP response. This confirms that **namespace separation alone does not provide network isolation** — by default, all pods in a `kind`/Calico cluster can route to one another regardless of namespace. This is the core multi-tenancy risk highlighted in Week 3: on shared infrastructure, isolation must be explicitly configured — it is never automatic.

**Evidence:** `![Task 2 - Before HTTP 200](Lab2_03_task2_before_HTTP200.png)`

---

## Task 3 — Contain the Noisy Neighbour (Resource Quotas)

**Command:**
```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ResourceQuota
metadata:
  name: tenant-a-quota
  namespace: tenant-a
spec:
  hard:
    requests.cpu: "1"
    requests.memory: 512Mi
    pods: "5"
EOF

kubectl describe resourcequota tenant-a-quota -n tenant-a
```

**Output:**
```
Resource          Used  Hard
--------          ----  ----
pods              1     5
requests.cpu      0     1
requests.memory   0     512Mi
```

**Result:** A hard resource ceiling is now enforced on `tenant-a` at the namespace level. Any workload exceeding these limits (excess CPU/memory requests or pod count) will be rejected by the Kubernetes API's admission control — preventing one tenant from exhausting shared node capacity and causing a Denial-of-Service (DoS) condition against co-located tenants. This addresses the **availability** dimension of the CIA triad, which is distinct from the confidentiality/integrity concerns addressed by network and RBAC isolation.

**Evidence:** `![Task 3 - ResourceQuota](Lab2_04_task3_resourcequota.png)`

---

## Task 4 — Default-Deny Network Isolation

**Command:**
```bash
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: tenant-b
spec:
  podSelector: {}
  policyTypes: [Ingress]
EOF

kubectl -n tenant-a run probe --image=curlimages/curl --restart=Never \
  -- sh -c "curl -s -m 5 http://10.96.255.22 -o /dev/null -w 'HTTP %{http_code}\n'"
kubectl logs probe -n tenant-a
```

**Output:**
```
HTTP 000
```

**Result:** The exact same probe that returned `HTTP 200` in Task 2 now returns `HTTP 000` (connection timeout — no response at all) after the `default-deny-ingress` policy was applied to `tenant-b`. This is a **before/after** comparison that provides direct empirical evidence that Calico is correctly enforcing the NetworkPolicy. Traffic is silently dropped rather than actively refused, which is the correct behaviour for a security-hardened boundary — it avoids leaking information (such as "port closed" vs "host unreachable") to a potential attacker probing from another tenant.

| | Before (Task 2) | After (Task 4) |
|---|---|---|
| Probe result | `HTTP 200` | `HTTP 000` |
| Interpretation | Cross-tenant traffic allowed | Cross-tenant traffic blocked |

**Evidence:** `![Task 4 - After HTTP 000](Lab2_05_task4_after_HTTP000.png)`

---

## Task 5 — Storage & Secret Isolation

**Command:**
```bash
kubectl -n tenant-a create secret generic data --from-literal=value=SECRET_A
kubectl -n tenant-b create secret generic data --from-literal=value=SECRET_B

kubectl -n tenant-a create serviceaccount app-a
kubectl -n tenant-a create role reader --verb=get --resource=secrets
kubectl -n tenant-a create rolebinding rb --role=reader --serviceaccount=tenant-a:app-a

SA=system:serviceaccount:tenant-a:app-a
kubectl auth can-i get secrets -n tenant-a --as=$SA
kubectl auth can-i get secrets -n tenant-b --as=$SA
```

**Output:**
```
yes
no
```

**Result:** The ServiceAccount `app-a`, scoped via a `Role` and `RoleBinding` to only `get secrets` within `tenant-a`, is correctly **permitted** to read secrets in its own namespace but **denied** access to `tenant-b`'s secret. This demonstrates the **Principle of Least Privilege** at the Kubernetes API layer — even though both namespaces reside on the same cluster and API server, RBAC enforces per-tenant boundaries independently of network-level controls.

**Evidence:** `![Task 5 - RBAC Isolation](Lab2_06_task5_rbac_isolation.png)`

---

## Task 6 — Data Remanence & Secure Deletion

**Command (remanence scan):**
```bash
docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE-PATIENT-RECORD > /data/phi.txt; sync; rm /data/phi.txt; \
  grep -a SENSITIVE /data/* 2>/dev/null; echo scan-done'

sudo grep -a "SENSITIVE" /var/lib/docker/volumes/ccse-vol/_data/* 2>/dev/null
```

**Output:**
```
scan-done
scan-done-host-level
```
(No matches found for `SENSITIVE` at either the container filesystem level or the host mountpoint level.)

**Result:** Unlike the textbook expectation, `grep` did not recover any residual plaintext after a normal `rm` deletion in this environment. This is itself a meaningful finding: filesystem-level data remanence is **not reliably reproducible** — it depends heavily on the specific filesystem implementation (ext4 journaling, Docker's overlay driver), block reuse timing, and sync behaviour. This does **not** mean remanence is not a real risk; it means that a simple `rm` is not something to rely on for verifying deletion, and that more forensic-grade tools (e.g. `photorec`, raw disk imaging) would be needed to reliably demonstrate recovery on this particular stack.

**Evidence:** `![Task 6 - Remanence Scan](Lab2_07_task6_remanence_scan.png)`

**Command (secure wipe):**
```bash
docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE > /data/phi2.txt; sync; \
  dd if=/dev/zero of=/data/phi2.txt bs=1k count=1 conv=notrunc; rm /data/phi2.txt; \
  echo wiped'
```

**Output:**
```
1+0 records in
1+0 records out
1024 bytes (1.0KB) copied
wiped
```

**Result:** The file's contents were overwritten with zero-bytes **before** deletion, using `conv=notrunc` to ensure the write targets the same physical block rather than a newly allocated one. This "overwrite-before-delete" approach is a classic secure-deletion technique for traditional spinning disks. However, it has a well-known limitation on modern storage: **SSDs and cloud block storage use wear-levelling**, meaning the firmware may redirect writes to a different physical block rather than truly overwriting the original. This is precisely why cloud environments favour **cryptographic erasure** — destroying the encryption key rather than attempting to physically overwrite data the tenant does not have direct control over.

**Evidence:** `![Task 6 - Secure Wipe](Lab2_08_task6_secure_wipe.png)`

---

## Verification

**Command:**
```bash
kubectl get networkpolicy -A
kubectl describe resourcequota tenant-a-quota -n tenant-a
```

**Output:** Confirms `default-deny-ingress` is still active in `tenant-b`, and `tenant-a-quota` correctly reflects the patched deployment's resource usage (`requests.cpu: 100m/1`, `requests.memory: 128Mi/512Mi`, `pods: 1/5`).

**Evidence:** `![Verification](Lab2_09_verification.png)`

---

## Short-Answer Questions

**Q1. Why can containers in different namespaces reach each other by default, and why is that dangerous in multi-tenant cloud?**

Kubernetes namespaces provide **logical** separation only — they scope resource naming, RBAC, and quotas, but they do **not** create a network boundary. The underlying CNI (Container Network Interface) by default routes all pod IPs on a flat, cluster-wide network, so any pod can reach any other pod's IP/service regardless of namespace unless a `NetworkPolicy` explicitly restricts it. This is dangerous in multi-tenant cloud because a compromised or malicious tenant could scan, probe, or directly attack another tenant's workloads without ever needing to breach an authentication boundary — the network itself offers no resistance by default.

**Q2. Explain the default-deny principle and how your NetworkPolicy implements it.**

The default-deny principle states that all traffic should be blocked unless explicitly permitted — "deny by default, allow by exception." This is the inverse (and safer) approach compared to allowing everything and trying to block known-bad traffic. In this lab, the `default-deny-ingress` NetworkPolicy uses `podSelector: {}` (applies to all pods in `tenant-b`) with `policyTypes: [Ingress]` and **no explicit ingress rules**. Under Kubernetes' NetworkPolicy semantics, a policy that selects pods for a given policy type but defines no matching rules blocks all traffic of that type. This was empirically verified: the same probe returned `HTTP 200` before the policy was applied and `HTTP 000` after.

**Q3. How do virtual machines and containers differ in isolation strength? When would you add a VM boundary?**

Virtual machines isolate tenants at the **hardware/hypervisor level** — each VM has its own kernel, and a VM escape requires breaking the hypervisor itself, which is a much harder attack surface. Containers, by contrast, share the **host kernel**, so isolation relies on kernel-level features (namespaces, cgroups, seccomp) — a kernel vulnerability can potentially allow a container to escape to the host or to other containers on the same node. A VM boundary should be added when tenants have a low level of mutual trust, when regulatory/compliance requirements demand strong isolation (e.g. handling regulated PHI/financial data), or when running untrusted third-party code, since the blast radius of a container-level breakout is far larger than that of a VM breakout.

**Q4. What is data remanence, and why is cryptographic erasure the preferred cloud solution?**

Data remanence refers to residual data that remains physically present on a storage medium after a file has been "deleted." A normal `rm`/delete operation typically only removes the filesystem's pointer/metadata entry to the data — the actual bytes remain on disk until that physical space is reused, potentially allowing recovery by someone with subsequent access to the same storage. Cryptographic erasure — destroying the encryption key used to protect the data, rather than attempting to overwrite every physical block — is preferred in cloud environments because tenants and even cloud providers frequently do **not** have direct control over the physical storage medium (multi-tenant SANs, SSD wear-levelling, distributed/replicated storage). Once the key is destroyed, the ciphertext remaining on disk is computationally infeasible to recover, regardless of where or how many copies of the underlying blocks still physically exist.

**Q5. Which of the three isolation dimensions (compute, network, storage) did each task exercise?**

| Task | Isolation Dimension |
|---|---|
| Task 1 (namespaces, deployments) | Compute |
| Task 2 (cross-tenant probe) | Network (demonstrating the *lack* of it) |
| Task 3 (ResourceQuota) | Compute |
| Task 4 (NetworkPolicy) | Network |
| Task 5 (Secrets + RBAC) | Storage / API access |
| Task 6 (remanence + secure wipe) | Storage |

---

## Security Best-Practices Checklist

- [x] Tenants are separated into distinct namespaces.
- [x] A default-deny NetworkPolicy blocks cross-tenant traffic (verified before/after).
- [x] Resource quotas prevent a noisy-neighbour from exhausting shared capacity.
- [x] Per-tenant secrets are unreadable by other tenants (RBAC enforced).
- [x] Secure deletion / cryptographic erasure is understood for data remanence.

---

## Conclusion

This lab demonstrated, with hands-on empirical evidence, that multi-tenant cloud isolation is **not** a single control but a composition of several independent layers: compute (namespaces, quotas), network (default-deny NetworkPolicy enforced by Calico), and storage/API access (RBAC on Secrets). The most important lesson from Session A was that Kubernetes namespaces alone create **zero** network isolation — the `HTTP 200` result in Task 2 is direct proof that shared infrastructure is "default-open" unless explicitly hardened. Session B then showed that each of these gaps can be closed with concrete, verifiable controls, and that verification (the before/after HTTP 200 → HTTP 000 comparison, and the RBAC `yes`/`no` test) is essential — a control that hasn't been tested empirically cannot be trusted to be working. Finally, the data remanence exercise showed that even well-known techniques like `rm` and overwrite-before-delete have real-world limitations depending on the underlying filesystem and storage hardware, which is precisely why cloud providers rely on cryptographic erasure as the industry-standard approach to guaranteeing data is unrecoverable.
