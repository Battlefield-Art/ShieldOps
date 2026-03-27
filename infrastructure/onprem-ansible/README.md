# ShieldOps On-Premises Deployment (Ansible)

Automated deployment of the full ShieldOps stack on bare-metal or VM infrastructure using K3s, Helm, HAProxy, and Prometheus/Grafana.

## Prerequisites

- **Control machine**: Ansible 2.15+, Python 3.10+
- **Target hosts**: Ubuntu 22.04+ or RHEL 8+ with SSH access and sudo
- **Network**: All nodes reachable from control machine; ports 6443, 80, 443, 8472 open between cluster nodes
- **Hardware minimums**:
  - Master: 4 vCPU, 8 GB RAM, 100 GB disk
  - Workers (3): 4 vCPU, 16 GB RAM, 200 GB disk each
  - Load balancer: 2 vCPU, 4 GB RAM, 20 GB disk

## Quick Start

```bash
# 1. Install Ansible collections
ansible-galaxy collection install community.general ansible.posix

# 2. Copy and customize inventory
cp inventory.yml inventory.local.yml
# Edit inventory.local.yml with your hostnames, IPs, and credentials

# 3. Create encrypted secrets file
ansible-vault create secrets.enc.yml
# Add: vault_postgresql_password, vault_grafana_admin_password, anthropic_api_key

# 4. Run the full playbook
ansible-playbook -i inventory.local.yml playbook.yml \
  -e @secrets.enc.yml --ask-vault-pass

# 5. Run specific stages
ansible-playbook -i inventory.local.yml playbook.yml --tags k3s
ansible-playbook -i inventory.local.yml playbook.yml --tags helm
ansible-playbook -i inventory.local.yml playbook.yml --tags shieldops
ansible-playbook -i inventory.local.yml playbook.yml --tags haproxy
ansible-playbook -i inventory.local.yml playbook.yml --tags monitoring
ansible-playbook -i inventory.local.yml playbook.yml --tags opa
ansible-playbook -i inventory.local.yml playbook.yml --tags healthcheck
```

## Architecture

```
                    Internet
                       |
                  [ HAProxy ]
                  /    |    \
           [Master] [Worker1] [Worker2] [Worker3]
              |        |         |         |
              +--------+---------+---------+
                     K3s Cluster
                         |
         +-------+-------+-------+-------+
         |       |       |       |       |
      ShieldOps  PG    Redis   Kafka   OPA
       (Helm)
```

## What Gets Deployed

| Component | Method | Namespace |
|-----------|--------|-----------|
| K3s cluster | curl installer | system |
| PostgreSQL | Bitnami Helm chart | shieldops |
| Redis | Bitnami Helm chart | shieldops |
| Kafka (3 brokers) | Bitnami Helm chart | shieldops |
| OPA | Bitnami Helm chart | shieldops |
| ShieldOps API + Dashboard | ShieldOps Helm chart | shieldops |
| Prometheus + Grafana | kube-prometheus-stack | monitoring |
| HAProxy | apt/yum package | host |
| TLS certificates | openssl / certbot | host |
| OPA policies | API upload | shieldops |

## Inventory Groups

- **master** -- K3s control plane node(s)
- **workers** -- K3s agent nodes
- **load_balancer** -- HAProxy host(s)

## Tags Reference

| Tag | Description |
|-----|-------------|
| `prereqs` | OS packages, kernel modules, sysctl |
| `k3s` | Install K3s on master + workers |
| `k3s-master` | Master node only |
| `k3s-workers` | Worker nodes only |
| `helm` / `infra` | Deploy PostgreSQL, Redis, Kafka, OPA |
| `postgresql` | PostgreSQL only |
| `redis` | Redis only |
| `kafka` | Kafka only |
| `opa` | OPA deployment |
| `build` | Build Docker images from source |
| `deploy` / `shieldops` | Deploy ShieldOps via Helm |
| `haproxy` / `lb` | Configure HAProxy load balancer |
| `tls` / `certs` | Generate or obtain TLS certificates |
| `monitoring` | Prometheus + Grafana stack |
| `policies` | Load OPA policies (HIPAA, SOC 2, etc.) |
| `healthcheck` / `smoke` | Verify deployment health |

## TLS Modes

Set `tls_mode` in inventory:

- **`self_signed`** (default) -- Generates a 4096-bit RSA certificate valid for 365 days. Suitable for internal/staging environments.
- **`letsencrypt`** -- Obtains a certificate via HTTP-01 challenge. Requires port 80 accessible from the internet and a valid `letsencrypt_email`.

## Air-Gapped Deployments

For environments without internet access:

1. Pre-pull all container images and save as tarballs
2. Set `docker_registry` to your internal registry
3. Push images to internal registry before running the playbook
4. Pre-download Helm charts and use `--set` with local chart paths

## Secrets Management

Never commit secrets to version control. Use one of:

- `ansible-vault` encrypted files (`-e @secrets.enc.yml --ask-vault-pass`)
- `--extra-vars` on the command line
- HashiCorp Vault lookup plugin
- Environment variables with `lookup('env', 'VAR')`

Required secrets:
- `vault_postgresql_password` -- PostgreSQL password
- `vault_grafana_admin_password` -- Grafana admin password
- `anthropic_api_key` -- Anthropic Claude API key (optional)
- `jwt_secret_key` -- JWT signing key for API auth

## Post-Deployment

After a successful deployment:

1. Access the dashboard at `https://<shieldops_domain>/`
2. Access the API at `https://<shieldops_domain>/api/v1`
3. Access Grafana at `http://<master_ip>:30300` (admin / your password)
4. Access HAProxy stats at `http://<lb_ip>:8404/stats`
5. Get kubeconfig from `/tmp/shieldops-kubeconfig.yaml`

## Troubleshooting

```bash
# Check K3s status
ssh master sudo systemctl status k3s

# Check pod status
ssh master sudo k3s kubectl get pods -n shieldops

# View ShieldOps API logs
ssh master sudo k3s kubectl logs -n shieldops -l app.kubernetes.io/name=shieldops --tail=100

# Check HAProxy status
ssh lb sudo systemctl status haproxy
ssh lb sudo haproxy -c -f /etc/haproxy/haproxy.cfg
```
