terraform {
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.38.2"
    }

    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "5.2.0"
    }
  }

  required_version = ">= 1.4.4"
}


locals {
  web-ip                 = "65.109.240.127"
  cloudflare_dns_zone_id = "621fc491908c6181271f4101cecb574c"

  server_settings = {
    web = {
      "web1.livectf.local" = { ip = "10.0.1.11", external_ip = local.web-ip, type = "cpx51", labels = { bastion = 1, web = 1, database = 1, registry = 1, rabbitmq = 1, redis = 1 } },
    }
    builders = {
      #"builder01.livectf.local" = { ip = "10.0.2.11", type = "cpx51", labels = { builder = 1 } },
      #"builder02.livectf.local" = { ip = "10.0.2.12", type = "cpx51", labels = { builder = 1 } },
      #"builder03.livectf.local" = { ip = "10.0.2.13", type = "cpx51", labels = { builder = 1 } },
      #"builder04.livectf.local" = { ip = "10.0.2.14", type = "cpx51", labels = { builder = 1 } },
      #"builder05.livectf.local" = { ip = "10.0.2.15", type = "cpx51", labels = { builder = 1 } },
      #"builder06.livectf.local" = { ip = "10.0.2.16", type = "cpx51", labels = { builder = 1 } },
      #"builder07.livectf.local" = { ip = "10.0.2.17", type = "cpx51", labels = { builder = 1 } },
      #"builder08.livectf.local" = { ip = "10.0.2.18", type = "cpx51", labels = { builder = 1 } },
      #"builder09.livectf.local" = { ip = "10.0.2.19", type = "cpx51", labels = { builder = 1 } },
      #"builder10.livectf.local" = { ip = "10.0.2.20", type = "cpx51", labels = { builder = 1 } },
      #"builder11.livectf.local" = { ip = "10.0.2.21", type = "cpx51", labels = { builder = 1 } },
      #"builder12.livectf.local" = { ip = "10.0.2.22", type = "cpx51", labels = { builder = 1 } },
      #"builder13.livectf.local" = { ip = "10.0.2.23", type = "cpx51", labels = { builder = 1 } },
      #"builder14.livectf.local" = { ip = "10.0.2.24", type = "cpx51", labels = { builder = 1 } },
      #"builder15.livectf.local" = { ip = "10.0.2.25", type = "cpx51", labels = { builder = 1 } },
      #"builder16.livectf.local" = { ip = "10.0.2.26", type = "cpx51", labels = { builder = 1 } },
      #"builder17.livectf.local" = { ip = "10.0.2.27", type = "cpx51", labels = { builder = 1 } },
      #"builder18.livectf.local" = { ip = "10.0.2.28", type = "cpx51", labels = { builder = 1 } },
      #"builder19.livectf.local" = { ip = "10.0.2.29", type = "cpx51", labels = { builder = 1 } },
      #"builder20.livectf.local" = { ip = "10.0.2.30", type = "cpx51", labels = { builder = 1 } },

    }
    runners = {
      #"runner01.livectf.local" = { ip = "10.0.3.11", type = "cpx51", labels = { runner = 1 } },
      #"runner02.livectf.local" = { ip = "10.0.3.12", type = "cpx51", labels = { runner = 1 } },
      #"runner03.livectf.local" = { ip = "10.0.3.13", type = "cpx51", labels = { runner = 1 } },
      #"runner04.livectf.local" = { ip = "10.0.3.14", type = "cpx51", labels = { runner = 1 } },
      #"runner05.livectf.local" = { ip = "10.0.3.15", type = "cpx51", labels = { runner = 1 } },
      #"runner06.livectf.local" = { ip = "10.0.3.16", type = "cpx51", labels = { runner = 1 } },
      #"runner07.livectf.local" = { ip = "10.0.3.17", type = "cpx51", labels = { runner = 1 } },
      #"runner08.livectf.local" = { ip = "10.0.3.18", type = "cpx51", labels = { runner = 1 } },
      #"runner09.livectf.local" = { ip = "10.0.3.19", type = "cpx51", labels = { runner = 1 } },
      #"runner10.livectf.local" = { ip = "10.0.3.20", type = "cpx51", labels = { runner = 1 } },
    }
    monitor = {
      "monitor.livectf.local" = { ip = "10.0.1.81", type = "cpx51", labels = { monitor = 1 } },
    }
  }

  sshkeys = ["negasora", "psifertex1", "psifertex2", "CouleeApps1", "CouleeApps2", "ZetaTwo2018"]
}

variable "hcloud_token" {
  sensitive = true # Requires terraform >= 0.14
}

variable "cloudflare_api_token" {
  sensitive = true # Requires terraform >= 0.14
}

#variable "cloudflare_zone_id" {
#  sensitive = false # Requires terraform >= 0.14
#}

# TODO(P4): apprently Hetzner DNS doesn't support .dev TLD
#variable "hcloud_dns_token" {
#  sensitive = true # Requires terraform >= 0.14
#}

provider "hcloud" {
  token = var.hcloud_token
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

# TODO(P4): apprently Hetzner DNS doesn't support .dev TLD
#provider "hetznerdns" {
#  apitoken = var.hcloud_dns_token
#}

data "hcloud_floating_ip" "web-ip" {
  ip_address = local.web-ip
}

data "cloudflare_zone" "livectf-com" {
  zone_id = local.cloudflare_dns_zone_id
}

resource "cloudflare_dns_record" "livectf-play" {
  zone_id = data.cloudflare_zone.livectf-com.zone_id
  comment = "LiveCTF web server"
  content = data.hcloud_floating_ip.web-ip.ip_address
  name    = "play.livectf.com"
  proxied = false
  ttl  = 600
  type = "A"
}

resource "hcloud_floating_ip_assignment" "web-ip-assignment" {
  floating_ip_id = data.hcloud_floating_ip.web-ip.id
  server_id      = hcloud_server.livectf-web["web1.livectf.local"].id
}

resource "hcloud_network" "network" {
  name     = "livectf-network"
  labels   = {}
  ip_range = "10.0.0.0/16"
}

resource "hcloud_network_subnet" "main-subnet" {
  type         = "cloud"
  network_id   = hcloud_network.network.id
  network_zone = "eu-central"
  ip_range     = "10.0.1.0/24"
}

resource "hcloud_network_subnet" "builder-subnet" {
  type         = "cloud"
  network_id   = hcloud_network.network.id
  network_zone = "eu-central"
  ip_range     = "10.0.2.0/24"
}

resource "hcloud_network_subnet" "runner-subnet" {
  type         = "cloud"
  network_id   = hcloud_network.network.id
  network_zone = "eu-central"
  ip_range     = "10.0.3.0/24"
}

resource "hcloud_server" "livectf-builder" {
  for_each = local.server_settings.builders

  name        = each.key
  server_type = each.value.type
  image       = "ubuntu-22.04"
  location    = "hel1"
  ssh_keys    = local.sshkeys
  labels      = each.value.labels

  network {
    network_id = hcloud_network.network.id
    ip         = each.value.ip
  }

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  depends_on = [
    hcloud_network_subnet.builder-subnet
  ]
}

resource "hcloud_volume" "livectf-builder" {
  for_each = local.server_settings.builders

  name      = format("storage.%s", each.key)
  size      = 50
  server_id = hcloud_server.livectf-builder[each.key].id
  automount = false
  format    = "xfs"
  labels    = { role : "docker" }
}

resource "hcloud_server" "livectf-runner" {
  for_each = local.server_settings.runners

  name        = each.key
  server_type = each.value.type
  image       = "ubuntu-22.04"
  location    = "hel1"
  ssh_keys    = local.sshkeys
  labels      = each.value.labels

  network {
    network_id = hcloud_network.network.id
    ip         = each.value.ip
  }

  public_net {
    ipv4_enabled = false
    ipv6_enabled = true
  }

  depends_on = [
    hcloud_network_subnet.runner-subnet
  ]
}

resource "hcloud_volume" "livectf-runner" {
  for_each = local.server_settings.runners

  name      = format("storage.%s", each.key)
  size      = 50
  server_id = hcloud_server.livectf-runner[each.key].id
  automount = false
  format    = "xfs"
  labels    = { role : "docker" }
}

resource "hcloud_server" "livectf-web" {
  for_each = local.server_settings.web

  name        = each.key
  server_type = each.value.type
  image       = "ubuntu-22.04"
  location    = "hel1"
  ssh_keys    = local.sshkeys
  labels      = each.value.labels

  network {
    network_id = hcloud_network.network.id
    ip         = each.value.ip
  }

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  depends_on = [
    hcloud_network_subnet.main-subnet
  ]
}

#resource "cloudflare_record" "example" {
#  zone_id = var.cloudflare_zone_id
#  name    = "web.livectf.zetatwo.dev"
#  value   = hcloud_server.livectf-web.ipv4_address
#  type    = "A"
#  ttl     = 3600
#}

resource "hcloud_server" "livectf-monitor" {
  for_each = local.server_settings.monitor

  name        = each.key
  server_type = each.value.type
  image       = "ubuntu-22.04"
  location    = "hel1"
  ssh_keys    = local.sshkeys
  labels      = each.value.labels

  network {
    network_id = hcloud_network.network.id
    ip         = each.value.ip
  }

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  depends_on = [
    hcloud_network_subnet.main-subnet
  ]
}

#resource "cloudflare_record" "example" {
#  zone_id = var.cloudflare_zone_id
#  name    = "monitor.livectf.zetatwo.dev"
#  value   = hcloud_server.livectf-monitor.ipv4_address
#  type    = "A"
#  ttl     = 3600
#}

# generate inventory file for Ansible
resource "local_file" "hosts_ansible_inventory" {
  content = templatefile("${path.module}/hosts.tpl",
    {
      livectf-web             = hcloud_server.livectf-web
      livectf-builder         = hcloud_server.livectf-builder
      livectf-builder-volumes = hcloud_volume.livectf-builder
      livectf-runner          = hcloud_server.livectf-runner
      livectf-runner-volumes  = hcloud_volume.livectf-runner
      livectf-monitor         = hcloud_server.livectf-monitor
      livectf-all             = merge(hcloud_server.livectf-web, hcloud_server.livectf-builder, hcloud_server.livectf-runner, hcloud_server.livectf-monitor)

      server_settings = merge(local.server_settings.web, local.server_settings.builders, local.server_settings.runners, local.server_settings.monitor)
      #subnet = hcloud_network_subnet.network-subnet
      subnet = hcloud_network.network # TODO(P3): is this safe?
    }
  )
  filename        = "hosts.yml"
  file_permission = "0644"
}

# generate SSH config file
resource "local_file" "hosts_ssh_config" {
  content = templatefile("${path.module}/hosts.ssh.tpl",
    {
      livectf-web             = hcloud_server.livectf-web
      livectf-builder         = hcloud_server.livectf-builder
      livectf-builder-volumes = hcloud_volume.livectf-builder
      livectf-runner          = hcloud_server.livectf-runner
      livectf-runner-volumes  = hcloud_volume.livectf-runner
      livectf-monitor         = hcloud_server.livectf-monitor
      livectf-all             = merge(hcloud_server.livectf-web, hcloud_server.livectf-builder, hcloud_server.livectf-runner, hcloud_server.livectf-monitor)

      server_settings = merge(local.server_settings.web, local.server_settings.builders, local.server_settings.runners, local.server_settings.monitor)
    }
  )
  filename        = "hosts.ssh.conf"
  file_permission = "0644"
}
