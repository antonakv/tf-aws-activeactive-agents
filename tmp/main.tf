terraform {
  required_providers {
    tfe = {
      version = "~> 0.36.0"
    }
  }
}

provider "tfe" {
  hostname = "unuytfeaa.akulov.cc"
  token    = "nAunbiLaOx72EQ.atlasv1.ppb9Y6quZ7Domm5VyKJBV0u5Our4WPCpslApIJmEZUbRLXrziqBSjbIzvN4YeHbo0mk"
}

resource "tfe_organization" "org1" {
  name  = "org1"
  email = "aakulov@hashicorp.com"
}

resource "tfe_agent_pool" "pool1" {
  name         = "pool1"
  organization = tfe_organization.org1.name
}
