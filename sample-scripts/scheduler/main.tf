terraform {
  required_providers {
    ciphertrust = {
      source = "thalesgroup.com/oss/ciphertrust"
      version = "1.0.0"
    }
  }
}
provider "ciphertrust" {
  address = "https://56.759.102.166"
  username = "admin"
  password = "Sample@34"
  bootstrap = "no"
}

resource "ciphertrust_scheduler" "scheduler" {
  name = "db_backup1-terraform"
  operation = "database_backup"
  description = "This is to backup db updated cancelleed"
  run_on = "any"
  run_at = "*/15 * * * *"
  database_backup_params = {
    backup_key = "d370535b-a035-4251-9780-e608f713be77"
    connection = "f9a81705-2b73-4a9c-9ab3-d78502ff11f1"
    description = "sample des updated"
    do_scp = false
    scope = "system"
    tied_to_hsm = false
  }
}

output "scheduler" {
  value = ciphertrust_scheduler.scheduler
}
