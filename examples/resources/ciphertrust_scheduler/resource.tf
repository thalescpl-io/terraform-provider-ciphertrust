# Specify the Terraform block to define required providers and their versions.
terraform {
  required_providers {
    ciphertrust = {
      # Define the provider source and version.
      source = "thalesgroup.com/oss/ciphertrust"
      version = "1.0.0"
    }
  }
}

# Configure the CipherTrust provider with connection details.
provider "ciphertrust" {
  # Address of the CipherTrust Manager.
  address = "https://54.159.702.196"
  # Username for authentication.
  username = "admin"
  # Password for authentication.
  password = "SamplePass@12"
  bootstrap = "no"
}

# Define a resource block to configure a scheduler in CipherTrust.
resource "ciphertrust_scheduler" "scheduler" {
  # Name of the scheduler.
  name = "db_backup1-terraform"
  # Type of operation the scheduler will perform.
  operation = "database_backup"
  # Description of the scheduler.
  description = "This is to backup db updated cancelleed"
  # Specify when the scheduler should run (e.g., "any" for no specific conditions).
  run_on = "any"
  # Cron-style schedule specifying when the job should run. Refer to the schema description to know more about the cron-style
  run_at = "*/15 * * * *"

  # Configuration for the database backup parameters.
  database_backup_params = {
    # Backup ID for the database backup.
    backup_key = "d370535b-a035-4251-9780-e608f713be77"
    # SCP Connection ID for the backup operation.
    connection = "f9a81705-2b73-4a9c-9ab3-d78502ff11f1"
    # Description of the backup job.
    description = "sample description"
    # Indicates if SCP should be used for the backup (false in this case).
    do_scp = false
    # Scope of the backup (e.g., "system","domain").
    scope = "system"
    # Indicates if the backup is tied to an HSM (false in this case).
    tied_to_hsm = false
  }
}

# Output block to display details of the created scheduler resource.
output "scheduler" {
  # Outputs all attributes of the scheduler resource.
  value = ciphertrust_scheduler.scheduler
}
