# Overview
*db_backup.py* is a _Python_ script for backing up _MySQL/MariaDB_ databases to an _S3_ bucket or a local directory.
Databases are read using _mysqldump_ and backed up using _rclone_.

In an attempt to complete as many backups as possible, the script will
not exit on an error, but will report a non 0 exit code after all backups
have been attempted.

Logging is to _standard out_ only, unless a log file
is specified with the flag _--log-file_, in which case messages are also logged to the file.
The configuration file is _/etc/backups.yaml_ unless a file is specified with the flag _--config_.

# Configuration
You can configure as many _backups_ as you want. Each _backup_ needs a _source_ and a _destination_.
A source can specify more than one database to be backed up.

```
rootdir: my_database_backups
rclone_config: /etc/rclone.conf
timeout: 600
loglevel: info
backups:
  backup_01:
    source:
      type: mysql
      host: db1.example.com
      port: 3306
      user: read_only_user
      password: 123456
      databases: [mysql, sys]
    destination:
      type: s3
      access_key_id: my_access_key_id
      bucket: my_bucket
      endpoint: my_endpoint
      secret_access_key: my_secret_access_key
  backup_02:
    source:
      type: mysql
      host: db2.example.com
      port: 3306
      user: read_only_user
      password: 654321
      databases: [sys]
      single-transaction: No
    destination:
      type: local
      path: /var/backups
```

* In _source_, _single-transaction_ defaults to _Yes_. This will dump _InnoDB_ databases without the need to lock them. 
* In _source_, _port_ defaults to the standard _MySQL_ port _3306_.

Environment variables *S3_BUCKET*, *S3_ENDPOINT*, *S3_ACCESS_KEY_ID* and *S3_SECRET_ACCESS_KEY* will be used
if matching parameters are not set in an S3 destination. This allows for simpler configuration if many
sources are to be backed up to single S3 destination. 

 
# Running db-backup
How to run db-backup.

## In Kubernetes with Helm

* Check out repository
* Go to dir _helm_
* Copy *my_values.yaml* to *my_values.local.yaml*
* Add your configuration to *my_values.local.yaml*
* See Kubernetes files to be generated: `helm template -f my_values.local.yaml db-backup`
* Install in Kubernetes as _my-db-backup_: `helm install my-db-backup db-backup -f my_values.local.yaml`

When updating configuration in _my_values.local.yaml_ in the future, the following command can be used to upgrade the running release:
`helm upgrade my-db-backup db-backup -f my_values.local.yaml`

## In Docker
* Check out repository
* Build image: `docker build -t ddb .`
* Create a local config file (External to the container) at _/local/backups/backups.yaml_
* Run container once, and delete it: `docker run --rm ddb -v /local/backups:/etc/backups`

## Locally

* Check out repository
* Go to dir _src_
* Copy *backups.yaml* to *backups.local.yaml*
* Add your configuration to *backups.local.yaml*
* Run with : `./do-db-backup.py --config ./backups.local.yaml`


# To do
- [x] Add backend _local_
- [ ] Add config parameter for expected size of backup. Throw error/warning if backup is too small
- [ ] Add other rclone backends by looking at (rclone config)[https://rclone.org/s3/#wasabi]
- [ ] Setting for max number of backups? Max age?
- [ ] Add option for encrypting backed up files
- [ ] Support encrypted MySQL connections
- [ ] Support dumping of all databases without naming them. (Could be default, if no databases mentioned)
- [ ] Validate configuration values
- [ ] Add helm chart to public repo
- [x] Exit code should be non 0 if any errors occured during the backup run
