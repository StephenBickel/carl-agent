use chrono::{SecondsFormat, Utc};
use rusqlite::{Connection, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::error::CarlError;

struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "initial schema",
        sql: include_str!("../../migrations/0001_init.sql"),
    },
    Migration {
        version: 2,
        name: "bound approvals",
        sql: include_str!("../../migrations/0002_bound_approvals.sql"),
    },
    Migration {
        version: 3,
        name: "subscription runs",
        sql: include_str!("../../migrations/0003_subscription_runs.sql"),
    },
];

pub(crate) fn migrate(connection: &mut Connection) -> Result<(), CarlError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(storage_error)?;

    transaction
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL,
                checksum TEXT NOT NULL
            );",
        )
        .map_err(storage_error)?;

    let applied = {
        let mut statement = transaction
            .prepare("SELECT version, name, checksum FROM migrations ORDER BY version")
            .map_err(storage_error)?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?
    };

    if let Some((version, _, _)) = applied.last()
        && usize::try_from(*version).map_or(true, |version| version > MIGRATIONS.len())
    {
        return Err(CarlError::Storage {
            detail: format!("unsupported database migration version {version}"),
        });
    }

    for (index, (version, name, checksum)) in applied.iter().enumerate() {
        let expected = &MIGRATIONS[index];
        if *version != expected.version {
            return Err(CarlError::Storage {
                detail: format!(
                    "inconsistent migration ledger: expected version {}, found {version}",
                    expected.version
                ),
            });
        }
        if name != expected.name {
            return Err(CarlError::Storage {
                detail: format!("migration {version} name mismatch: found {name:?}"),
            });
        }
        let expected_checksum = migration_checksum(expected);
        match checksum {
            Some(checksum) if *checksum == expected_checksum => {}
            Some(checksum) => {
                return Err(CarlError::Storage {
                    detail: format!(
                        "migration {version} checksum mismatch: expected {expected_checksum}, found {checksum}"
                    ),
                });
            }
            None => {
                return Err(CarlError::Storage {
                    detail: format!("migration {version} checksum is missing"),
                });
            }
        }
    }

    for migration in &MIGRATIONS[applied.len()..] {
        let checksum = migration_checksum(migration);
        transaction
            .execute_batch(migration.sql)
            .map_err(storage_error)?;
        transaction
            .execute(
                "INSERT INTO migrations (version, name, applied_at, checksum)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    migration.version,
                    migration.name,
                    Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true),
                    checksum,
                ],
            )
            .map_err(storage_error)?;
    }

    transaction.commit().map_err(storage_error)
}

fn migration_checksum(migration: &Migration) -> String {
    format!("{:x}", Sha256::digest(migration.sql.as_bytes()))
}

fn storage_error(error: rusqlite::Error) -> CarlError {
    CarlError::Storage {
        detail: error.to_string(),
    }
}
