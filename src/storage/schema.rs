use chrono::{SecondsFormat, Utc};
use rusqlite::{Connection, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::error::CarlError;
use crate::memory::{
    MAX_MEMORY_CONTENT_BYTES, MAX_MEMORY_PROVENANCE_BYTES, validate_memory_capture_text,
};
use crate::security::SecretFilter;

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
    Migration {
        version: 4,
        name: "proposal artifacts",
        sql: include_str!("../../migrations/0004_proposal_artifacts.sql"),
    },
    Migration {
        version: 5,
        name: "verifications",
        sql: include_str!("../../migrations/0005_verifications.sql"),
    },
    Migration {
        version: 6,
        name: "memory system",
        sql: include_str!("../../migrations/0006_memory_system.sql"),
    },
    Migration {
        version: 7,
        name: "ACP frontends",
        sql: include_str!("../../migrations/0007_acp_frontends.sql"),
    },
    Migration {
        version: 8,
        name: "long-horizon tasks",
        sql: include_str!("../../migrations/0008_long_horizon_tasks.sql"),
    },
    Migration {
        version: 9,
        name: "trusted frontend owners",
        sql: include_str!("../../migrations/0009_trusted_frontend_owners.sql"),
    },
    Migration {
        version: 10,
        name: "durable task controls",
        sql: include_str!("../../migrations/0010_durable_task_controls.sql"),
    },
    Migration {
        version: 11,
        name: "service task receipts",
        sql: include_str!("../../migrations/0011_service_task_receipts.sql"),
    },
    Migration {
        version: 12,
        name: "service command receipts",
        sql: include_str!("../../migrations/0012_service_command_receipts.sql"),
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
            Some(checksum) if migration_checksum_matches(expected, checksum) => {}
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
        if migration.version == 6 {
            scrub_unsafe_migrated_memories(&transaction)?;
        }
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

fn scrub_unsafe_migrated_memories(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<(), CarlError> {
    transaction
        .execute(
            "DELETE FROM memories
             WHERE length(CAST(content AS BLOB)) > ?1
                OR length(CAST(provenance AS BLOB)) > ?2
                OR length(trim(content)) = 0
                OR length(trim(provenance)) = 0",
            params![MAX_MEMORY_CONTENT_BYTES, MAX_MEMORY_PROVENANCE_BYTES],
        )
        .map_err(storage_error)?;

    let unsafe_ids = {
        let mut statement = transaction
            .prepare("SELECT id, content, provenance FROM memories")
            .map_err(storage_error)?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?
            .into_iter()
            .filter_map(|(id, content, provenance)| {
                (!migration_memory_is_safe(&content, &provenance)).then_some(id)
            })
            .collect::<Vec<_>>()
    };
    for id in unsafe_ids {
        transaction
            .execute("DELETE FROM memories WHERE id = ?1", [id])
            .map_err(storage_error)?;
    }
    Ok(())
}

fn migration_memory_is_safe(content: &str, provenance: &str) -> bool {
    let valid_controls = |value: &str| {
        !value.contains('\0')
            && !value
                .chars()
                .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    };
    !content.trim().is_empty()
        && !provenance.trim().is_empty()
        && valid_controls(content)
        && valid_controls(provenance)
        && SecretFilter.inspect(content.as_bytes()).is_ok()
        && SecretFilter.inspect(provenance.as_bytes()).is_ok()
        && validate_memory_capture_text(content).is_ok()
        && validate_memory_capture_text(provenance).is_ok()
}

fn migration_checksum(migration: &Migration) -> String {
    // Git may materialize checked-out SQL as CRLF on Windows. New ledger
    // entries use one LF-normalized digest so databases remain portable.
    checksum_sql(&migration.sql.replace("\r\n", "\n"))
}

fn migration_checksum_matches(migration: &Migration, applied: &str) -> bool {
    let normalized = migration.sql.replace("\r\n", "\n");
    // Accept the equivalent historical CRLF digest without rewriting an
    // existing ledger created by earlier Windows builds.
    applied == checksum_sql(&normalized)
        || applied == checksum_sql(&normalized.replace('\n', "\r\n"))
}

fn checksum_sql(sql: &str) -> String {
    format!("{:x}", Sha256::digest(sql.as_bytes()))
}

fn storage_error(error: rusqlite::Error) -> CarlError {
    CarlError::Storage {
        detail: error.to_string(),
    }
}
