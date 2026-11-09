#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use strongroom_api::db::connect_pool;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let migrator_url = env::var("MIGRATOR_DATABASE_URL")
        .map_err(|_| "missing required environment variable: MIGRATOR_DATABASE_URL")?;

    if migrator_url.trim().is_empty() {
        return Err("MIGRATOR_DATABASE_URL must not be empty".into());
    }

    let pool = connect_pool(&migrator_url).await?;

    let current_user: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&pool)
        .await?;

    if current_user == "vault_app" {
        return Err(
            "refusing to run migrations as vault_app; MIGRATOR_DATABASE_URL must use vault_migrator"
                .into(),
        );
    }

    sqlx::migrate!("./migrations").run(&pool).await?;

    Ok(())
}
