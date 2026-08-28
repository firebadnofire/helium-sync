use std::path::Path;

use directories::BaseDirs;
use helium_sync_profile::{BookmarkStatus, DiscoveryOptions, discover};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let report = discover(&DiscoveryOptions::from_environment())?;
    let executable = report
        .installation
        .executable
        .as_deref()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .unwrap_or("not reported");
    println!("installation: {:?}", report.installation.source);
    println!("executable: {executable}");
    println!(
        "user data: {}",
        sanitized_path(&report.installation.user_data_dir)
    );
    println!("profiles: {}", report.profiles.len());
    for profile in report.profiles {
        let bookmark_status = match profile.bookmark_status {
            BookmarkStatus::Missing => "missing",
            BookmarkStatus::Readable => "readable",
            BookmarkStatus::Invalid(_) => "invalid",
        };
        println!(
            "- {} ({bookmark_status}) at {}",
            profile.directory_name,
            sanitized_path(&profile.path)
        );
    }
    Ok(())
}

fn sanitized_path(path: &Path) -> String {
    if let Some(base) = BaseDirs::new()
        && let Ok(relative) = path.strip_prefix(base.home_dir())
    {
        return Path::new("~").join(relative).display().to_string();
    }
    path.display().to_string()
}
