use std::ffi::OsStr;
use std::fs;
use std::fs::Metadata;
use std::io::ErrorKind;
use std::os::linux::fs::MetadataExt;
use std::path;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use clap::Parser;
use fuser::Config;
use fuser::Errno;
use fuser::FileAttr;
use fuser::FileHandle;
use fuser::FileType;
use fuser::Filesystem;
use fuser::INodeNo;
use fuser::MountOption;
use fuser::ReplyAttr;
use fuser::ReplyData;
use fuser::ReplyDirectory;
use fuser::ReplyEntry;
use fuser::Request;
use sysinfo::Uid;
use sysinfo::Users;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Directory to mount FUSE fs to (parent of the .linuxbrew folder)
    #[arg(short, long, default_value_t = "/home/linuxbrew".to_string())]
    mount_point: String,

    /// Prefix for storing the symlinked folder 
    /// 
    /// .linuxbrew will be linked to [prefix]/USER/[folder name]
    #[arg(short, long, default_value_t = "/home/".to_string())]
    link_prefix: String,

    /// name of folder symlinked to .linuxbrew.
    /// 
    /// Sets name in PREFIX/USER/[name]
    #[arg(short, long, default_value_t = ".userbrew".to_string())]
    name: String,

    #[arg(short, long, default_value_t = false)]
    single_user: bool,
}

const TTL: Duration = Duration::from_secs(1); // 1 second
const SYMLINK_INO: u64 = 2;

struct TimeMetadata {
    accessed: SystemTime,
    created: SystemTime,
    changed: SystemTime,
    modified: SystemTime,
}

impl TimeMetadata {
    fn from_metadata(meta: Metadata) -> TimeMetadata {
        let changed_time = meta.st_ctime();
        let ctime_duration = Duration::from_secs(
            changed_time
                .abs()
                .try_into()
                .expect("ctime duration should be positive"),
        );
        let ctime_opt = if changed_time >= 0 {
            UNIX_EPOCH.checked_add(ctime_duration)
        } else {
            UNIX_EPOCH.checked_sub(ctime_duration)
        };
        let ctime = if let Some(ctime_inner) = ctime_opt {
            ctime_inner
        } else {
            UNIX_EPOCH
        };
        TimeMetadata {
            accessed: meta.accessed().unwrap_or(UNIX_EPOCH),
            created: meta.created().unwrap_or(UNIX_EPOCH),
            modified: meta.modified().unwrap_or(UNIX_EPOCH),
            changed: ctime,
        }
    }
}

fn get_username(uid: u32) -> String {
    let users = Users::new_with_refreshed_list();
    let uid = Uid::from_str(&uid.to_string()).unwrap();
    users.get_user_by_id(&uid).unwrap().name().to_string()
}

struct UserBrewFS {
    mount_metadata: TimeMetadata,
    userbrew_prefix: PathBuf,
    userbrew_name: PathBuf,
}

impl UserBrewFS {
    fn new(meta: TimeMetadata, prefix: PathBuf, userbrew_name: PathBuf) -> UserBrewFS {
        UserBrewFS {
            mount_metadata: meta,
            userbrew_prefix: prefix,
            userbrew_name: userbrew_name,
        }
    }

    fn build_root_attr(&self, uid: u32, gid: u32) -> FileAttr {
        FileAttr {
            ino: INodeNo::ROOT,
            size: 0,
            blocks: 0,
            atime: self.mount_metadata.accessed,
            mtime: self.mount_metadata.modified,
            ctime: self.mount_metadata.changed,
            crtime: self.mount_metadata.created,
            kind: FileType::Directory,
            perm: 0o554, // no write permissions, (cant write to the fs anyways)
            nlink: 1,
            uid: uid,
            gid: gid,
            rdev: 0,
            flags: 0,
            blksize: 4096,
        }
    }

    fn build_symlink_attr(&self, uid: u32, gid: u32) -> FileAttr {
        FileAttr {
            ino: INodeNo(SYMLINK_INO),
            size: 0,
            blocks: 0,
            atime: self.mount_metadata.accessed,
            mtime: self.mount_metadata.modified,
            ctime: self.mount_metadata.changed,
            crtime: self.mount_metadata.created,
            kind: FileType::Symlink,
            perm: 0o554, // no write permissions, (cant write to the fs anyways)
            nlink: 1,
            uid: uid,
            gid: gid,
            rdev: 0,
            flags: 0,
            blksize: 4096,
        }
    }
}

impl Filesystem for UserBrewFS {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if u64::from(parent) == 1 && name.to_str() == Some(".linuxbrew") {
            let attr = self.build_symlink_attr(_req.uid(), _req.gid());
            reply.entry(&TTL, &attr, fuser::Generation(0));
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match u64::from(ino) {
            1 => {
                let attr = self.build_root_attr(_req.uid(), _req.gid());
                reply.attr(&TTL, &attr)
            }
            SYMLINK_INO => {
                let attr = self.build_symlink_attr(_req.uid(), _req.gid());
                reply.attr(&TTL, &attr)
            }
            _ => reply.error(Errno::ENOENT),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        if u64::from(ino) == SYMLINK_INO {
            let username = get_username(_req.uid());
            let path_str = self.userbrew_prefix.join(Path::new(&username)).join(&self.userbrew_name);
            if let Ok(real_path) = fs::canonicalize(path_str) {
                if let Ok(path_str) = real_path.into_string() {
                    reply.data(path_str.as_bytes());
                }
            }
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        if u64::from(ino) != 1 {
            reply.error(Errno::ENOENT);
            return;
        }

        let entries = vec![
            (1, FileType::Directory, "."),
            (1, FileType::Directory, ".."),
            (2, FileType::Symlink, ".linuxbrew"),
        ];

        for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
            let can_add = if entry.2 == ".linuxbrew" {
                let username = get_username(_req.uid());
                let path_str = self.userbrew_prefix.join(Path::new(&username)).join(&self.userbrew_name);
                path_str.exists()
            } else {
                true
            };
            if can_add {
                // i + 1 means the index of the next entry
                if reply.add(INodeNo(entry.0), (i + 1) as u64, entry.1, entry.2) {
                    break;
                }
            }
        }
        reply.ok();
    }
}

fn main() {
    let args = Args::parse();

    let target_path = path::Path::new(&args.mount_point);
    println!("Mounting fs to {}", args.mount_point);

    let prefix_path = path::Path::new(&args.link_prefix);
    let path_extension_str = format!("$USER/{}", args.name);
    let path_str = prefix_path.join(Path::new(&path_extension_str));
    println!("Linking .linuxbrew to {}!", path_str.display());

    let linked_dir = path::Path::new(&args.name);

    let mut cfg = Config::default();
    cfg.mount_options
        .extend([MountOption::RO, MountOption::FSName("userbrew".to_string())]);
    if !args.single_user {
        cfg.acl = fuser::SessionACL::RootAndOwner;
        cfg.mount_options.push(MountOption::AutoUnmount);
    }

    let mount_meta = match std::fs::metadata(target_path) {
        Ok(meta) => meta,
        Err(_) => {
            eprintln!("Could not get mount folder metadata");
            std::process::exit(1);
        }
    };
    let mount_timemeta = TimeMetadata::from_metadata(mount_meta);
    let fs = UserBrewFS::new(
        mount_timemeta,
        prefix_path.to_owned(),
        linked_dir.to_owned(),
    );

    let result = fuser::mount(fs, target_path, &cfg);

    if let Err(e) = result {
        // Return a special error code for permission denied, which usually indicates that
        // "user_allow_other" is missing from /etc/fuse.conf
        if e.kind() == ErrorKind::PermissionDenied {
            eprintln!("{e}");
            std::process::exit(2);
        } else {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
