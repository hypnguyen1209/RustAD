#[cfg(not(feature = "noargs"))]
use clap::{value_parser, Arg, ArgAction, Command};

#[cfg(feature = "noargs")]
use crate::utils::exec::run;
#[cfg(feature = "noargs")]
use regex::Regex;
#[cfg(feature = "noargs")]
use winreg::{enums::*, RegKey};

#[derive(Clone, Debug)]
pub struct Options {
    pub domain: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub ldapfqdn: Option<String>,
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub name_server: String,
    pub path: String,
    pub collection_method: CollectionMethod,
    pub ldaps: bool,
    pub dns_tcp: bool,
    pub fqdn_resolver: bool,
    pub hashes: Option<String>,
    pub kerberos: bool,
    pub pfx: Option<String>,
    pub pfx_pass: Option<String>,
    pub crt: Option<String>,
    pub key: Option<String>,
    pub zip: bool,
    pub verbose: log::LevelFilter,
    pub ldap_filter: String,
    pub sspi: bool,
    pub cache: bool,
    pub cache_buffer_size: usize,
    pub resume: bool,
    pub session_loop: bool,
    pub loop_duration: u64,
    pub loop_interval: u64,
    pub output_prefix: Option<String>,
    pub analyze: bool,
    pub delay_ms: u64,
    pub jitter_ms: u64,
    pub owned: Option<String>,
    pub exclude_dc: bool,
    pub opsec: bool,
    pub export_format: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            domain: String::new(),
            username: None,
            password: None,
            ldapfqdn: None,
            ip: None,
            port: None,
            name_server: "not set".to_string(),
            path: "./".to_string(),
            collection_method: CollectionMethod::All,
            ldaps: false,
            dns_tcp: false,
            fqdn_resolver: false,
            hashes: None,
            kerberos: false,
            sspi: false,
            pfx: None,
            pfx_pass: None,
            crt: None,
            key: None,
            zip: false,
            verbose: log::LevelFilter::Info,
            ldap_filter: "(objectClass=*)".to_string(),
            cache: false,
            cache_buffer_size: 1000,
            resume: false,
            session_loop: false,
            loop_duration: 7200,
            loop_interval: 120,
            output_prefix: None,
            analyze: false,
            delay_ms: 0,
            jitter_ms: 0,
            owned: None,
            exclude_dc: false,
            opsec: false,
            export_format: None,
        }
    }
}

impl Options {
    pub fn uses_cert(&self) -> bool {
        self.pfx.is_some() || self.crt.is_some()
    }
    pub fn has_smb_creds(&self) -> bool {
        !self.sspi
            && !self.uses_cert()
            && (self.username.is_some() || self.hashes.is_some() || self.kerberos)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum CollectionMethod {
    All,
    Default,
    DCOnly,
    Session,
    RegistryOnly,
    LdapOnly,
    Group,
    ACL,
    ObjectProps,
    SPNTargets,
    Trusts,
    Container,
    GPOLocalGroup,
    ComputerOnly,
    RDP,
    DCOM,
    PSRemote,
}

impl CollectionMethod {
    pub fn does_sessions(&self) -> bool {
        matches!(
            self,
            Self::All | Self::Session | Self::RDP | Self::DCOM | Self::PSRemote
        )
    }
    pub fn srvsvc(&self) -> bool {
        matches!(self, Self::All | Self::Session)
    }
    pub fn wkssvc(&self) -> bool {
        matches!(self, Self::All | Self::Session)
    }
    pub fn registry(&self) -> bool {
        matches!(self, Self::All | Self::Session | Self::RegistryOnly)
    }
    pub fn does_gpo(&self) -> bool {
        matches!(
            self,
            Self::All | Self::DCOnly | Self::Default | Self::GPOLocalGroup
        )
    }
    pub fn does_ldap(&self) -> bool {
        !matches!(
            self,
            Self::Session | Self::RDP | Self::DCOM | Self::PSRemote
        )
    }
}

pub const RUSTHOUND_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(not(feature = "noargs"))]
fn cli() -> Command {
    Command::new("")
    .version(RUSTHOUND_VERSION)
    .about("")
    .arg(Arg::new("v")
        .short('v')
        .help("Set the level of verbosity")
        .action(ArgAction::Count),
    )
    .next_help_heading("REQUIRED VALUES")
    .arg(Arg::new("domain")
        .short('d')
        .long("domain")
        .help("Domain name like: DOMAIN.LOCAL")
        .required(true)
        .value_parser(value_parser!(String))
    )
    .next_help_heading("OPTIONAL VALUES")
    .arg(Arg::new("ldapusername")
        .short('u')
        .long("ldapusername")
        .help("LDAP username, like: user@domain.local")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("ldappassword")
        .short('p')
        .long("ldappassword")
        .help("LDAP password")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("hashes")
        .short('H')
        .long("hashes")
        .help("NT hash for pass-the-hash authentication (NTLM), accept [NTHASH, :NTHASH, LMHASH:NTHASH]")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("ldapfqdn")
        .short('f')
        .long("ldapfqdn")
        .help("Domain Controller FQDN like: DC01.DOMAIN.LOCAL or just DC01")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("ldapip")
        .short('i')
        .long("ldapip")
        .help("Domain Controller IP address like: 192.168.1.10")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("ldapport")
        .short('P')
        .long("ldapport")
        .help("LDAP port [default: 389, or 636 with --ldaps]")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("name-server")
        .short('n')
        .long("name-server")
        .help("Alternative IP address name server to use for DNS queries")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("output")
        .short('o')
        .long("output")
        .help("Output directory where you would like to save JSON files [default: ./]")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .next_help_heading("CERTIFICATE AUTHENTICATION")
    .arg(Arg::new("pfx")
        .long("pfx")
        .help("PFX/PKCS#12 client certificate for certificate authentication (Pass-the-Certificate)")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("pfx-pass")
        .long("pfx-pass")
        .help("Password protecting the PFX file (optional)")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("crt")
        .long("crt")
        .help("PEM client certificate for certificate authentication (use with --key)")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("key")
        .long("key")
        .help("PEM private key for certificate authentication (use with --crt)")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .next_help_heading("OPTIONAL FLAGS")
    .arg(Arg::new("collectionmethod")
        .short('c')
        .long("collectionmethod")
        .help("Collection method (default: All). Values: All, Default (no sessions), DCOnly, Session, RegistryOnly, LdapOnly, Group, ACL, ObjectProps, SPNTargets, Trusts, Container, GPOLocalGroup, ComputerOnly, RDP, DCOM, PSRemote")
        .required(false)
        .value_name("METHOD")
        .value_parser(["All", "Default", "DCOnly", "Session", "RegistryOnly", "LdapOnly",
            "Group", "ACL", "ObjectProps", "SPNTargets", "Trusts", "Container",
            "GPOLocalGroup", "ComputerOnly", "RDP", "DCOM", "PSRemote"])
        .num_args(0..=1)
        .default_missing_value("All")
    )
    .arg(Arg::new("ldap-filter")
        .long("ldap-filter")
        .help("Use custom LDAP filter (default: (objectClass=*))")
        .required(false)
        .value_parser(value_parser!(String))
        .default_missing_value("(objectClass=*)")
    )
    .arg(Arg::new("ldaps")
        .long("ldaps")
        .help("Force LDAPS using for request like: ldaps://DOMAIN.LOCAL/")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
    .arg(Arg::new("kerberos")
        .short('k')
        .long("kerberos")
        .help("Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters for Linux.")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
    .arg(Arg::new("dns-tcp")
        .long("dns-tcp")
        .help("Use TCP instead of UDP for DNS queries")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
    .arg(Arg::new("zip")
        .long("zip")
        .short('z')
        .help("Compress the JSON files into a zip archive")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
    .arg(Arg::new("loop")
        .long("loop")
        .help("Loop session collection repeatedly")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
    .arg(Arg::new("loopduration")
        .long("loopduration")
        .help("Duration of session loop in seconds (default: 7200 = 2 hours)")
        .required(false)
        .value_parser(value_parser!(u64))
    )
    .arg(Arg::new("loopinterval")
        .long("loopinterval")
        .help("Interval between session loops in seconds (default: 120 = 2 minutes)")
        .required(false)
        .value_parser(value_parser!(u64))
    )
    .arg(Arg::new("outputprefix")
        .long("outputprefix")
        .help("Prefix for output file names")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .next_help_heading("ANALYSIS (post-collection)")
    .arg(Arg::new("analyze")
        .long("analyze")
        .help("Run attack surface analysis after collection (paths, ACLs, ADCS, Kerberoast, DCSync, etc.)")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
    .next_help_heading("OPERATIONAL")
    .arg(Arg::new("delay")
        .long("delay")
        .help("Delay between requests in milliseconds (default: 0)")
        .required(false)
        .value_parser(value_parser!(u64))
    )
    .arg(Arg::new("jitter")
        .long("jitter")
        .help("Random jitter added to delay in milliseconds (default: 0)")
        .required(false)
        .value_parser(value_parser!(u64))
    )
    .arg(Arg::new("opsec")
        .long("opsec")
        .help("OPSEC mode: generate traffic patterns closer to genuine requests")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
    .arg(Arg::new("exclude-dc")
        .long("exclude-dc")
        .help("Skip Domain Controllers in session enumeration")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
    .arg(Arg::new("owned")
        .long("owned")
        .help("Comma-separated list of owned/compromised principals for path analysis")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("export")
        .long("export")
        .help("Export analysis report format: json, csv, or md")
        .required(false)
        .value_parser(["json", "csv", "md"])
    )
    .next_help_heading("CACHING")
    .arg(Arg::new("cache")
        .long("cache")
        .help("Cache LDAP search results to disk (reduce memory usage on large domains)")
        .required(false)
        .action(ArgAction::SetTrue)
    )
    .arg(Arg::new("cache_buffer")
        .long("cache-buffer")
        .help("Buffer size to use when caching")
        .required(false)
        .value_parser(value_parser!(usize))
        .default_value("1000")
    )
    .arg(Arg::new("resume")
        .long("resume")
        .help("Resume the collection from the last saved state")
        .required(false)
        .action(ArgAction::SetTrue)
    )
    .next_help_heading("OPTIONAL MODULES")
    .arg(Arg::new("fqdn-resolver")
        .long("fqdn-resolver")
        .help("Use fqdn-resolver module to get computers IP address")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
}

#[cfg(not(feature = "noargs"))]
pub fn extract_args() -> Options {
    let matches = cli().get_matches();

    let d = matches
        .get_one::<String>("domain")
        .map(|s| s.as_str())
        .unwrap();
    let username = matches.get_one::<String>("ldapusername").cloned();
    let password = matches.get_one::<String>("ldappassword").cloned();
    let hashes = matches.get_one::<String>("hashes").cloned();
    let f = matches.get_one::<String>("ldapfqdn").cloned();
    let ip = matches.get_one::<String>("ldapip").cloned();
    let port = match matches.get_one::<String>("ldapport") {
        Some(val) => val.parse::<u16>().ok(),
        None => None,
    };
    let n = matches
        .get_one::<String>("name-server")
        .map(|s| s.as_str())
        .unwrap_or("not set");
    let path = matches
        .get_one::<String>("output")
        .map(|s| s.as_str())
        .unwrap_or("./");
    let ldaps = matches.get_one::<bool>("ldaps").copied().unwrap_or(false);
    let dns_tcp = matches.get_one::<bool>("dns-tcp").copied().unwrap_or(false);
    let z = matches.get_one::<bool>("zip").copied().unwrap_or(false);
    let fqdn_resolver = matches
        .get_one::<bool>("fqdn-resolver")
        .copied()
        .unwrap_or(false);
    let kerberos = matches
        .get_one::<bool>("kerberos")
        .copied()
        .unwrap_or(false);

    let pfx = matches.get_one::<String>("pfx").cloned();
    let pfx_pass = matches.get_one::<String>("pfx-pass").cloned();
    let crt = matches.get_one::<String>("crt").cloned();
    let key = matches.get_one::<String>("key").cloned();

    let v = match matches.get_count("v") {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    let collection_method = match matches
        .get_one::<String>("collectionmethod")
        .map(|s| s.as_str())
        .unwrap_or("All")
    {
        "All" => CollectionMethod::All,
        "Default" => CollectionMethod::Default,
        "DCOnly" => CollectionMethod::DCOnly,
        "Session" => CollectionMethod::Session,
        "RegistryOnly" => CollectionMethod::RegistryOnly,
        "LdapOnly" => CollectionMethod::LdapOnly,
        "Group" => CollectionMethod::Group,
        "ACL" => CollectionMethod::ACL,
        "ObjectProps" => CollectionMethod::ObjectProps,
        "SPNTargets" => CollectionMethod::SPNTargets,
        "Trusts" => CollectionMethod::Trusts,
        "Container" => CollectionMethod::Container,
        "GPOLocalGroup" => CollectionMethod::GPOLocalGroup,
        "ComputerOnly" => CollectionMethod::ComputerOnly,
        "RDP" => CollectionMethod::RDP,
        "DCOM" => CollectionMethod::DCOM,
        "PSRemote" => CollectionMethod::PSRemote,
        _ => CollectionMethod::All,
    };
    let ldap_filter = matches
        .get_one::<String>("ldap-filter")
        .map(|s| s.as_str())
        .unwrap_or("(objectClass=*)");

    let cache = matches.get_flag("cache");
    let cache_buffer_size = matches
        .get_one::<usize>("cache_buffer")
        .copied()
        .unwrap_or(1000);
    let resume = matches.get_flag("resume");

    let analyze = matches.get_one::<bool>("analyze").copied().unwrap_or(false);

    let session_loop = matches.get_one::<bool>("loop").copied().unwrap_or(false);
    let loop_duration = matches
        .get_one::<u64>("loopduration")
        .copied()
        .unwrap_or(7200);
    let loop_interval = matches
        .get_one::<u64>("loopinterval")
        .copied()
        .unwrap_or(120);
    let output_prefix = matches.get_one::<String>("outputprefix").cloned();

    let delay_ms = matches.get_one::<u64>("delay").copied().unwrap_or(0);
    let jitter_ms = matches.get_one::<u64>("jitter").copied().unwrap_or(0);
    let owned = matches.get_one::<String>("owned").cloned();
    let exclude_dc = matches
        .get_one::<bool>("exclude-dc")
        .copied()
        .unwrap_or(false);
    let opsec = matches.get_one::<bool>("opsec").copied().unwrap_or(false);
    let export_format = matches.get_one::<String>("export").cloned();

    Options {
        domain: d.to_string(),
        username,
        password,
        hashes,
        ldapfqdn: f,
        ip,
        port,
        name_server: n.to_string(),
        path: path.to_string(),
        collection_method,
        ldaps,
        dns_tcp,
        fqdn_resolver,
        kerberos,
        pfx,
        pfx_pass,
        crt,
        key,
        zip: z,
        verbose: v,
        ldap_filter: ldap_filter.to_string(),
        sspi: false,
        cache,
        cache_buffer_size,
        resume,
        session_loop,
        loop_duration,
        loop_interval,
        output_prefix,
        analyze,
        delay_ms,
        jitter_ms,
        owned,
        exclude_dc,
        opsec,
        export_format,
    }
}

#[cfg(feature = "noargs")]
pub fn auto_args() -> Options {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let cur_ver = match hklm.open_subkey("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters") {
        Ok(k) => k,
        Err(err) => {
            eprintln!("Failed to read TCP/IP parameters from registry: {:?}", err);
            eprintln!("This machine may not be domain-joined.");
            std::process::exit(1);
        }
    };
    let domain: String = match cur_ver.get_value("Domain") {
        Ok(domain) => domain,
        Err(err) => {
            eprintln!("Failed to read domain from registry: {:?}", err);
            eprintln!("This machine may not be domain-joined.");
            std::process::exit(1);
        }
    };

    let _fqdn: String = run(&format!("nslookup -query=srv _ldap._tcp.{}", &domain));
    let re = Regex::new(r"hostname.*= (?<ldap_fqdn>[0-9a-zA-Z._-]+)").unwrap();
    let mut values = re.captures_iter(&_fqdn);
    let caps = match values.next() {
        Some(c) => c,
        None => {
            eprintln!("Failed to resolve DC via nslookup for domain: {}", &domain);
            std::process::exit(1);
        }
    };
    let fqdn = caps["ldap_fqdn"]
        .to_string()
        .trim_end_matches('.')
        .to_string();

    let re = Regex::new(r"port.*= (?<ldap_port>[0-9]{3,})").unwrap();
    let mut values = re.captures_iter(&_fqdn);
    let caps = match values.next() {
        Some(c) => c,
        None => {
            eprintln!(
                "Failed to parse LDAP port from nslookup for domain: {}",
                &domain
            );
            std::process::exit(1);
        }
    };
    let port = caps["ldap_port"].to_string().parse::<u16>().ok();
    let ldaps = port == Some(636);

    // With gssapi: use Kerberos (SSPI on Windows). Without: prompt for creds.
    #[cfg(not(feature = "nogssapi"))]
    let use_kerberos = true;
    #[cfg(feature = "nogssapi")]
    let use_kerberos = false;

    Options {
        domain,
        ldapfqdn: Some(fqdn),
        port,
        name_server: "127.0.0.1".to_string(),
        path: "./output".to_string(),
        collection_method: CollectionMethod::All,
        ldaps,
        kerberos: use_kerberos,
        zip: true,
        ..Default::default()
    }
}
