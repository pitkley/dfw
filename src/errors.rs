
error_chain! {
    foreign_links {
        Docker(::shiplift::errors::Error);
        IPTError(::iptables::error::IPTError);
        Io(::std::io::Error);
        TomlSer(::toml::ser::Error);
        TomlDe(::toml::de::Error);
    }
}
