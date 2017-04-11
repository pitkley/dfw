
error_chain! {
    links {
        Boondock(::boondock::errors::Error, ::boondock::errors::ErrorKind);
    }

    foreign_links {
        IPTError(::iptables::error::IPTError);
        Io(::std::io::Error);
        TomlSer(::toml::ser::Error);
        TomlDe(::toml::de::Error);
    }

    errors {
        EmptyKey(key: String) {
            description("key is empty")
            display("key '{}' is empty", key)
        }
    }
}
