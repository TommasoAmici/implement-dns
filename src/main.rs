use implement_dns::{resolve, DomainName};

fn main() -> Result<(), std::io::Error> {
    env_logger::init();

    let test_domains = vec![
        "tommasoamici.com",
        "google.com",
        "twitter.com",
        "www.facebook.com", // CNAME
    ];

    for domain in test_domains {
        let result = resolve(&DomainName::from(domain), implement_dns::TypeField::A);
        println!("{:?}", result);
    }

    Ok(())
}
