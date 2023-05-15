use implement_dns::{resolve, DomainName};

fn main() -> Result<(), std::io::Error> {
    env_logger::init();

    let example = resolve(
        &DomainName::from("example.com"),
        implement_dns::TypeField::A,
    )?;
    println!("{:?}", example);

    let google = resolve(&DomainName::from("google.com"), implement_dns::TypeField::A)?;
    println!("{:?}", google);

    let twitter = resolve(
        &DomainName::from("twitter.com"),
        implement_dns::TypeField::A,
    )?;
    println!("{:?}", twitter);

    let ennamio = resolve(&DomainName::from("ennam.io"), implement_dns::TypeField::A)?;
    println!("{:?}", ennamio);

    Ok(())
}
