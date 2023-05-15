use implement_dns::domain_lookup;

fn main() -> Result<(), std::io::Error> {
    let example = domain_lookup("example.com")?;
    println!("{:?}", example.answers[0].ipv4);

    let recurse = domain_lookup("recurse.com")?;
    println!("{:?}", recurse.answers[0].ipv4);

    let metafilter = domain_lookup("metafilter.com")?;
    println!("{:?}", metafilter.answers[0].ipv4);

    let www_metafilter = domain_lookup("www.metafilter.com")?;
    println!("{:?}", www_metafilter.answers[0].ipv4);

    let facebook = domain_lookup("facebook.com")?;
    println!("{:?}", facebook.answers[0].ipv4);

    let www_facebook = domain_lookup("www.facebook.com")?;
    println!("{:?}", www_facebook.answers[0].ipv4);

    Ok(())
}
