fn main() -> Result<(), &'static str> {
    println!("Starting Sshield");
    
    let app = sshield::run();

    println!("Stopping Sshield");

    app?; // we have to ask rust whether there is an app

    Ok(())
}