fn main() -> Result<(), &'static str> {
    println!("Starting Sshield");
    
    let app = sshield::run();

    println!("Stopping Sshield");

    app?; // we have to ask rust whether there is an app

    Ok(())
}

// plans until v.1:
// - make a cli to control things like bans or future config details(which aren't implemented yet even)
// - propper config file management
// - to make it more stable by integrating into the system