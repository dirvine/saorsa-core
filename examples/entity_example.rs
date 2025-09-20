// Copyright 2024 Saorsa Labs Limited
//
// Entity system example demonstrating the unified API
//
// This example shows how the communitas app can use the saorsa-core
// entity API to create and manage entities with virtual disks

use anyhow::Result;
use saorsa_core::api::{
    create_entity, entity_disk_list, entity_disk_read, entity_disk_write, entity_website_url,
};
use saorsa_core::entities::EntityType;

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Saorsa Core Entity System Example ===\n");

    // Note: In production, these would need to be valid four-word-networking words
    // The communitas app would get these from user input or generate them
    let four_words = ["test", "demo", "entity", "example"];

    println!("Creating an Individual entity for Alice...");
    println!(
        "Four-word address: {}-{}-{}-{}",
        four_words[0], four_words[1], four_words[2], four_words[3]
    );

    // Create an individual entity
    // In production, the communitas app would validate the four-word address
    match create_entity(
        EntityType::Individual,
        "Alice",
        four_words,
        Some("Alice's personal entity for secure communication".to_string()),
        None, // Use default settings
    )
    .await
    {
        Ok(handle) => {
            println!("✓ Entity created successfully!");
            println!("  Entity ID: {:?}", handle.id);

            // Write to private disk
            println!("\nWriting to Alice's private virtual disk...");
            let private_data = b"This is Alice's private data";
            entity_disk_write(&handle, "/private/notes.txt", private_data.to_vec(), false).await?;
            println!("✓ Written to private disk: /private/notes.txt");

            // Write to public disk (for website)
            println!("\nWriting to Alice's public virtual disk (website)...");
            let public_content =
                b"# Welcome to Alice's Website\n\nThis is published via four-word address.";
            entity_disk_write(&handle, "/index.md", public_content.to_vec(), true).await?;
            println!("✓ Written to public disk: /index.md");

            // Read from private disk
            println!("\nReading from private disk...");
            let read_data = entity_disk_read(&handle, "/private/notes.txt", false).await?;
            println!("✓ Read {} bytes from private disk", read_data.len());

            // List files in public disk
            println!("\nListing files in public disk...");
            let files = entity_disk_list(&handle, "/", false, true).await?;
            for file in files {
                println!("  - {} ({} bytes)", file.path.display(), file.size);
            }

            // Get website URL
            if let Some(url) = entity_website_url(&handle) {
                println!("\nWebsite URL: {}", url);
            }
        }
        Err(e) => {
            println!("✗ Failed to create entity: {}", e);
            println!("\nNote: This example requires valid four-word-networking dictionary words.");
            println!("The communitas app would handle this validation and provide proper words.");
        }
    }

    // Demonstrate creating different entity types
    println!("\n=== Entity Types Available for Communitas ===");
    println!("1. Individual - Personal identity with private/public storage");
    println!("2. Group - Team collaboration with shared virtual disks");
    println!("3. Channel - Communication channel for broadcasting");
    println!("4. Project - Project workspace with collaborative editing");
    println!("5. Organization - Large-scale entity with hierarchical structure");

    println!("\n=== API Functions for Communitas App ===");
    println!("• create_entity() - Create new entities");
    println!("• get_entity() - Retrieve entity by ID");
    println!("• get_entity_by_address() - Retrieve by four-word address");
    println!("• list_entities() - List all registered entities");
    println!("• entity_disk_write() - Write to virtual disks");
    println!("• entity_disk_read() - Read from virtual disks");
    println!("• entity_disk_list() - List files in virtual disks");
    println!("• entity_set_website() - Enable/disable website publishing");
    println!("• entity_website_url() - Get entity's website URL");

    println!("\n=== Virtual Disk Features ===");
    println!("• Private Disk: Encrypted storage for sensitive data");
    println!("• Public Disk: Markdown-based website content");
    println!("• Automatic FEC encoding for redundancy");
    println!("• Content-addressed storage via DHT");
    println!("• Per-entity isolation and encryption");

    Ok(())
}
