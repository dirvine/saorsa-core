// Copyright 2024 Saorsa Labs Limited
//
// Build script for saorsa-core
//
// When the 'vdf' feature is enabled, this compiles the SP1 guest program
// for the VDF heartbeat system.

fn main() {
    // Only build the SP1 guest program if the 'vdf' feature is enabled
    // The sp1-build dependency is only available when this feature is active
    #[cfg(feature = "vdf")]
    {
        sp1_build::build_program("../saorsa-vdf-guest");
    }
}
