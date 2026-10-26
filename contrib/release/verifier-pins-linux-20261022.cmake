# Recorded offline-tested Ubuntu 24.04 x86_64 / Rust 1.92.0 archives.
# Source overlay c9116d76987a60359805ef9cea270dec69df0b6269f4cc3934ffffb854e6d643.
# These pins authenticate bytes, not current-source or production qualification.
# Load with cmake -C before configuring; never use them for another build target.
set(USDD_SP1_VERIFIER_SHA256 "5a090255a3852ce8691d5b8844a4a9ae4adf17786ca098851e58926e9033d1a3" CACHE STRING "Recorded Linux USDD archive SHA256")
set(ECX_SP1_VERIFIER_SHA256 "b739935c8c14a26cb09705fb3bbc5fcebcac51b1013ea1a7a52638ef70fb2519" CACHE STRING "Recorded Linux ECX archive SHA256")
