// Package version records the build's version, shared by every binary.
package version

// Version is the MeshMorphic release this build came from. It is sent in the
// handshake for diagnostics only; nothing branches on it, and a peer must
// never be trusted more or less because of what it claims here.
const Version = "0.1.0"

// UserAgent identifies this build in outbound requests.
const UserAgent = "MeshMorphic/" + Version
