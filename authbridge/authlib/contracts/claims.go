package contracts

// Claim strings for PluginCapabilities.Claims. A claim is a semantic
// resource that exactly one plugin per chain owns; two plugins
// declaring the same claim cause plugins.Build to fail at startup.
//
// Plugin authors reference these constants instead of string literals
// so typos are compile errors and the canonical set is greppable.
// Third-party plugins that need a claim not listed here may declare
// their own arbitrary string — the framework enforces uniqueness of
// whatever it sees, not "must be from the list" — but won't benefit
// from typo safety until the claim is upstreamed here.
//
// Resist speculative additions. Each constant is a small
// hard-to-deprecate contract. Adding a new claim should be driven by
// a concrete use case where two plugins would conflict in practice.
// Upstream a new constant in a follow-up PR when a claim stabilizes,
// with a godoc paragraph explaining what the resource is and which
// in-tree plugins claim it.

// ClaimAuthorizationHeader is the exclusive right to replace the
// outbound Authorization header. token-exchange and token-broker
// both claim this; they cannot coexist in the same outbound chain
// because the one that runs second would silently clobber the
// first's work.
//
// A future SPIFFE-exchanger or Keycloak-flavored gate plugin that
// also rewrites Authorization should declare this claim.
const ClaimAuthorizationHeader = "authorization_header"
