module github.com/ovirt/go-ovirt-client/v2

go 1.16

// Bootstrap pin: publish the SDK renewal change and pin that fork revision
// before building without the local development workspace.
replace github.com/ovirt/go-ovirt => github.com/oracle-cne/go-ovirt v0.0.0-20220427092237-114c47f2835c

require (
	github.com/google/uuid v1.3.0
	github.com/ovirt/go-ovirt v0.0.0-20220427092237-114c47f2835c
	github.com/ovirt/go-ovirt-client-log/v3 v3.0.0
	github.com/stretchr/testify v1.7.0 // indirect
)
