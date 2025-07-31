package pci.access

default allow = false

# Allow if user has PaymentProcessor role and resource is cardholder data (CHD)
allow if {
    input.action == "read"
    input.resource.classification == "CHD"
    input.user.role == "PaymentProcessor"
}

# Dual authorization for write actions on CHD
allow if {
    input.action == "write"
    input.resource.classification == "CHD"
    input.user.role == "PaymentProcessor"
    input.approved_by == "SecurityOfficer"
}

# Deny with message if unauthorized
deny[msg] if {
    input.resource.classification == "CHD"
    not input.user.role == "PaymentProcessor"
    msg := sprintf("Access denied: Role %v cannot access CHD", [input.user.role])
}

# Block wildcard permissions
deny[msg] if {
    input.action == "*"
    msg := "Wildcard actions are prohibited under PCI-DSS"
}

