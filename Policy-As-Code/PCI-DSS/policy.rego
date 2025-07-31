package pci.access

default allow = false

# Allow if user has PaymentProcessor role and resource is cardholder data (CHD)
allow if {
    input.action == "read"
    input.resource.classification == "CHD"
    input.user.role == "Developer"
}

# Deny with message if unauthorized
deny[msg] if {
    input.resource.classification == "CHD"
    not input.user.role == "PaymentProcessor"
    msg := sprintf("Access denied: Role %v cannot access CHD", [input.user.role])
}
