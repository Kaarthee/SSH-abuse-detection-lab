def mitre_for(event: str):
    mapping = {
        "bruteforce": {"T1110"},            # Brute Force
        "valid_accounts": {"T1078"},        # Valid Accounts
        "remote_services": {"T1021.004"},   # Remote Services: SSH
        "protocol_tunneling": {"T1572"},    # Protocol Tunneling
    }
    return mapping.get(event, set())
