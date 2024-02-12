import dns.resolver

# Function to get A record (IP address)
def get_a_record(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        for ipval in result:
            print('A Record:', ipval.to_text())
    except Exception as e:
        print('Error:', e)

# Function to get MX record (Mail server)
def get_mx_record(domain):
    try:
        result = dns.resolver.resolve(domain, 'MX')
        for mail_server in result:
            print('MX Record:', mail_server.exchange.to_text())
    except Exception as e:
        print('Error:', e)

# Function to get NS record (Name servers)
def get_ns_record(domain):
    try:
        result = dns.resolver.resolve(domain, 'NS')
        for nameserver in result:
            print('NS Record:', nameserver.to_text())
    except Exception as e:
        print('Error:', e)

# Test the functions with a domain
domain = 'example.com'
print(f"DNS records for {domain}:")
get_a_record(domain)
get_mx_record(domain)
get_ns_record(domain)
