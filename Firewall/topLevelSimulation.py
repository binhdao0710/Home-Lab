import random

def generate_random_ip():
    return f"192.168.1.{random.randint(0,20)}"

def check_firewall_rules(ip, rules):
    for rule_ip, action in rules.items():
        if ip == rule_ip:
            return action
    return "allow"


def main():
    firewall_rules={
        "192.168.1.1": "block",
        "192.168.1.4": "block",
        "192.168.1.5": "block",
        "192.168.1.11": "block",
        "192.168.1.13": "block",
        "192.168.1.17": "block",
        "192.168.1.18": "block",
        "192.168.1.19": "block",
          }
    
    for _ in range(10):
        ip = generate_random_ip()
        action = check_firewall_rules(ip, firewall_rules)
        print(f"IP: {ip} - Action: {action}")

if __name__ == "__main__":  
    main()
    