import os
from query import launch_attack
from drop_ip import drop_matched_ips
from rate_limiter import rate_limit
from filter import rules_match

def main():
    
    query_result = launch_attack()

    ratelim = rate_limit()

    filterr = rules_match()

    dropips = drop_matched_ips()
    
    
    print(f"Query result saved to: logs/dns_query_log.csv {query_result}")
    print(f"rate limit saved to: logs/rate_limiter_logs.csv {ratelim}")
    print(f"Yara matched file saved to: logs/yara_matched.csv {filterr}")
    print(f"legit ips saved to: logs/not_blocked.csv {dropips}")

if __name__ == "__main__":
    main()
