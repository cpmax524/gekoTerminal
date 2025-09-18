# smart_money_tracker.py

import requests
import time
import os
from datetime import datetime, timedelta

# --- CONFIGURATION ---

# 1. API Keys - IMPORTANT: Replace "YOUR_API_KEY" with your actual API key
# Get your BscScan API key here: https://bscscan.com/myapikey
# The other APIs (GeckoTerminal, GoPlus) are free and don't require a key for this script's usage.
BSCSCAN_API_KEY = os.getenv("BSCSCAN_API_KEY", "YOUR_API_KEY")

# 2. Smart Money Wallet Criteria
MIN_BNB_BALANCE = 50  # Minimum 50 BNB
MIN_WALLET_AGE_DAYS = 365  # Minimum 1 year old
MIN_TXN_COUNT = 400  # Minimum 400 transactions

# 3. Token Scan Criteria
MIN_LIQUIDITY_USD = 20000  # Minimum $20,000 liquidity
MIN_24H_VOLUME_USD = 50000  # Minimum $50,000 24h trading volume
MAX_POOL_AGE_HOURS = 24  # Pools created in the last 24 hours

# 4. Large Buy & High-Potential Token Criteria
LARGE_BUY_USD = 2000  # A buy of $2,000 or more is considered large
MIN_SMART_MONEY_WALLETS = 2  # Minimum number of smart money wallets to flag a token

# 5. Security Filter Criteria
MAX_BUY_TAX = 0.10  # 10%
MAX_SELL_TAX = 0.10  # 10%

# --- API ENDPOINTS ---
GECKOTERMINAL_API_URL = "https://api.geckoterminal.com/api/v2"
GOPLUS_API_URL = "https://api.gopluslabs.io/api/v1"
BSCSCAN_API_URL = "https://api.bscscan.com/api"


def scan_for_new_pools():
    """
    Scans GeckoTerminal for new token pools on BSC PancakeSwap v3 that meet the criteria.
    """
    print("Step 1: SCANNING for new and active token pools...")
    potential_tokens = []

    # We will paginate through the results, sorting by creation time to get the newest pools first.
    page = 1
    # Limit to a reasonable number of pages to avoid infinite loops in edge cases.
    max_pages = 10

    while page <= max_pages:
        print(f"Scanning page {page}...")
        # Add the 'sort=created_at_desc' parameter to fetch newest pools first.
        url = f"{GECKOTERMINAL_API_URL}/networks/bsc/pools?page={page}&sort=created_at_desc"

        try:
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()

            pools = data.get("data", [])
            if not pools:
                print("No more pools found on this page. Concluding scan.")
                break

            for pool in pools:
                # Filter for PancakeSwap v3 pools
                dex_id = pool.get("relationships", {}).get("dex", {}).get("data", {}).get("id")
                if dex_id != 'pancakeswap_v3':
                    continue

                attributes = pool.get("attributes", {})

                # 1. Check pool creation time
                created_at_str = attributes.get("pool_created_at")
                if not created_at_str:
                    continue

                created_at = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
                if datetime.now(created_at.tzinfo) - created_at > timedelta(hours=MAX_POOL_AGE_HOURS):
                    print("Found pools older than 24 hours. Concluding scan.")
                    return potential_tokens

                # 2. Check liquidity
                liquidity_usd = float(attributes.get("reserve_in_usd", 0))
                if liquidity_usd < MIN_LIQUIDITY_USD:
                    continue

                # 3. Check 24h volume
                volume_usd_h24 = float(attributes.get("volume_usd", {}).get("h24", 0))
                if volume_usd_h24 < MIN_24H_VOLUME_USD:
                    continue

                # This pool meets all criteria
                relationships = pool.get("relationships", {})
                base_token_data = relationships.get("base_token", {}).get("data", {})
                token_address_full = base_token_data.get("id")

                if token_address_full and token_address_full.startswith("bsc_"):
                    token_address = token_address_full.split('_')[1]
                else:
                    continue

                token_price = float(attributes.get("base_token_price_usd", 0))

                print(f"  [+] Found potential token: {token_address}")
                potential_tokens.append({
                    "address": token_address,
                    "price": token_price
                })

            page += 1
            time.sleep(6) # Respect GeckoTerminal rate limit

        except requests.exceptions.RequestException as e:
            print(f"Error fetching data from GeckoTerminal: {e}")
            break

    return potential_tokens


def filter_tokens_by_security(tokens_to_check):
    """
    Filters tokens using the GoPlus Security API based on defined criteria.
    """
    print("\nStep 2: FILTERING tokens for security risks...")
    safe_tokens = []

    for token in tokens_to_check:
        token_address = token["address"]
        print(f"  Checking security for token: {token_address}...")

        # Note: GoPlus API expects checksummed address for the key in the result
        url = f"{GOPLUS_API_URL}/token_security/56?contract_addresses={token_address}"

        try:
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()

            # The key in the result dictionary is the lowercased address
            result = data.get("result", {}).get(token_address.lower())
            if not result:
                print(f"    [!] No security data found for {token_address}.")
                continue

            # Check for deal-breaker red flags
            if result.get("is_honeypot") == "1":
                print(f"    [!] REJECTED: Is a honeypot.")
                continue
            if result.get("cannot_sell_all") == "1":
                print(f"    [!] REJECTED: Cannot sell all tokens.")
                continue
            if result.get("is_proxy") == "1":
                print(f"    [!] REJECTED: Is a proxy contract.")
                continue
            if result.get("hidden_owner") == "1":
                print(f"    [!] REJECTED: Has a hidden owner.")
                continue

            # Check taxes
            buy_tax = float(result.get("buy_tax", 0))
            sell_tax = float(result.get("sell_tax", 0))
            if buy_tax > MAX_BUY_TAX or sell_tax > MAX_SELL_TAX:
                print(f"    [!] REJECTED: High taxes (Buy: {buy_tax*100:.2f}%, Sell: {sell_tax*100:.2f}%).")
                continue

            print(f"    [+] PASSED: Token {token_address} seems safe.")
            safe_tokens.append(token)

            time.sleep(2) # Respect GoPlus rate limit

        except requests.exceptions.RequestException as e:
            print(f"    [!] Error checking security for {token_address}: {e}")
            continue

    return safe_tokens


def _bscscan_request(params):
    """Helper function to make requests to the BscScan API."""
    params['apikey'] = BSCSCAN_API_KEY
    try:
        response = requests.get(BSCSCAN_API_URL, params=params)
        response.raise_for_status()
        data = response.json()
        if data.get("status") == "1" or data.get("message") == "OK":
            return data.get("result")
        else:
            # Handle BscScan's specific error messages
            error_message = data.get('result', data.get('message', 'Unknown error'))
            print(f"    [!] BscScan API Error: {error_message}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"    [!] Error making BscScan request: {e}")
        return None
    finally:
        time.sleep(0.25) # Respect BscScan rate limit

def get_token_transfers(token_address):
    """Gets the last 200 token transfers for a specific token contract."""
    print(f"  Fetching recent transactions for {token_address}...")
    params = {
        "module": "account",
        "action": "tokentx",
        "contractaddress": token_address,
        "page": 1,
        "offset": 200,
        "sort": "desc",
    }
    return _bscscan_request(params)

def is_smart_money(wallet_address):
    """Checks if a wallet address meets the 'Smart Money' criteria."""
    print(f"    -> Checking wallet: {wallet_address}...")

    # 1. Check BNB Balance
    bnb_balance_params = {"module": "account", "action": "balance", "address": wallet_address, "tag": "latest"}
    balance_result = _bscscan_request(bnb_balance_params)
    if balance_result is None: return False
    bnb_balance = int(balance_result) / 1e18
    if bnb_balance < MIN_BNB_BALANCE:
        print(f"        - Fail: Low BNB balance ({bnb_balance:.2f} BNB).")
        return False
    print(f"        - Pass: High BNB balance ({bnb_balance:.2f} BNB).")

    # 2. Check Wallet Age (First Transaction)
    # We get the first transaction to check the age.
    txlist_params = {"module": "account", "action": "txlist", "address": wallet_address, "startblock": 0, "endblock": 99999999, "page": 1, "offset": 1, "sort": "asc"}
    first_tx_result = _bscscan_request(txlist_params)
    if not first_tx_result or not isinstance(first_tx_result, list):
        print(f"        - Fail: Could not retrieve transaction history.")
        return False
    first_tx_timestamp = int(first_tx_result[0].get("timeStamp", 0))
    wallet_age = datetime.now() - datetime.fromtimestamp(first_tx_timestamp)
    if wallet_age.days < MIN_WALLET_AGE_DAYS:
        print(f"        - Fail: Wallet is too new ({wallet_age.days} days old).")
        return False
    print(f"        - Pass: Wallet is old enough ({wallet_age.days} days old).")

    # 3. Check Transaction Count
    tx_count_params = {"module": "proxy", "action": "eth_getTransactionCount", "address": wallet_address, "tag": "latest"}
    tx_count_result = _bscscan_request(tx_count_params)
    if tx_count_result is None: return False
    tx_count = int(tx_count_result, 16) # Result is in hex
    if tx_count < MIN_TXN_COUNT:
        print(f"        - Fail: Low transaction count ({tx_count} txns).")
        return False
    print(f"        - Pass: High transaction count ({tx_count} txns).")

    print(f"    [+] SMART MONEY CONFIRMED: {wallet_address}")
    return True

def confirm_conviction(safe_tokens):
    """
    Analyzes safe tokens to find those being bought by "Smart Money" wallets.
    """
    print("\nStep 3: CONFIRMING CONVICTION by analyzing wallets...")
    high_potential_tokens = []

    for token in safe_tokens:
        token_address = token["address"]
        token_price = token["price"]
        print(f"\nAnalyzing token: {token_address}")

        transfers = get_token_transfers(token_address)
        if not transfers:
            print(f"  Could not retrieve transactions for {token_address}. Skipping.")
            continue

        smart_money_buyers = set()
        large_buyers = set()

        for tx in transfers:
            # We are looking for buys, so the 'to' address is the buyer.
            buyer_address = tx.get("to")
            if not buyer_address or buyer_address in large_buyers:
                continue

            large_buyers.add(buyer_address) # Avoid re-checking the same buyer for this token

            try:
                token_decimals = int(tx.get("tokenDecimal", 18))
                value = int(tx.get("value", 0)) / (10 ** token_decimals)
                usd_value = value * token_price
            except (ValueError, TypeError):
                continue

            if usd_value >= LARGE_BUY_USD:
                if is_smart_money(buyer_address):
                    smart_money_buyers.add(buyer_address)

            if len(smart_money_buyers) >= MIN_SMART_MONEY_WALLETS:
                print(f"  [***] HIGH POTENTIAL: Found {len(smart_money_buyers)} smart money wallets for {token_address}.")
                high_potential_tokens.append({
                    "address": token_address,
                    "smart_money_wallets": list(smart_money_buyers)
                })
                break # Move to the next token

    return high_potential_tokens

def main():
    """
    Main function to run the Smart Money Tracker.
    """
    print("=============================================")
    print("====== Starting Smart Money Tracker =========")
    print("=============================================")

    # To test the final step without waiting for scans, you can use mock data:
    # safe_tokens_mock = [{"address": "0x123...", "price": 0.5}]
    # high_potential = confirm_conviction(safe_tokens_mock)

    # Step 1: SCAN
    newly_found_tokens = scan_for_new_pools()

    if not newly_found_tokens:
        print("\nExecution HALTED: No new tokens meeting the criteria were found.")
    else:
        print(f"\n[Flow] SCAN Complete. Found {len(newly_found_tokens)} potential tokens. Proceeding to FILTER.")

        # Step 2: FILTER
        safe_tokens = filter_tokens_by_security(newly_found_tokens)

        if not safe_tokens:
            print("\nExecution HALTED: No tokens passed the security filter.")
        else:
            print(f"\n[Flow] FILTER Complete. Found {len(safe_tokens)} safe tokens. Proceeding to CONFIRM.")

            # Step 3: CONFIRM
            high_potential_tokens = confirm_conviction(safe_tokens)

            print("\n=============================================")
            print("========= FINAL SUMMARY REPORT ==============")
            print("=============================================")
            if high_potential_tokens:
                print(f"Found {len(high_potential_tokens)} high-potential token(s):")
                for token in high_potential_tokens:
                    print(f"\n  -> Token: https://bscscan.com/token/{token['address']}")
                    print("     Smart Money Wallets:")
                    for wallet in token['smart_money_wallets']:
                        print(f"       - https://bscscan.com/address/{wallet}")
            else:
                print("No tokens were flagged as high-potential by smart money.")
            print("=============================================")

    print("\nSmart Money Tracker finished.")


if __name__ == "__main__":
    main()
