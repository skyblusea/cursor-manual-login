#!/usr/bin/env python3

import os
import requests
from cursor_auth import CursorAuth
from check_user_authorized import check_user_authorized
from get_user_token import get_token_from_cookie
from colorama import Fore, Style, init
from cursor_acc_info import UsageManager, format_subscription_type

# Initialize colorama
init(autoreset=True)

# Define emoji constants
EMOJI = {
    'SUCCESS': '✅',
    'ERROR': '❌',
    'INFO': 'ℹ️',
    'KEY': '🔐',
    'DEBUG': '🔍',
    'WARNING': '⚠️'
}

def manual_login():
    print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Manual Cursor Login with WorkosCursorSessionToken{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")

    # Get WorkosCursorSessionToken from user
    print(f"\n{Fore.YELLOW}{EMOJI['INFO']} Enter your WorkosCursorSessionToken:")
    cookie_value = input(f"{Fore.CYAN}> {Style.RESET_ALL}").strip()

    if not cookie_value:
        print(f"{Fore.RED}{EMOJI['ERROR']} Token is required{Style.RESET_ALL}")
        return False

    # Extract token from cookie value
    token = get_token_from_cookie(cookie_value)
    if not token:
        print(f"{Fore.RED}{EMOJI['ERROR']} Invalid token format{Style.RESET_ALL}")
        return False

    # Print token details for debugging
    print(f"\n{Fore.CYAN}{EMOJI['DEBUG']} Token length: {len(token)} characters{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{EMOJI['DEBUG']} Token format: {token[:10]}...{token[-10:] if len(token) > 20 else token[10:]}{Style.RESET_ALL}")

    # Verify token
    print(f"\n{Fore.CYAN}{EMOJI['INFO']} Verifying token validity...{Style.RESET_ALL}")
    is_valid = check_user_authorized(token)

    if not is_valid:
        print(f"{Fore.RED}{EMOJI['ERROR']} Invalid token. Authentication failed.{Style.RESET_ALL}")
        return False

    print(f"{Fore.GREEN}{EMOJI['SUCCESS']} Token verified successfully!{Style.RESET_ALL}")

    # Check subscription status using UsageManager
    print(f"\n{Fore.CYAN}{EMOJI['INFO']} Checking subscription status...{Style.RESET_ALL}")
    subscription_info = UsageManager.get_stripe_profile(token)

    if subscription_info:
        subscription_type = format_subscription_type(subscription_info)
        print(f"{Fore.GREEN}{EMOJI['SUCCESS']} Subscription Type: {subscription_type}{Style.RESET_ALL}")

        # Show remaining trial days if applicable
        days_remaining = subscription_info.get("daysRemainingOnTrial")
        if days_remaining is not None and days_remaining > 0:
            print(f"{Fore.GREEN}{EMOJI['INFO']} Remaining Pro Trial: {days_remaining} days{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}{EMOJI['WARNING']} Could not verify subscription status{Style.RESET_ALL}")

    # Get email (optional)
    print(f"\n{Fore.YELLOW}{EMOJI['INFO']} Enter email (leave blank for default):")
    email = input(f"{Fore.CYAN}> {Style.RESET_ALL}").strip()

    if not email:
        email = "user@cursor.sh"

    # Select auth type
    print(f"\n{Fore.YELLOW}{EMOJI['INFO']} Select authentication type:")
    print("1. Auth_0 (Default)")
    print("2. Google")
    print("3. GitHub")

    auth_choice = input(f"{Fore.CYAN}> {Style.RESET_ALL}").strip()

    if auth_choice == "2":
        auth_type = "Google"
    elif auth_choice == "3":
        auth_type = "GitHub"
    else:
        auth_type = "Auth_0"

    # Confirm information
    print(f"\n{Fore.YELLOW}{EMOJI['INFO']} Please confirm the following information:")
    print(f"{Fore.CYAN}Token: {token[:10]}...{token[-10:] if len(token) > 20 else token[10:]}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Email: {email}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Auth Type: {auth_type}{Style.RESET_ALL}")

    confirm = input(f"\n{Fore.YELLOW}Proceed? (y/N): {Style.RESET_ALL}").strip().lower()

    if confirm not in ["y", "yes"]:
        print(f"{Fore.RED}{EMOJI['ERROR']} Operation cancelled{Style.RESET_ALL}")
        return False

    # Update Cursor authentication database
    print(f"\n{Fore.CYAN}{EMOJI['INFO']} Updating Cursor authentication database...{Style.RESET_ALL}")

    try:
        cursor_auth = CursorAuth()
        result = cursor_auth.update_auth(
            email=email,
            access_token=token,
            refresh_token=token,
            auth_type=auth_type
        )

        if result:
            print(f"\n{Fore.GREEN}{EMOJI['SUCCESS']} Authentication information updated successfully!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{EMOJI['INFO']} Please restart Cursor for the changes to take effect.{Style.RESET_ALL}")
            return True
        else:
            print(f"\n{Fore.RED}{EMOJI['ERROR']} Failed to update authentication information{Style.RESET_ALL}")
            return False

    except Exception as e:
        print(f"\n{Fore.RED}{EMOJI['ERROR']} Error: {str(e)}{Style.RESET_ALL}")
        return False

if __name__ == "__main__":
    manual_login()
