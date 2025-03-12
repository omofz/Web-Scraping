import re
import requests
from bs4 import BeautifulSoup


def email_extractor(html_link):
    try:
        html_content = requests.get(html_link)
        if html_content.status_code == 200:
            soup = BeautifulSoup(html_content, 'lxml')
            # Email regex pattern
            emailRegex = re.compile(r'''
                                [a-zA-Z0-9._%+-]+
                                @
                                [a-zA-Z0-9.-]+
                                \.
                                [a-zA-Z0-9.-]+
                                ''', re.VERBOSE)

            emails = []
            for link in soup.find_all('a'):
                href = link.get('href')
                # Checks if href exists and contains 'mailto:'
                if href and 'mailto:' in href:
                    # extract email from href
                    email = href.replace('mailto:', '').strip()
                    # verifies with regex pattern
                    if emailRegex.fullmatch(email):
                        emails.append(email)

            if emails:
                try:
                    with open('emails.txt', 'w') as file:
                        for email in emails:
                            file.write(f"{email}\n")
                    return emails
                except Exception as e:
                    print(f"Error writing to file: {e}")
                    return emails
            else:
                print("No emails found")
                return []
        else:
            print(f"Failed to fetch the webpage: Status code {html_content.status_code}")
            return []
    except Exception as e:
        print(f"An error occured: {e}")
        return []


if __name__ == "__main__":
    print("Enter the webpage to find email links")
    webpage = input("> ")
    extracted_emails = email_extractor(webpage)
    print(f"Extracted {len(extracted_emails)} emails")
