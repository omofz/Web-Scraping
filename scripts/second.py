import requests
from bs4 import BeautifulSoup

html_text = requests.get('https://www.bbc.com/sport/football/premier-league/table')
soup = BeautifulSoup(html_text, 'lxml')

table_rows = soup.find_all('tr', class_="ssrcss-usj84m-TableRow e3bga5w3").text.replace(' ', '')
team = table_rows.find('span', class_="visually-hidden ssrcss-1f39n02-VisuallyHidden e16en2lz0")