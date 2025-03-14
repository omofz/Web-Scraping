from bs4 import BeautifulSoup

with open("./source/index.html", "r") as html_file:
    content = html_file.read()

    soup = BeautifulSoup(content, 'lxml')

    # Find article sections
    html_sections = soup.find_all('div', class_='card')
    
    store = {}
    for section in html_sections:
        section_title = section.h5.text
        section_article = section.find('p', class_='card-text').text
        section_price = section.a.text.split()[-1]

        store[section_title] = section_price

    print(store)