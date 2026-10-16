"""Debug RCDATA parsing."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf-8', buffering=1)

from bs4 import BeautifulSoup
from xssentinel.core.parser_utils import bs_parser

# Test how BS4 parses script inside textarea
html_text = '<textarea><script>alert("tok_y")</script></textarea>'
soup = BeautifulSoup(html_text, bs_parser())
print(f"Parser: {bs_parser()}")
print(f"HTML: {html_text}")
print(f"Parsed: {soup}")
print()

# Find all script elements
scripts = soup.find_all("script")
print(f"Script elements found: {len(scripts)}")
for s in scripts:
    print(f"  script text: {repr(s.get_text())}")
    print(f"  script parent: {s.parent.name if s.parent else None}")
    # Walk parents
    p = s.parent
    chain = []
    while p:
        chain.append(p.name)
        p = p.parent
    print(f"  parent chain: {chain}")

print()
# Find textarea
textareas = soup.find_all("textarea")
print(f"Textarea elements: {len(textareas)}")
for t in textareas:
    print(f"  textarea text: {repr(t.get_text())}")
    print(f"  textarea children: {[c.name for c in t.children if hasattr(c, 'name')]}")

print()
# Also test with html5lib if available
try:
    soup2 = BeautifulSoup(html_text, "html5lib")
    print("html5lib parse:")
    scripts2 = soup2.find_all("script")
    print(f"  Script elements: {len(scripts2)}")
    for s in scripts2:
        p = s.parent
        chain = []
        while p:
            chain.append(p.name)
            p = p.parent
        print(f"  parent chain: {chain}")
except Exception as e:
    print(f"html5lib not available: {e}")

# Test the verifier's _is_in_rcdata
from xssentinel.core.verifier import _is_in_rcdata
print()
print("Testing _is_in_rcdata:")
for s in soup.find_all("script"):
    print(f"  script in rcdata: {_is_in_rcdata(s)}")
for img in soup.find_all("img"):
    print(f"  img in rcdata: {_is_in_rcdata(img)}")
